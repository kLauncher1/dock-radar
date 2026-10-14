package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	// ErrInvalidProjectName denotes a malformed or unsafe compose project name.
	ErrInvalidProjectName = errors.New("invalid project name: must be 1-128 alphanumeric characters with optional '.', '_', or '-'")
	// ErrProjectNotFound denotes when no containers match the requested compose project.
	ErrProjectNotFound = errors.New("compose stack project not found or contains no active containers")

	projectNameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
)

// ValidateProjectName checks that the project identifier contains only safe characters.
func ValidateProjectName(project string) error {
	trimmed := strings.TrimSpace(project)
	if trimmed == "" || len(trimmed) > 128 {
		return ErrInvalidProjectName
	}
	if !projectNameRegex.MatchString(trimmed) {
		return ErrInvalidProjectName
	}
	return nil
}

// ComposeService represents a single containerized service inside a Docker Compose project.
type ComposeService struct {
	Name            string            `json:"name"`
	ContainerID     string            `json:"container_id"`
	ContainerName   string            `json:"container_name"`
	Image           string            `json:"image"`
	State           string            `json:"state"`
	Status          string            `json:"status"`
	ContainerNumber int               `json:"container_number"`
	DependsOn       []string          `json:"depends_on"`
	Role            string            `json:"role"`
	Labels          map[string]string `json:"labels,omitempty"`
}

// TopologyNode represents a visual node in the topology dependency graph.
type TopologyNode struct {
	ID      string  `json:"id"`
	Label   string  `json:"label"`
	Service string  `json:"service"`
	Role    string  `json:"role"`
	State   string  `json:"state"`
	Image   string  `json:"image"`
	Layer   int     `json:"layer"`
	X       float64 `json:"x"`
	Y       float64 `json:"y"`
}

// TopologyEdge represents a directional link from a dependent service to its prerequisite.
type TopologyEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Type string `json:"type"` // "depends_on" or "inferred"
}

// ComposeTopology aggregates nodes and edges for visual rendering.
type ComposeTopology struct {
	Nodes []TopologyNode `json:"nodes"`
	Edges []TopologyEdge `json:"edges"`
}

// ComposeStack encapsulates all services and dependency graphs for a compose project.
type ComposeStack struct {
	Project         string           `json:"project"`
	WorkingDir      string           `json:"working_dir,omitempty"`
	ConfigFiles     string           `json:"config_files,omitempty"`
	TotalServices   int              `json:"total_services"`
	RunningServices int              `json:"running_services"`
	Health          string           `json:"health"` // "healthy", "degraded", "stopped", "empty"
	Services        []ComposeService `json:"services"`
	Topology        ComposeTopology  `json:"topology"`
}

// StackActionResult describes the execution result of whole-stack lifecycle actions.
type StackActionResult struct {
	Project            string    `json:"project"`
	Action             string    `json:"action"` // "restart", "stop", "recreate"
	AffectedContainers []string  `json:"affected_containers"`
	SuccessCount       int       `json:"success_count"`
	FailureCount       int       `json:"failure_count"`
	Errors             []string  `json:"errors,omitempty"`
	ExecutedAt         time.Time `json:"executed_at"`
}

// ParseDependsOn extracts clean service names from compose depends_on labels.
func ParseDependsOn(raw string) []string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return []string{}
	}

	// Format 1: JSON dictionary, e.g. {"db":{"condition":"service_started"}}
	if strings.HasPrefix(trimmed, "{") {
		var obj map[string]any
		if err := json.Unmarshal([]byte(trimmed), &obj); err == nil {
			var deps []string
			for k := range obj {
				kClean := strings.TrimSpace(k)
				if kClean != "" {
					deps = append(deps, kClean)
				}
			}
			sort.Strings(deps)
			return deps
		}
	}

	// Format 2: Comma or colon separated list, e.g. "db:service_healthy,redis:service_started"
	parts := strings.Split(trimmed, ",")
	seen := make(map[string]bool)
	var deps []string
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}
		if colonIdx := strings.Index(item, ":"); colonIdx > 0 {
			item = item[:colonIdx]
		}
		item = strings.TrimSpace(item)
		if item != "" && !seen[item] {
			seen[item] = true
			deps = append(deps, item)
		}
	}
	sort.Strings(deps)
	return deps
}

// DetectServiceRole classifies a container into standard architectural tiers.
func DetectServiceRole(serviceName, image string) string {
	combined := strings.ToLower(serviceName + " " + image)
	switch {
	case strings.Contains(combined, "postgres") || strings.Contains(combined, "mysql") ||
		strings.Contains(combined, "mariadb") || strings.Contains(combined, "mongo") ||
		strings.Contains(combined, "sqlite") || strings.Contains(combined, "cockroach"):
		return "database"
	case strings.Contains(combined, "redis") || strings.Contains(combined, "memcached") ||
		strings.Contains(combined, "valkey") || strings.Contains(combined, "dragonfly"):
		return "cache"
	case strings.Contains(combined, "kafka") || strings.Contains(combined, "rabbitmq") ||
		strings.Contains(combined, "nats") || strings.Contains(combined, "pulsar"):
		return "queue"
	case strings.Contains(combined, "nginx") || strings.Contains(combined, "caddy") ||
		strings.Contains(combined, "traefik") || strings.Contains(combined, "envoy") ||
		strings.Contains(combined, "frontend") || strings.Contains(combined, "web") ||
		strings.Contains(combined, "ingress"):
		return "gateway"
	case strings.Contains(combined, "worker") || strings.Contains(combined, "job") ||
		strings.Contains(combined, "celery") || strings.Contains(combined, "consumer"):
		return "worker"
	case strings.Contains(combined, "minio") || strings.Contains(combined, "s3") ||
		strings.Contains(combined, "elastic") || strings.Contains(combined, "opensearch"):
		return "storage"
	default:
		return "service"
	}
}

// BuildTopologyGraph computes nodes, edges, and coordinates for layout rendering.
func BuildTopologyGraph(services []ComposeService) ComposeTopology {
	topo := ComposeTopology{
		Nodes: make([]TopologyNode, 0, len(services)),
		Edges: make([]TopologyEdge, 0),
	}

	serviceMap := make(map[string]ComposeService)
	for _, s := range services {
		serviceMap[s.Name] = s
	}

	// Layer mapping: 0=gateway/web, 1=worker/service, 2=cache/queue/storage/db
	assignLayer := func(role string) int {
		switch role {
		case "gateway":
			return 0
		case "service", "worker":
			return 1
		case "database", "cache", "queue", "storage":
			return 2
		default:
			return 1
		}
	}

	edgeSeen := make(map[string]bool)
	hasExplicitEdges := false

	for _, s := range services {
		for _, dep := range s.DependsOn {
			if _, exists := serviceMap[dep]; exists && dep != s.Name {
				edgeKey := fmt.Sprintf("%s->%s", s.Name, dep)
				if !edgeSeen[edgeKey] {
					edgeSeen[edgeKey] = true
					topo.Edges = append(topo.Edges, TopologyEdge{
						From: s.Name,
						To:   dep,
						Type: "depends_on",
					})
					hasExplicitEdges = true
				}
			}
		}
	}

	// If no explicit depends_on labels were set, infer connections across tiers
	if !hasExplicitEdges {
		for _, s := range services {
			if s.Role == "gateway" || s.Role == "service" || s.Role == "worker" {
				for _, other := range services {
					if other.Name != s.Name && (other.Role == "database" || other.Role == "cache" || other.Role == "queue") {
						edgeKey := fmt.Sprintf("%s->%s", s.Name, other.Name)
						if !edgeSeen[edgeKey] {
							edgeSeen[edgeKey] = true
							topo.Edges = append(topo.Edges, TopologyEdge{
								From: s.Name,
								To:   other.Name,
								Type: "inferred",
							})
						}
					}
				}
			}
		}
	}

	// Group nodes by layers for spatial positioning
	layerGroups := make(map[int][]ComposeService)
	for _, s := range services {
		l := assignLayer(s.Role)
		layerGroups[l] = append(layerGroups[l], s)
	}

	for l := 0; l <= 2; l++ {
		group := layerGroups[l]
		count := len(group)
		for idx, s := range group {
			xPos := 160.0 + float64(l)*320.0
			yPos := 70.0
			if count > 1 {
				yStep := 260.0 / float64(count)
				yPos = 50.0 + float64(idx)*yStep
			} else {
				yPos = 130.0
			}

			label := s.Name
			if s.ContainerNumber > 1 {
				label = fmt.Sprintf("%s (#%d)", s.Name, s.ContainerNumber)
			}

			topo.Nodes = append(topo.Nodes, TopologyNode{
				ID:      s.ContainerID,
				Label:   label,
				Service: s.Name,
				Role:    s.Role,
				State:   s.State,
				Image:   s.Image,
				Layer:   l,
				X:       xPos,
				Y:       yPos,
			})
		}
	}

	return topo
}

// ExtractComposeStacks groups containers by com.docker.compose.project label.
func ExtractComposeStacks(containers []ContainerSummary) []ComposeStack {
	projectBuckets := make(map[string][]ContainerSummary)

	for _, c := range containers {
		project := strings.TrimSpace(c.Labels["com.docker.compose.project"])
		if project == "" {
			continue
		}
		projectBuckets[project] = append(projectBuckets[project], c)
	}

	var stacks []ComposeStack

	for project, cList := range projectBuckets {
		stack := ComposeStack{
			Project:  project,
			Services: make([]ComposeService, 0, len(cList)),
		}

		running := 0
		for _, c := range cList {
			serviceName := strings.TrimSpace(c.Labels["com.docker.compose.service"])
			if serviceName == "" {
				if len(c.Names) > 0 {
					serviceName = strings.TrimPrefix(c.Names[0], "/")
				} else {
					serviceName = c.ID[:min(12, len(c.ID))]
				}
			}

			if stack.WorkingDir == "" {
				stack.WorkingDir = c.Labels["com.docker.compose.project.working_dir"]
			}
			if stack.ConfigFiles == "" {
				stack.ConfigFiles = c.Labels["com.docker.compose.project.config_files"]
			}

			dependsOn := ParseDependsOn(c.Labels["com.docker.compose.depends_on"])
			role := DetectServiceRole(serviceName, c.Image)

			cName := ""
			if len(c.Names) > 0 {
				cName = strings.TrimPrefix(c.Names[0], "/")
			}

			svc := ComposeService{
				Name:          serviceName,
				ContainerID:   c.ID,
				ContainerName: cName,
				Image:         c.Image,
				State:         c.State,
				Status:        c.Status,
				DependsOn:     dependsOn,
				Role:          role,
				Labels:        c.Labels,
			}

			if strings.EqualFold(c.State, "running") {
				running++
			}

			stack.Services = append(stack.Services, svc)
		}

		stack.TotalServices = len(stack.Services)
		stack.RunningServices = running

		switch {
		case stack.TotalServices == 0:
			stack.Health = "empty"
		case running == stack.TotalServices:
			stack.Health = "healthy"
		case running > 0:
			stack.Health = "degraded"
		default:
			stack.Health = "stopped"
		}

		stack.Topology = BuildTopologyGraph(stack.Services)
		stacks = append(stacks, stack)
	}

	sort.Slice(stacks, func(i, j int) bool {
		return stacks[i].Project < stacks[j].Project
	})

	return stacks
}

// RestartStack restarts all containers within a compose project in dependency sequence.
func (c *Client) RestartStack(ctx context.Context, project string) (StackActionResult, error) {
	result := StackActionResult{
		Project:            project,
		Action:             "restart",
		AffectedContainers: make([]string, 0),
		ExecutedAt:         time.Now().UTC(),
	}

	if err := ValidateProjectName(project); err != nil {
		return result, err
	}

	status := c.InspectContainers()
	var targets []ContainerSummary
	for _, ct := range status.Containers {
		if strings.EqualFold(ct.Labels["com.docker.compose.project"], project) {
			targets = append(targets, ct)
		}
	}

	if len(targets) == 0 {
		return result, ErrProjectNotFound
	}

	for _, ct := range targets {
		result.AffectedContainers = append(result.AffectedContainers, ct.ID)
		if err := c.RestartContainer(ctx, ct.ID, 10); err != nil {
			result.FailureCount++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", ct.ID[:min(12, len(ct.ID))], err))
		} else {
			result.SuccessCount++
		}
	}

	return result, nil
}

// StopStack gracefully terminates all containers within a compose project.
func (c *Client) StopStack(ctx context.Context, project string) (StackActionResult, error) {
	result := StackActionResult{
		Project:            project,
		Action:             "stop",
		AffectedContainers: make([]string, 0),
		ExecutedAt:         time.Now().UTC(),
	}

	if err := ValidateProjectName(project); err != nil {
		return result, err
	}

	status := c.InspectContainers()
	var targets []ContainerSummary
	for _, ct := range status.Containers {
		if strings.EqualFold(ct.Labels["com.docker.compose.project"], project) {
			targets = append(targets, ct)
		}
	}

	if len(targets) == 0 {
		return result, ErrProjectNotFound
	}

	for _, ct := range targets {
		result.AffectedContainers = append(result.AffectedContainers, ct.ID)
		if err := c.StopContainer(ctx, ct.ID, 10); err != nil {
			result.FailureCount++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", ct.ID[:min(12, len(ct.ID))], err))
		} else {
			result.SuccessCount++
		}
	}

	return result, nil
}

// RecreateStack executes a stop followed by restart to refresh stack container states.
func (c *Client) RecreateStack(ctx context.Context, project string) (StackActionResult, error) {
	result := StackActionResult{
		Project:            project,
		Action:             "recreate",
		AffectedContainers: make([]string, 0),
		ExecutedAt:         time.Now().UTC(),
	}

	if err := ValidateProjectName(project); err != nil {
		return result, err
	}

	status := c.InspectContainers()
	var targets []ContainerSummary
	for _, ct := range status.Containers {
		if strings.EqualFold(ct.Labels["com.docker.compose.project"], project) {
			targets = append(targets, ct)
		}
	}

	if len(targets) == 0 {
		return result, ErrProjectNotFound
	}

	for _, ct := range targets {
		result.AffectedContainers = append(result.AffectedContainers, ct.ID)
		_ = c.StopContainer(ctx, ct.ID, 5)
		if err := c.RestartContainer(ctx, ct.ID, 10); err != nil {
			result.FailureCount++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", ct.ID[:min(12, len(ct.ID))], err))
		} else {
			result.SuccessCount++
		}
	}

	return result, nil
}
