package mesh

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultMaxNodes defines the in-memory capacity ceiling for registered mesh nodes.
	DefaultMaxNodes = 256
	// DefaultMaxContainersPerNode limits in-memory container allocations per remote node.
	DefaultMaxContainersPerNode = 2000
)

var (
	// ErrInvalidNodeID signifies that a node identifier does not conform to safety specifications.
	ErrInvalidNodeID = errors.New("invalid node ID: must be 1-64 alphanumeric characters, underscores, dashes, or dots")
	nodeIDRegex      = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)
)

// NodeStatus enumerates the operational health status of a cluster node.
type NodeStatus string

const (
	NodeStatusOnline   NodeStatus = "online"
	NodeStatusOffline  NodeStatus = "offline"
	NodeStatusDegraded NodeStatus = "degraded"
	NodeStatusUnknown  NodeStatus = "unknown"
)

// RemoteContainer represents container metadata collected from a remote cluster node.
type RemoteContainer struct {
	ID       string   `json:"id"`
	Names    []string `json:"names"`
	Image    string   `json:"image"`
	Status   string   `json:"status"`
	State    string   `json:"state"`
	Created  int64    `json:"created"`
	Ports    string   `json:"ports,omitempty"`
	NodeID   string   `json:"node_id"`
	NodeName string   `json:"node_name"`
}

// NodeMetrics encapsulates compute and container capacity metrics from a cluster node.
type NodeMetrics struct {
	CPUPercent        float64 `json:"cpu_percent"`
	MemoryUsedBytes   uint64  `json:"memory_used_bytes"`
	MemoryTotalBytes  uint64  `json:"memory_total_bytes"`
	MemoryPercent     float64 `json:"memory_percent"`
	Goroutines        int     `json:"goroutines"`
	UptimeSeconds     uint64  `json:"uptime_seconds"`
	ContainersRunning int     `json:"containers_running"`
	ContainersTotal   int     `json:"containers_total"`
}

// Node represents an individual dock-radar instance registered in the mesh.
type Node struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Address       string            `json:"address"`
	Labels        map[string]string `json:"labels,omitempty"`
	Status        NodeStatus        `json:"status"`
	LatencyMs     int64             `json:"latency_ms"`
	LastHeartbeat time.Time         `json:"last_heartbeat"`
	LastError     string            `json:"last_error,omitempty"`
	Metrics       NodeMetrics       `json:"metrics"`
	Containers    []RemoteContainer `json:"containers,omitempty"`
}

// ClusterSummary provides aggregated telemetry across all active mesh nodes.
type ClusterSummary struct {
	TotalNodes                int            `json:"total_nodes"`
	OnlineNodes               int            `json:"online_nodes"`
	OfflineNodes              int            `json:"offline_nodes"`
	TotalContainers           int            `json:"total_containers"`
	RunningContainers         int            `json:"running_containers"`
	AggregateCPUPercent       float64        `json:"aggregate_cpu_percent"`
	AggregateMemoryUsedBytes  uint64         `json:"aggregate_memory_used_bytes"`
	AggregateMemoryTotalBytes uint64         `json:"aggregate_memory_total_bytes"`
	NodesByLabel              map[string]int `json:"nodes_by_label"`
}

// Registry manages thread-safe storage, health tracking, and aggregation of mesh nodes.
type Registry struct {
	mu            sync.RWMutex
	nodes         map[string]*Node
	localNodeID   string
	localNodeName string
	maxNodes      int
}

// NewRegistry initializes an empty node mesh registry with bounded node capacity.
func NewRegistry(localID, localName string) *Registry {
	return &Registry{
		nodes:         make(map[string]*Node),
		localNodeID:   localID,
		localNodeName: localName,
		maxNodes:      DefaultMaxNodes,
	}
}

// ValidateNodeID verifies that a node ID conforms to safety specifications.
func ValidateNodeID(id string) error {
	trimmed := strings.TrimSpace(id)
	if trimmed == "" || len(trimmed) > 64 {
		return ErrInvalidNodeID
	}
	if !nodeIDRegex.MatchString(trimmed) {
		return ErrInvalidNodeID
	}
	return nil
}

// ValidateNodeAddress verifies that an address is a valid HTTP/HTTPS endpoint without control characters, user credentials, or SSRF metadata targets.
func ValidateNodeAddress(addr string) error {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return errors.New("node address cannot be empty")
	}
	for _, r := range addr {
		if r < 32 || r == 127 {
			return errors.New("node address contains invalid control characters")
		}
	}
	u, err := url.Parse(addr)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("node address must use http or https scheme")
	}
	if u.Host == "" {
		return errors.New("node address must include a valid host or host:port")
	}
	if u.User != nil {
		return errors.New("node address must not contain embedded user credentials")
	}

	hostname := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if hostname == "" {
		return errors.New("node address missing valid hostname")
	}

	// SSRF defense: block cloud metadata endpoints and prohibited targets
	blockedHosts := []string{
		"169.254.169.254",
		"169.254.169.253",
		"metadata.google.internal",
		"metadata.internal",
		"instance-data",
	}
	for _, b := range blockedHosts {
		if hostname == b || strings.HasSuffix(hostname, "."+b) {
			return fmt.Errorf("node address blocked by security policy: prohibited target %s", hostname)
		}
	}

	// SSRF defense: block link-local unicast/multicast IP ranges (RFC 3927)
	if ip := net.ParseIP(hostname); ip != nil {
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("node address blocked by security policy: link-local IP %s is prohibited", hostname)
		}
	}

	return nil
}

// Register adds or updates a node in the mesh registry after validating its ID and address.
func (r *Registry) Register(node *Node) error {
	if node == nil {
		return errors.New("cannot register nil node")
	}
	if err := ValidateNodeID(node.ID); err != nil {
		return err
	}
	if err := ValidateNodeAddress(node.Address); err != nil {
		return fmt.Errorf("invalid address for node %s: %w", node.ID, err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	maxNodes := r.maxNodes
	if maxNodes <= 0 {
		maxNodes = DefaultMaxNodes
	}
	if _, exists := r.nodes[node.ID]; !exists && len(r.nodes) >= maxNodes {
		return fmt.Errorf("mesh registry capacity reached (%d nodes maximum)", maxNodes)
	}

	labelsCopy := make(map[string]string)
	for k, v := range node.Labels {
		labelsCopy[k] = v
	}

	status := node.Status
	if status == "" {
		status = NodeStatusUnknown
	}

	name := strings.TrimSpace(node.Name)
	if name == "" {
		name = node.ID
	}

	clone := &Node{
		ID:            node.ID,
		Name:          name,
		Address:       strings.TrimRight(strings.TrimSpace(node.Address), "/"),
		Labels:        labelsCopy,
		Status:        status,
		LatencyMs:     node.LatencyMs,
		LastHeartbeat: node.LastHeartbeat,
		LastError:     node.LastError,
		Metrics:       node.Metrics,
		Containers:    append([]RemoteContainer(nil), node.Containers...),
	}

	r.nodes[node.ID] = clone
	return nil
}

// Unregister removes a node from the mesh registry by ID.
func (r *Registry) Unregister(id string) bool {
	id = strings.TrimSpace(id)
	if err := ValidateNodeID(id); err != nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.nodes[id]; exists {
		delete(r.nodes, id)
		return true
	}
	return false
}

// Get retrieves a snapshot of a node by ID.
func (r *Registry) Get(id string) (*Node, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n, exists := r.nodes[id]
	if !exists {
		return nil, false
	}
	return copyNode(n), true
}

// List returns a snapshot slice of all registered nodes.
func (r *Registry) List() []*Node {
	r.mu.RLock()
	defer r.mu.RUnlock()
	list := make([]*Node, 0, len(r.nodes))
	for _, n := range r.nodes {
		list = append(list, copyNode(n))
	}
	return list
}

// UpdateNodeStatus updates telemetry, health, latency, and container states for a node.
func (r *Registry) UpdateNodeStatus(id string, status NodeStatus, latencyMs int64, metrics NodeMetrics, containers []RemoteContainer, errStr string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	n, exists := r.nodes[id]
	if !exists {
		return
	}

	n.Status = status
	n.LatencyMs = latencyMs
	n.LastError = errStr
	if status == NodeStatusOnline || status == NodeStatusDegraded {
		n.LastHeartbeat = time.Now().UTC()
	}
	n.Metrics = metrics

	if len(containers) > DefaultMaxContainersPerNode {
		containers = containers[:DefaultMaxContainersPerNode]
	}

	taggedContainers := make([]RemoteContainer, len(containers))
	for i, c := range containers {
		c.NodeID = n.ID
		c.NodeName = n.Name
		taggedContainers[i] = c
	}
	n.Containers = taggedContainers
}

// ClusterSummary computes aggregated cluster statistics across all registered nodes.
func (r *Registry) ClusterSummary() ClusterSummary {
	r.mu.RLock()
	defer r.mu.RUnlock()

	summary := ClusterSummary{
		NodesByLabel: make(map[string]int),
	}
	summary.TotalNodes = len(r.nodes)

	var totalCPU float64
	var onlineCount int

	for _, n := range r.nodes {
		if n.Status == NodeStatusOnline {
			summary.OnlineNodes++
			onlineCount++
			totalCPU += n.Metrics.CPUPercent
		} else {
			summary.OfflineNodes++
		}

		summary.TotalContainers += n.Metrics.ContainersTotal
		summary.RunningContainers += n.Metrics.ContainersRunning
		summary.AggregateMemoryUsedBytes += n.Metrics.MemoryUsedBytes
		summary.AggregateMemoryTotalBytes += n.Metrics.MemoryTotalBytes

		for k, v := range n.Labels {
			summary.NodesByLabel[k+"="+v]++
		}
	}

	if onlineCount > 0 {
		summary.AggregateCPUPercent = totalCPU / float64(onlineCount)
	}

	return summary
}

// AllContainers aggregates all container records across all registered nodes into a unified slice.
func (r *Registry) AllContainers() []RemoteContainer {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var all []RemoteContainer
	for _, n := range r.nodes {
		for _, c := range n.Containers {
			all = append(all, c)
		}
	}
	return all
}

// LocalID returns the local node identifier.
func (r *Registry) LocalID() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.localNodeID
}

// LocalName returns the local node friendly name.
func (r *Registry) LocalName() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.localNodeName
}

func copyNode(src *Node) *Node {
	labels := make(map[string]string, len(src.Labels))
	for k, v := range src.Labels {
		labels[k] = v
	}
	containers := make([]RemoteContainer, len(src.Containers))
	copy(containers, src.Containers)

	return &Node{
		ID:            src.ID,
		Name:          src.Name,
		Address:       src.Address,
		Labels:        labels,
		Status:        src.Status,
		LatencyMs:     src.LatencyMs,
		LastHeartbeat: src.LastHeartbeat,
		LastError:     src.LastError,
		Metrics:       src.Metrics,
		Containers:    containers,
	}
}
