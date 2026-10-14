package mesh

import (
	"fmt"
	"sync"
	"testing"
)

func TestValidateNodeAddress(t *testing.T) {
	valid := []string{
		"http://127.0.0.1:9080",
		"https://node1.internal:9080",
		"http://docker-host",
		"https://cluster.local:8443/subpath",
	}

	for _, addr := range valid {
		if err := ValidateNodeAddress(addr); err != nil {
			t.Errorf("expected valid address %q, got error: %v", addr, err)
		}
	}

	invalid := []string{
		"",
		"   ",
		"ftp://cluster.local",
		"ws://cluster.local",
		"http://",
		"http://\x01evil.com",
		"https://bad\nhost:9080",
		"http://user:pass@legit-node:9080",
		"http://169.254.169.254",
		"http://169.254.169.254/latest/meta-data",
		"http://metadata.google.internal/computeMetadata/v1",
		"http://169.254.10.20:9080",
	}

	for _, addr := range invalid {
		if err := ValidateNodeAddress(addr); err == nil {
			t.Errorf("expected invalid address %q to fail, but it passed", addr)
		}
	}
}

func TestRegistry_RegisterAndGet(t *testing.T) {
	reg := NewRegistry("local", "coordinator")

	// Nil node validation
	if err := reg.Register(nil); err == nil {
		t.Fatal("expected error registering nil node")
	}

	// Empty ID validation
	if err := reg.Register(&Node{Address: "http://localhost:9080"}); err == nil {
		t.Fatal("expected error registering node with empty ID")
	}

	// Invalid address validation
	if err := reg.Register(&Node{ID: "node-1", Address: "ftp://bad"}); err == nil {
		t.Fatal("expected error registering node with invalid address")
	}

	// Successful registration
	node := &Node{
		ID:      "node-1",
		Name:    "Worker 1",
		Address: "http://192.168.1.10:9080/",
		Labels: map[string]string{
			"env":  "production",
			"tier": "frontend",
		},
	}

	if err := reg.Register(node); err != nil {
		t.Fatalf("failed to register node: %v", err)
	}

	retrieved, ok := reg.Get("node-1")
	if !ok {
		t.Fatal("expected node-1 to exist in registry")
	}

	if retrieved.ID != "node-1" || retrieved.Name != "Worker 1" {
		t.Errorf("unexpected node metadata: %+v", retrieved)
	}
	if retrieved.Address != "http://192.168.1.10:9080" {
		t.Errorf("expected trailing slash to be trimmed, got %s", retrieved.Address)
	}
	if retrieved.Status != NodeStatusUnknown {
		t.Errorf("expected default status %s, got %s", NodeStatusUnknown, retrieved.Status)
	}

	// Modifying original map should not affect registry
	node.Labels["env"] = "staging"
	fresh, _ := reg.Get("node-1")
	if fresh.Labels["env"] != "production" {
		t.Errorf("expected label to remain production, got %s", fresh.Labels["env"])
	}
}

func TestRegistry_Unregister(t *testing.T) {
	reg := NewRegistry("local", "coordinator")
	_ = reg.Register(&Node{ID: "node-1", Address: "http://10.0.0.1:9080"})

	if !reg.Unregister("node-1") {
		t.Error("expected unregister to return true for existing node")
	}
	if reg.Unregister("node-1") {
		t.Error("expected second unregister to return false")
	}
	if _, exists := reg.Get("node-1"); exists {
		t.Error("node-1 still exists after unregister")
	}
}

func TestRegistry_UpdateNodeStatus(t *testing.T) {
	reg := NewRegistry("local", "coordinator")
	_ = reg.Register(&Node{ID: "node-1", Name: "Worker Node", Address: "http://10.0.0.1:9080"})

	metrics := NodeMetrics{
		CPUPercent:        45.2,
		MemoryUsedBytes:   512 * 1024 * 1024,
		MemoryTotalBytes:  1024 * 1024 * 1024,
		MemoryPercent:     50.0,
		ContainersRunning: 2,
		ContainersTotal:   3,
	}

	containers := []RemoteContainer{
		{ID: "c1", Names: []string{"/app"}, State: "running"},
		{ID: "c2", Names: []string{"/db"}, State: "running"},
	}

	reg.UpdateNodeStatus("node-1", NodeStatusOnline, 14, metrics, containers, "")

	node, ok := reg.Get("node-1")
	if !ok {
		t.Fatal("expected node-1 to exist")
	}
	if node.Status != NodeStatusOnline {
		t.Errorf("expected status %s, got %s", NodeStatusOnline, node.Status)
	}
	if node.LatencyMs != 14 {
		t.Errorf("expected latency 14ms, got %d", node.LatencyMs)
	}
	if node.LastHeartbeat.IsZero() {
		t.Error("expected non-zero heartbeat timestamp")
	}
	if len(node.Containers) != 2 {
		t.Fatalf("expected 2 containers, got %d", len(node.Containers))
	}
	if node.Containers[0].NodeID != "node-1" || node.Containers[0].NodeName != "Worker Node" {
		t.Errorf("container missing node tag: %+v", node.Containers[0])
	}
}

func TestRegistry_ClusterSummaryAndAllContainers(t *testing.T) {
	reg := NewRegistry("local", "coordinator")

	// Empty registry summary
	emptySummary := reg.ClusterSummary()
	if emptySummary.TotalNodes != 0 || emptySummary.OnlineNodes != 0 {
		t.Errorf("unexpected empty summary: %+v", emptySummary)
	}

	_ = reg.Register(&Node{
		ID:      "n1",
		Name:    "Node 1",
		Address: "http://10.0.0.1:9080",
		Labels:  map[string]string{"zone": "us-east"},
	})
	_ = reg.Register(&Node{
		ID:      "n2",
		Name:    "Node 2",
		Address: "http://10.0.0.2:9080",
		Labels:  map[string]string{"zone": "us-east"},
	})
	_ = reg.Register(&Node{
		ID:      "n3",
		Name:    "Node 3",
		Address: "http://10.0.0.3:9080",
		Labels:  map[string]string{"zone": "eu-west"},
	})

	reg.UpdateNodeStatus("n1", NodeStatusOnline, 10, NodeMetrics{
		CPUPercent:        20.0,
		MemoryUsedBytes:   100,
		MemoryTotalBytes:  200,
		ContainersRunning: 3,
		ContainersTotal:   5,
	}, []RemoteContainer{{ID: "c1"}}, "")

	reg.UpdateNodeStatus("n2", NodeStatusOnline, 12, NodeMetrics{
		CPUPercent:        40.0,
		MemoryUsedBytes:   300,
		MemoryTotalBytes:  400,
		ContainersRunning: 2,
		ContainersTotal:   2,
	}, []RemoteContainer{{ID: "c2"}, {ID: "c3"}}, "")

	reg.UpdateNodeStatus("n3", NodeStatusOffline, 0, NodeMetrics{
		ContainersTotal: 1,
	}, nil, "network unreachable")

	summary := reg.ClusterSummary()
	if summary.TotalNodes != 3 {
		t.Errorf("expected 3 total nodes, got %d", summary.TotalNodes)
	}
	if summary.OnlineNodes != 2 {
		t.Errorf("expected 2 online nodes, got %d", summary.OnlineNodes)
	}
	if summary.OfflineNodes != 1 {
		t.Errorf("expected 1 offline node, got %d", summary.OfflineNodes)
	}
	if summary.TotalContainers != 8 {
		t.Errorf("expected 8 total containers, got %d", summary.TotalContainers)
	}
	if summary.RunningContainers != 5 {
		t.Errorf("expected 5 running containers, got %d", summary.RunningContainers)
	}
	if summary.AggregateCPUPercent != 30.0 {
		t.Errorf("expected 30.0 aggregate CPU percent, got %f", summary.AggregateCPUPercent)
	}
	if summary.AggregateMemoryUsedBytes != 400 {
		t.Errorf("expected 400 bytes memory used, got %d", summary.AggregateMemoryUsedBytes)
	}
	if summary.NodesByLabel["zone=us-east"] != 2 {
		t.Errorf("expected 2 nodes in us-east, got %d", summary.NodesByLabel["zone=us-east"])
	}

	allContainers := reg.AllContainers()
	if len(allContainers) != 3 {
		t.Errorf("expected 3 remote containers aggregated, got %d", len(allContainers))
	}
}

func TestRegistry_Concurrency(t *testing.T) {
	reg := NewRegistry("local", "coordinator")
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			id := fmt.Sprintf("node-%d", idx)
			_ = reg.Register(&Node{
				ID:      id,
				Name:    fmt.Sprintf("Node %d", idx),
				Address: fmt.Sprintf("http://10.0.0.%d:9080", idx+1),
			})

			reg.UpdateNodeStatus(id, NodeStatusOnline, int64(idx), NodeMetrics{
				CPUPercent: float64(idx),
			}, []RemoteContainer{{ID: fmt.Sprintf("c-%d", idx)}}, "")

			_ = reg.List()
			_ = reg.ClusterSummary()
			_ = reg.AllContainers()

			if idx%3 == 0 {
				reg.Unregister(id)
			}
		}(i)
	}

	wg.Wait()
}

func TestValidateNodeID(t *testing.T) {
	valid := []string{"node-1", "worker_01", "edge.us-east", "node123"}
	for _, id := range valid {
		if err := ValidateNodeID(id); err != nil {
			t.Errorf("expected valid node ID %q, got error: %v", id, err)
		}
	}

	invalid := []string{
		"",
		"   ",
		"-leading-dash",
		".leading-dot",
		"has space",
		"bad@char!",
		"../path-traversal",
		"a-very-long-node-id-that-exceeds-the-maximum-allowed-sixty-four-characters-limit",
	}
	for _, id := range invalid {
		if err := ValidateNodeID(id); err == nil {
			t.Errorf("expected invalid node ID %q to fail, but it passed", id)
		}
	}
}

func TestRegistry_MemoryBounds(t *testing.T) {
	reg := NewRegistry("local", "coordinator")
	reg.maxNodes = 5

	for i := 1; i <= 5; i++ {
		err := reg.Register(&Node{
			ID:      fmt.Sprintf("node-%d", i),
			Address: fmt.Sprintf("http://10.0.0.%d:9080", i),
		})
		if err != nil {
			t.Fatalf("expected registration of node %d to succeed: %v", i, err)
		}
	}

	// 6th node should hit the memory bound ceiling
	err := reg.Register(&Node{
		ID:      "node-6",
		Address: "http://10.0.0.6:9080",
	})
	if err == nil {
		t.Fatal("expected registry capacity exceeded error, got nil")
	}

	// Test container allocation capping
	excessiveContainers := make([]RemoteContainer, 3000)
	for i := range excessiveContainers {
		excessiveContainers[i] = RemoteContainer{ID: fmt.Sprintf("c-%d", i)}
	}

	reg.UpdateNodeStatus("node-1", NodeStatusOnline, 5, NodeMetrics{}, excessiveContainers, "")
	n, ok := reg.Get("node-1")
	if !ok {
		t.Fatal("failed to get node-1")
	}
	if len(n.Containers) != DefaultMaxContainersPerNode {
		t.Fatalf("expected containers capped at %d, got %d", DefaultMaxContainersPerNode, len(n.Containers))
	}
}

