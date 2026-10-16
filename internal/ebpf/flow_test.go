package ebpf

import (
	"sync"
	"testing"
	"time"
)

func TestFlowTracker_RecordAndRetrieve(t *testing.T) {
	ft := NewFlowTracker(100)

	flow := SocketFlow{
		ContainerID:   "c-1",
		ContainerName: "web-frontend",
		Protocol:      "TCP",
		LocalAddr:     "172.17.0.2:80",
		RemoteAddr:    "10.0.0.5:43210",
		State:         "ESTABLISHED",
		BytesSent:     1024,
		BytesRecv:     2048,
	}

	ft.RecordFlow(flow)

	active, total, in, out := ft.Stats()
	if active != 1 || total != 1 {
		t.Fatalf("Expected 1 active, 1 total; got %d active, %d total", active, total)
	}
	if in != 2048 || out != 1024 {
		t.Fatalf("Expected in=2048, out=1024; got in=%d, out=%d", in, out)
	}

	// Update the existing flow with new byte counters
	flow.BytesSent = 2048
	flow.BytesRecv = 4096
	ft.RecordFlow(flow)

	active, total, in, out = ft.Stats()
	if active != 1 || total != 1 {
		t.Fatalf("Expected still 1 active/total after update, got %d/%d", active, total)
	}
	// Incremental deltas: +1024 out, +2048 in -> totals: out=2048, in=4096
	if in != 4096 || out != 2048 {
		t.Fatalf("Expected in=4096, out=2048; got in=%d, out=%d", in, out)
	}
}

func TestFlowTracker_EvictionAtCapacity(t *testing.T) {
	capacity := 5
	ft := NewFlowTracker(capacity)

	for i := 0; i < 10; i++ {
		ft.RecordFlow(SocketFlow{
			ContainerID: "c-1",
			Protocol:    "TCP",
			LocalAddr:   "172.17.0.2:80",
			RemoteAddr:  "10.0.0." + string(rune('0'+i)) + ":1234",
			State:       "ESTABLISHED",
			LastSeen:    time.Now().UTC().Add(time.Duration(i) * time.Second),
		})
	}

	active, total, _, _ := ft.Stats()
	if active > capacity {
		t.Fatalf("Expected active <= %d, got %d", capacity, active)
	}
	if total != 10 {
		t.Fatalf("Expected total=10, got %d", total)
	}
}

func TestFlowTracker_PruneStale(t *testing.T) {
	ft := NewFlowTracker(100)

	oldTime := time.Now().UTC().Add(-2 * time.Minute)
	ft.RecordFlow(SocketFlow{
		ContainerID: "c-1",
		Protocol:    "TCP",
		LocalAddr:   "172.17.0.2:80",
		RemoteAddr:  "10.0.0.1:1111",
		State:       "TIME_WAIT",
		LastSeen:    oldTime,
	})

	ft.RecordFlow(SocketFlow{
		ContainerID: "c-1",
		Protocol:    "TCP",
		LocalAddr:   "172.17.0.2:80",
		RemoteAddr:  "10.0.0.2:2222",
		State:       "ESTABLISHED",
		LastSeen:    time.Now().UTC(),
	})

	pruned := ft.PruneStale(30 * time.Second)
	if pruned != 1 {
		t.Fatalf("Expected 1 pruned flow, got %d", pruned)
	}

	list := ft.List(FlowFilter{})
	if len(list) != 1 {
		t.Fatalf("Expected 1 flow remaining, got %d", len(list))
	}
	if list[0].RemoteAddr != "10.0.0.2:2222" {
		t.Fatalf("Unexpected remaining flow: %s", list[0].RemoteAddr)
	}
}

func TestFlowTracker_Concurrency(t *testing.T) {
	ft := NewFlowTracker(50)
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				ft.RecordFlow(SocketFlow{
					ContainerID: "c-concurrency",
					Protocol:    "TCP",
					LocalAddr:   "172.17.0.2:80",
					RemoteAddr:  "10.0.0.1:" + string(rune('0'+(idx%10))),
					State:       "ESTABLISHED",
					BytesSent:   uint64(j * 10),
				})
				_ = ft.List(FlowFilter{ContainerID: "c-concurrency"})
				_, _, _, _ = ft.Stats()
			}
		}(i)
	}

	wg.Wait()
}
