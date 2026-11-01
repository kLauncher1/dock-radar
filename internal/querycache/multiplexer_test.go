package querycache

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestMultiplexer_SubscribePublish(t *testing.T) {
	cfg := DefaultMultiplexerConfig()
	m := NewEventMultiplexer(cfg)
	defer m.Close()

	ch, err := m.Subscribe("test-sub-1", EventFilter{}, 10)
	if err != nil {
		t.Fatalf("failed to subscribe: %v", err)
	}

	ev := DockerEvent{
		ID:        "e-1",
		Type:      "container",
		Action:    "start",
		ActorID:   "c-100",
		ActorName: "api-gateway",
		Time:      time.Now().Unix(),
	}

	m.Publish(ev)

	select {
	case received := <-ch:
		if received.ID != "e-1" || received.Action != "start" {
			t.Fatalf("unexpected event received: %+v", received)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timed out waiting for event delivery")
	}

	stats := m.Stats()
	if stats.ActiveSubscribers != 1 {
		t.Errorf("expected 1 active subscriber, got %d", stats.ActiveSubscribers)
	}
	if stats.TotalIngested != 1 {
		t.Errorf("expected 1 ingested event, got %d", stats.TotalIngested)
	}
	if stats.TotalDispatched != 1 {
		t.Errorf("expected 1 dispatched event, got %d", stats.TotalDispatched)
	}
}

func TestMultiplexer_FilterMatching(t *testing.T) {
	cfg := DefaultMultiplexerConfig()
	m := NewEventMultiplexer(cfg)
	defer m.Close()

	dieCh, _ := m.Subscribe("die-sub", EventFilter{Action: "die"}, 10)
	startCh, _ := m.Subscribe("start-sub", EventFilter{Action: "start"}, 10)

	evDie := DockerEvent{ID: "e-die", Action: "die", ActorID: "c-1"}
	evStart := DockerEvent{ID: "e-start", Action: "start", ActorID: "c-1"}

	m.Publish(evDie)
	m.Publish(evStart)

	// dieCh should only receive evDie
	select {
	case r := <-dieCh:
		if r.ID != "e-die" {
			t.Errorf("expected e-die, got %s", r.ID)
		}
	case <-time.After(50 * time.Millisecond):
		t.Fatal("dieCh did not receive expected event")
	}

	select {
	case r := <-dieCh:
		t.Fatalf("unexpected extra event in dieCh: %+v", r)
	default:
	}

	// startCh should only receive evStart
	select {
	case r := <-startCh:
		if r.ID != "e-start" {
			t.Errorf("expected e-start, got %s", r.ID)
		}
	case <-time.After(50 * time.Millisecond):
		t.Fatal("startCh did not receive expected event")
	}
}

func TestMultiplexer_BackpressureDropOldest(t *testing.T) {
	cfg := DefaultMultiplexerConfig()
	cfg.DropPolicy = DropOldest
	m := NewEventMultiplexer(cfg)
	defer m.Close()

	// Small buffer of 2
	ch, _ := m.Subscribe("small-buf", EventFilter{}, 2)

	// Publish 3 events
	m.Publish(DockerEvent{ID: "e1", Action: "a1", ActorID: "c1"})
	m.Publish(DockerEvent{ID: "e2", Action: "a2", ActorID: "c1"})
	m.Publish(DockerEvent{ID: "e3", Action: "a3", ActorID: "c1"}) // drops e1 to insert e3

	stats := m.Stats()
	if stats.TotalDropped != 1 {
		t.Errorf("expected 1 dropped event due to backpressure, got %d", stats.TotalDropped)
	}

	// Drain channel: should receive e2 then e3 (e1 was dropped)
	first := <-ch
	if first.ID != "e2" {
		t.Errorf("expected e2 after e1 dropped, got %s", first.ID)
	}

	second := <-ch
	if second.ID != "e3" {
		t.Errorf("expected e3, got %s", second.ID)
	}
}

func TestMultiplexer_BackpressureDropNewest(t *testing.T) {
	cfg := DefaultMultiplexerConfig()
	cfg.DropPolicy = DropNewest
	m := NewEventMultiplexer(cfg)
	defer m.Close()

	ch, _ := m.Subscribe("small-buf-newest", EventFilter{}, 2)

	m.Publish(DockerEvent{ID: "e1", Action: "a1", ActorID: "c1"})
	m.Publish(DockerEvent{ID: "e2", Action: "a2", ActorID: "c1"})
	m.Publish(DockerEvent{ID: "e3", Action: "a3", ActorID: "c1"}) // drops e3

	stats := m.Stats()
	if stats.TotalDropped != 1 {
		t.Errorf("expected 1 dropped event, got %d", stats.TotalDropped)
	}

	first := <-ch
	if first.ID != "e1" {
		t.Errorf("expected e1, got %s", first.ID)
	}

	second := <-ch
	if second.ID != "e2" {
		t.Errorf("expected e2, got %s", second.ID)
	}

	select {
	case unexpected := <-ch:
		t.Fatalf("unexpected event: %+v", unexpected)
	default:
	}
}

func TestMultiplexer_Unsubscribe(t *testing.T) {
	cfg := DefaultMultiplexerConfig()
	m := NewEventMultiplexer(cfg)
	defer m.Close()

	ch, _ := m.Subscribe("sub-to-remove", EventFilter{}, 5)
	if !m.Unsubscribe("sub-to-remove") {
		t.Fatal("expected unsubscribe to succeed")
	}

	// Channel should be closed
	_, open := <-ch
	if open {
		t.Error("expected channel to be closed after unsubscribe")
	}

	if m.Unsubscribe("non-existent") {
		t.Error("expected unsubscribe on missing ID to return false")
	}
}

func TestMultiplexer_Concurrency(t *testing.T) {
	cfg := DefaultMultiplexerConfig()
	m := NewEventMultiplexer(cfg)
	defer m.Close()

	const subs = 10
	var channels []<-chan DockerEvent
	for i := 0; i < subs; i++ {
		ch, err := m.Subscribe(fmt.Sprintf("sub-%d", i), EventFilter{}, 100)
		if err != nil {
			t.Fatalf("failed subscribing: %v", err)
		}
		channels = append(channels, ch)
	}

	const publishers = 5
	const eventsPerPub = 20
	var wg sync.WaitGroup
	wg.Add(publishers)

	for p := 0; p < publishers; p++ {
		pubID := p
		go func() {
			defer wg.Done()
			for e := 0; e < eventsPerPub; e++ {
				m.Publish(DockerEvent{
					ID:      fmt.Sprintf("ev-%d-%d", pubID, e),
					Action:  "ping",
					ActorID: "c-worker",
				})
			}
		}()
	}

	wg.Wait()

	stats := m.Stats()
	if stats.TotalIngested != int64(publishers*eventsPerPub) {
		t.Errorf("expected %d ingested events, got %d", publishers*eventsPerPub, stats.TotalIngested)
	}
}
