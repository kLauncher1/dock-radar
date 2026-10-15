package rolling

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestStore_SaveAndGet(t *testing.T) {
	store := NewStore(10)

	op := &RollingOperation{
		ID:              "roll-1",
		Status:          StatusPending,
		TotalContainers: 3,
		CreatedAt:       time.Now(),
	}

	store.Save(op)

	retrieved, found := store.Get("roll-1")
	if !found {
		t.Fatalf("expected to find roll-1, but not found")
	}
	if retrieved.Status != StatusPending {
		t.Fatalf("expected status pending, got %s", retrieved.Status)
	}

	// Update status
	op.Status = StatusCompleted
	store.Save(op)

	retrieved2, _ := store.Get("roll-1")
	if retrieved2.Status != StatusCompleted {
		t.Fatalf("expected status completed after update, got %s", retrieved2.Status)
	}
}

func TestStore_CapacityEviction(t *testing.T) {
	store := NewStore(3)

	for i := 1; i <= 5; i++ {
		store.Save(&RollingOperation{
			ID:     fmt.Sprintf("roll-%d", i),
			Status: StatusCompleted,
		})
	}

	if store.Count() != 3 {
		t.Fatalf("expected store count 3, got %d", store.Count())
	}

	// Oldest (roll-1 and roll-2) should have been evicted
	if _, found := store.Get("roll-1"); found {
		t.Fatalf("expected roll-1 to be evicted")
	}
	if _, found := store.Get("roll-2"); found {
		t.Fatalf("expected roll-2 to be evicted")
	}
	if _, found := store.Get("roll-5"); !found {
		t.Fatalf("expected roll-5 to be retained")
	}
}

func TestStore_ListAndActive(t *testing.T) {
	store := NewStore(10)

	store.Save(&RollingOperation{ID: "roll-1", Status: StatusCompleted})
	store.Save(&RollingOperation{ID: "roll-2", Status: StatusRestarting})
	store.Save(&RollingOperation{ID: "roll-3", Status: StatusDraining})

	active := store.Active()
	if len(active) != 2 {
		t.Fatalf("expected 2 active operations, got %d", len(active))
	}

	list := store.List(2)
	if len(list) != 2 {
		t.Fatalf("expected list limit 2, got %d", len(list))
	}
	// Newest first
	if list[0].ID != "roll-3" {
		t.Fatalf("expected newest operation roll-3 first, got %s", list[0].ID)
	}
}

func TestStore_Concurrency(t *testing.T) {
	store := NewStore(50)
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			id := fmt.Sprintf("con-roll-%d", idx)
			store.Save(&RollingOperation{ID: id, Status: StatusPending})
			_, _ = store.Get(id)
			_ = store.List(10)
			_ = store.Active()
		}(i)
	}

	wg.Wait()
	if store.Count() != 20 {
		t.Fatalf("expected 20 items, got %d", store.Count())
	}
}
