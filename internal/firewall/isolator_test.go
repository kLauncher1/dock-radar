package firewall

import (
	"testing"
)

func TestNetworkIsolator_SetAndGet(t *testing.T) {
	iso := NewNetworkIsolator(false)

	st := iso.SetIsolation("c-app-1", "frontend-web", IsolationStrictZero, "Security audit policy", []string{"c-db-1"}, 1000000, 2000000)
	if st.ContainerID != "c-app-1" || st.IsolationLevel != IsolationStrictZero {
		t.Fatalf("expected c-app-1 with StrictZero isolation")
	}

	retrieved, ok := iso.GetIsolation("c-app-1")
	if !ok || len(retrieved.AllowedPeers) != 1 || retrieved.AllowedPeers[0] != "c-db-1" {
		t.Fatalf("failed to retrieve correct isolation state: %+v", retrieved)
	}

	all := iso.ListIsolations()
	if len(all) != 1 {
		t.Fatalf("expected 1 active isolation, got %d", len(all))
	}

	// Remove isolation
	if !iso.RemoveIsolation("c-app-1") {
		t.Fatalf("expected RemoveIsolation to return true")
	}
	if _, ok := iso.GetIsolation("c-app-1"); ok {
		t.Fatalf("expected c-app-1 to be removed")
	}
}

func TestNetworkIsolator_CheckTraffic(t *testing.T) {
	iso := NewNetworkIsolator(false)

	// Setup:
	// c-frontend: STRICT_ZEROTRUST, allowed: [c-backend]
	// c-malicious: FULL_QUARANTINE
	// c-worker: PARTIAL
	// c-backend: NONE
	iso.SetIsolation("c-frontend", "frontend", IsolationStrictZero, "DMZ policy", []string{"c-backend"}, 0, 0)
	iso.Quarantine("c-malicious", "malicious-pod", "Crypto miner detected")
	iso.SetIsolation("c-worker", "worker-job", IsolationPartial, "Isolated worker", nil, 0, 0)

	// 1. Quarantined container should be dropped completely
	action, _ := iso.CheckTraffic("c-malicious", "c-backend", true)
	if action != ActionDrop {
		t.Fatalf("expected ActionDrop for quarantined container, got %s", action)
	}

	// 2. c-frontend -> c-backend should be allowed (whitelisted)
	action2, _ := iso.CheckTraffic("c-frontend", "c-backend", true)
	if action2 != ActionAllow {
		t.Fatalf("expected ActionAllow for whitelisted peer, got %s", action2)
	}

	// 3. c-frontend -> c-worker should be dropped (not in allowed peers)
	action3, _ := iso.CheckTraffic("c-frontend", "c-worker", true)
	if action3 != ActionDrop {
		t.Fatalf("expected ActionDrop for non-whitelisted peer, got %s", action3)
	}

	// 4. c-worker (Partial) to external should be ALLOW, but to internal container should be DROP
	actionExt, _ := iso.CheckTraffic("c-worker", "external-ip", false)
	if actionExt != ActionAllow {
		t.Fatalf("expected ActionAllow for external egress from partial isolation, got %s", actionExt)
	}
	actionInt, _ := iso.CheckTraffic("c-worker", "c-backend", true)
	if actionInt != ActionDrop {
		t.Fatalf("expected ActionDrop for inter-container traffic from partial isolation, got %s", actionInt)
	}

	// 5. Global Zero-Trust test
	isoGlobal := NewNetworkIsolator(true)
	actionGlobal, _ := isoGlobal.CheckTraffic("c-any-1", "c-any-2", true)
	if actionGlobal != ActionDrop {
		t.Fatalf("expected ActionDrop under global zero-trust, got %s", actionGlobal)
	}
}
