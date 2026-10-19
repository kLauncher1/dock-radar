package firewall

import (
	"testing"
	"time"
)

func TestBandwidthInspector_TrafficDeltas(t *testing.T) {
	bi := NewBandwidthInspector(1000, 1000000, false, 10)

	t0 := time.Now()
	// Initial baseline sample
	bi.RecordTraffic("c-1", "nginx-ingress", 1000, 2000, 10, 20, t0)

	// Second sample 1 second later with +5000 bytes out, +50 packets out
	t1 := t0.Add(1 * time.Second)
	throttled, alert := bi.RecordTraffic("c-1", "nginx-ingress", 2000, 7000, 20, 70, t1)
	if throttled || alert != nil {
		t.Fatalf("expected no throttle on normal traffic")
	}

	stats := bi.Stats()
	if len(stats) != 1 {
		t.Fatalf("expected 1 container stat, got %d", len(stats))
	}
	if stats[0].EgressBPS != 5000 {
		t.Fatalf("expected EgressBPS=5000, got %d", stats[0].EgressBPS)
	}
	if stats[0].EgressPPS != 50 {
		t.Fatalf("expected EgressPPS=50, got %d", stats[0].EgressPPS)
	}
}

func TestBandwidthInspector_DDoSAlertTrigger(t *testing.T) {
	// Threshold: 100 PPS, 50,000 BPS
	bi := NewBandwidthInspector(100, 50000, true, 30)

	t0 := time.Now()
	bi.RecordTraffic("c-ddos", "compromised-pod", 100, 100, 1, 1, t0)

	// Ingress flood: +10,000 packets in 1 second (10,000 PPS > 100 PPS)
	t1 := t0.Add(1 * time.Second)
	throttled, alert := bi.RecordTraffic("c-ddos", "compromised-pod", 100000, 100, 10001, 1, t1)
	if !throttled || alert == nil {
		t.Fatalf("expected DDoS detection and throttling on PPS flood")
	}

	if alert.ActionTaken != "QUARANTINED" {
		t.Fatalf("expected QUARANTINED action, got %s", alert.ActionTaken)
	}
	if alert.ObservedPPS != 10000 {
		t.Fatalf("expected ObservedPPS=10000, got %d", alert.ObservedPPS)
	}

	alerts := bi.RecentAlerts(10)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 recent alert, got %d", len(alerts))
	}

	// Verify container is marked throttled
	if !bi.IsContainerThrottled("c-ddos") {
		t.Fatalf("expected c-ddos to be throttled")
	}
}
