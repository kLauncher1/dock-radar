package firewall

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

type containerCounter struct {
	lastBytesIn   uint64
	lastBytesOut  uint64
	lastPacketsIn uint64
	lastPacketsOut uint64
	lastSampleTime time.Time

	currentBPSIn  uint64
	currentBPSOut uint64
	currentPPSIn  uint64
	currentPPSOut uint64

	totalBytesIn  uint64
	totalBytesOut uint64
	totalPacketsIn uint64
	totalPacketsOut uint64
	containerName string

	// Rate limiting token bucket for throttled containers
	egressTokens   float64
	ingressTokens  float64
	lastTokenTime  time.Time
	isThrottled    bool
	throttleExpiry time.Time
}

// BandwidthInspector monitors container network volume, computes BPS/PPS, and throttles DDoS floods.
type BandwidthInspector struct {
	mu            sync.RWMutex
	containers    map[string]*containerCounter
	alerts        []DDoSAlertEvent
	maxAlerts     int
	thresholdPPS  uint64
	thresholdBPS  uint64
	autoQuarantine bool
	cooldownSec   int
	lastAlertTime map[string]time.Time
}

// NewBandwidthInspector initializes a new bandwidth inspector and DDoS detector.
func NewBandwidthInspector(thresholdPPS, thresholdBPS uint64, autoQuarantine bool, cooldownSec int) *BandwidthInspector {
	if thresholdPPS == 0 {
		thresholdPPS = 50000
	}
	if thresholdBPS == 0 {
		thresholdBPS = 104857600 // 100 MB/s
	}
	if cooldownSec <= 0 {
		cooldownSec = 60
	}
	return &BandwidthInspector{
		containers:     make(map[string]*containerCounter),
		alerts:         make([]DDoSAlertEvent, 0),
		maxAlerts:      500,
		thresholdPPS:   thresholdPPS,
		thresholdBPS:   thresholdBPS,
		autoQuarantine: autoQuarantine,
		cooldownSec:    cooldownSec,
		lastAlertTime:  make(map[string]time.Time),
	}
}

// RecordTraffic records raw packet and byte deltas for a container, updating live BPS/PPS rates.
func (bi *BandwidthInspector) RecordTraffic(containerID, containerName string, bytesIn, bytesOut, packetsIn, packetsOut uint64, sampleTime time.Time) (bool, *DDoSAlertEvent) {
	bi.mu.Lock()
	defer bi.mu.Unlock()

	c, exists := bi.containers[containerID]
	if !exists {
		c = &containerCounter{
			lastBytesIn:    bytesIn,
			lastBytesOut:   bytesOut,
			lastPacketsIn:  packetsIn,
			lastPacketsOut: packetsOut,
			lastSampleTime: sampleTime,
			containerName:  containerName,
			lastTokenTime:  sampleTime,
		}
		bi.containers[containerID] = c
		return false, nil
	}

	c.containerName = containerName
	elapsed := sampleTime.Sub(c.lastSampleTime).Seconds()
	if elapsed <= 0 {
		elapsed = 1.0
	}

	var deltaBytesIn, deltaBytesOut, deltaPacketsIn, deltaPacketsOut uint64
	if bytesIn >= c.lastBytesIn {
		deltaBytesIn = bytesIn - c.lastBytesIn
	}
	if bytesOut >= c.lastBytesOut {
		deltaBytesOut = bytesOut - c.lastBytesOut
	}
	if packetsIn >= c.lastPacketsIn {
		deltaPacketsIn = packetsIn - c.lastPacketsIn
	}
	if packetsOut >= c.lastPacketsOut {
		deltaPacketsOut = packetsOut - c.lastPacketsOut
	}

	c.currentBPSIn = uint64(float64(deltaBytesIn) / elapsed)
	c.currentBPSOut = uint64(float64(deltaBytesOut) / elapsed)
	c.currentPPSIn = uint64(float64(deltaPacketsIn) / elapsed)
	c.currentPPSOut = uint64(float64(deltaPacketsOut) / elapsed)

	c.totalBytesIn += deltaBytesIn
	c.totalBytesOut += deltaBytesOut
	c.totalPacketsIn += deltaPacketsIn
	c.totalPacketsOut += deltaPacketsOut

	c.lastBytesIn = bytesIn
	c.lastBytesOut = bytesOut
	c.lastPacketsIn = packetsIn
	c.lastPacketsOut = packetsOut
	c.lastSampleTime = sampleTime

	// Check DDoS thresholds
	return bi.evaluateDDoS(containerID, c, sampleTime)
}

func (bi *BandwidthInspector) evaluateDDoS(containerID string, c *containerCounter, now time.Time) (bool, *DDoSAlertEvent) {
	// Rate limit alert dispatches per container cooldown window
	lastAlert, alerted := bi.lastAlertTime[containerID]
	if alerted && now.Sub(lastAlert) < time.Duration(bi.cooldownSec)*time.Second {
		return false, nil
	}

	var alert *DDoSAlertEvent
	if c.currentPPSOut > bi.thresholdPPS || c.currentPPSIn > bi.thresholdPPS {
		dir := "EGRESS"
		pps := c.currentPPSOut
		if c.currentPPSIn > c.currentPPSOut {
			dir = "INGRESS"
			pps = c.currentPPSIn
		}
		alert = bi.createAlertLocked(containerID, c.containerName, dir, "High PPS Volumetric Flood (SYN/UDP Flood Suspected)", pps, bi.thresholdPPS, 0, 0, now)
	} else if c.currentBPSOut > bi.thresholdBPS || c.currentBPSIn > bi.thresholdBPS {
		dir := "EGRESS"
		bps := c.currentBPSOut
		if c.currentBPSIn > c.currentBPSOut {
			dir = "INGRESS"
			bps = c.currentBPSIn
		}
		alert = bi.createAlertLocked(containerID, c.containerName, dir, "Bandwidth Exhaustion Flood Exceeding Capacity", 0, 0, bps, bi.thresholdBPS, now)
	}

	if alert != nil {
		bi.lastAlertTime[containerID] = now
		c.isThrottled = true
		c.throttleExpiry = now.Add(time.Duration(bi.cooldownSec) * time.Second)
		return true, alert
	}

	return false, nil
}

func (bi *BandwidthInspector) createAlertLocked(containerID, name, direction, reason string, pps, ppsThresh, bps, bpsThresh uint64, now time.Time) *DDoSAlertEvent {
	actionTaken := "THROTTLED"
	if bi.autoQuarantine {
		actionTaken = "QUARANTINED"
	}

	b := make([]byte, 4)
	_, _ = rand.Read(b)
	alertID := fmt.Sprintf("ddos-%s-%s", containerID[:min(8, len(containerID))], hex.EncodeToString(b))

	evt := DDoSAlertEvent{
		ID:            alertID,
		Timestamp:     now,
		ContainerID:   containerID,
		ContainerName: name,
		Direction:     direction,
		AlertReason:   reason,
		ObservedPPS:   pps,
		ThresholdPPS:  ppsThresh,
		ObservedBPS:   bps,
		ThresholdBPS:  bpsThresh,
		ActionTaken:   actionTaken,
		Summary:       fmt.Sprintf("%s DDoS flood on container %s (%s). Action: %s", direction, name, reason, actionTaken),
	}

	bi.alerts = append(bi.alerts, evt)
	if len(bi.alerts) > bi.maxAlerts {
		bi.alerts = bi.alerts[len(bi.alerts)-bi.maxAlerts:]
	}
	return &evt
}

// IsContainerThrottled checks if a container is currently undergoing active DDoS rate limiting.
func (bi *BandwidthInspector) IsContainerThrottled(containerID string) bool {
	bi.mu.RLock()
	defer bi.mu.RUnlock()

	c, exists := bi.containers[containerID]
	if !exists {
		return false
	}
	if c.isThrottled && time.Now().Before(c.throttleExpiry) {
		return true
	}
	return false
}

// Stats returns a list of bandwidth statistics for all tracked containers.
func (bi *BandwidthInspector) Stats() []BandwidthStats {
	bi.mu.RLock()
	defer bi.mu.RUnlock()

	res := make([]BandwidthStats, 0, len(bi.containers))
	for id, c := range bi.containers {
		res = append(res, BandwidthStats{
			ContainerID:   id,
			ContainerName: c.containerName,
			IngressBPS:    c.currentBPSIn,
			EgressBPS:     c.currentBPSOut,
			IngressPPS:    c.currentPPSIn,
			EgressPPS:     c.currentPPSOut,
			TotalBytesIn:  c.totalBytesIn,
			TotalBytesOut: c.totalBytesOut,
			LastSeen:      c.lastSampleTime,
		})
	}
	return res
}

// RecentAlerts returns recent DDoS anomaly detection events.
func (bi *BandwidthInspector) RecentAlerts(limit int) []DDoSAlertEvent {
	bi.mu.RLock()
	defer bi.mu.RUnlock()

	if limit <= 0 || limit > len(bi.alerts) {
		limit = len(bi.alerts)
	}

	start := len(bi.alerts) - limit
	res := make([]DDoSAlertEvent, limit)
	copy(res, bi.alerts[start:])

	// Return most recent first
	for i, j := 0, len(res)-1; i < j; i, j = i+1, j-1 {
		res[i], res[j] = res[j], res[i]
	}
	return res
}

// UpdateThresholds configures updated DDoS limits.
func (bi *BandwidthInspector) UpdateThresholds(thresholdPPS, thresholdBPS uint64, autoQuarantine bool, cooldownSec int) {
	bi.mu.Lock()
	defer bi.mu.Unlock()

	if thresholdPPS > 0 {
		bi.thresholdPPS = thresholdPPS
	}
	if thresholdBPS > 0 {
		bi.thresholdBPS = thresholdBPS
	}
	bi.autoQuarantine = autoQuarantine
	if cooldownSec > 0 {
		bi.cooldownSec = cooldownSec
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
