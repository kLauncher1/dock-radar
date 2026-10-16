package storage

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// OffloadTask wraps a chunk targeted for S3 upload along with retry telemetry.
type OffloadTask struct {
	Chunk       *LogChunk
	Attempt     int
	MaxAttempts int
}

// Offloader manages an asynchronous worker queue streaming chunks to S3 with exponential backoff.
type Offloader struct {
	mu                 sync.RWMutex
	client             *S3Client
	chunker            *Chunker
	queue              chan *OffloadTask
	maxRetries         int
	baseBackoff        time.Duration
	offloadedCount     int64
	failedCount        int64
	lastOffloadTime    time.Time
	lastError          string
	onOffloadCompleted func(chunk *LogChunk)
	cancel             context.CancelFunc
	done               chan struct{}
}

// NewOffloader initializes a background offloader.
func NewOffloader(client *S3Client, chunker *Chunker, queueSize int) *Offloader {
	if queueSize <= 0 {
		queueSize = 500
	}
	return &Offloader{
		client:      client,
		chunker:     chunker,
		queue:       make(chan *OffloadTask, queueSize),
		maxRetries:  3,
		baseBackoff: 100 * time.Millisecond,
		done:        make(chan struct{}),
	}
}

// SetCompletionCallback registers an event hook invoked whenever a chunk is successfully uploaded.
func (o *Offloader) SetCompletionCallback(fn func(chunk *LogChunk)) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.onOffloadCompleted = fn
}

// UpdateClient dynamically swaps the S3 client when settings are reconfigured.
func (o *Offloader) UpdateClient(client *S3Client) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.client = client
}

// Start launches the offloader processing worker loop.
func (o *Offloader) Start(parentCtx context.Context) {
	o.mu.Lock()
	if o.cancel != nil {
		o.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(parentCtx)
	o.cancel = cancel
	o.done = make(chan struct{})
	o.mu.Unlock()

	go o.workerLoop(ctx)
}

// Stop cleanly terminates the offloader worker.
func (o *Offloader) Stop() {
	o.mu.Lock()
	cancel := o.cancel
	done := o.done
	o.cancel = nil
	o.mu.Unlock()

	if cancel != nil {
		cancel()
		<-done
	}
}

// Enqueue queues a chunk for cloud offload. If S3 is disabled, status is set to S3StatusDisabled.
func (o *Offloader) Enqueue(chunk *LogChunk) bool {
	if chunk == nil {
		return false
	}

	o.mu.RLock()
	client := o.client
	o.mu.RUnlock()

	if client == nil || !client.Config().IsEnabled() {
		chunk.S3Status = S3StatusDisabled
		return false
	}

	chunk.S3Status = S3StatusPending
	task := &OffloadTask{
		Chunk:       chunk,
		Attempt:     1,
		MaxAttempts: o.maxRetries,
	}

	select {
	case o.queue <- task:
		return true
	default:
		// Queue saturated; mark as failed
		chunk.S3Status = S3StatusFailed
		atomic.AddInt64(&o.failedCount, 1)
		o.mu.Lock()
		o.lastError = "offloader worker queue saturated"
		o.mu.Unlock()
		return false
	}
}

// QueueDepth returns the number of pending tasks waiting in the queue.
func (o *Offloader) QueueDepth() int {
	return len(o.queue)
}

// Stats returns counters and error information.
func (o *Offloader) Stats() (offloaded int64, failed int64, lastOffload time.Time, lastErr string) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return atomic.LoadInt64(&o.offloadedCount), atomic.LoadInt64(&o.failedCount), o.lastOffloadTime, o.lastError
}

func (o *Offloader) workerLoop(ctx context.Context) {
	defer close(o.done)

	for {
		select {
		case <-ctx.Done():
			return
		case task, ok := <-o.queue:
			if !ok {
				return
			}
			o.executeTask(ctx, task)
		}
	}
}

func (o *Offloader) executeTask(ctx context.Context, task *OffloadTask) {
	chunk := task.Chunk
	chunk.S3Status = S3StatusOffloading

	o.mu.RLock()
	client := o.client
	cb := o.onOffloadCompleted
	o.mu.RUnlock()

	if client == nil || !client.Config().IsEnabled() {
		chunk.S3Status = S3StatusDisabled
		return
	}

	var data []byte
	var err error

	if chunk.LocalPath != "" {
		data, err = o.chunker.ReadChunkBytes(chunk.LocalPath)
	} else {
		err = fmt.Errorf("local chunk file missing for %s", chunk.ID)
	}

	if err == nil {
		objectKey := chunk.ID + ".gz"
		storageClass := chunk.StorageClass
		if storageClass == "" {
			storageClass = client.Config().StorageClass
		}

		uploadCtx, uploadCancel := context.WithTimeout(ctx, 30*time.Second)
		err = client.PutObject(uploadCtx, objectKey, data, "application/gzip", storageClass)
		uploadCancel()
	}

	if err == nil {
		chunk.S3Key = client.BuildObjectKey(chunk.ID + ".gz")
		chunk.S3Status = S3StatusOffloaded
		now := time.Now().UTC()
		atomic.AddInt64(&o.offloadedCount, 1)

		o.mu.Lock()
		o.lastOffloadTime = now
		o.mu.Unlock()

		if cb != nil {
			cb(chunk)
		}
		return
	}

	// Retry handling
	if task.Attempt < task.MaxAttempts && ctx.Err() == nil {
		backoff := o.baseBackoff * time.Duration(1<<uint(task.Attempt-1))
		task.Attempt++
		time.Sleep(backoff)

		select {
		case <-ctx.Done():
			chunk.S3Status = S3StatusFailed
			return
		case o.queue <- task:
			return
		default:
			// Failed to re-enqueue
		}
	}

	chunk.S3Status = S3StatusFailed
	atomic.AddInt64(&o.failedCount, 1)
	o.mu.Lock()
	o.lastError = err.Error()
	o.mu.Unlock()
}
