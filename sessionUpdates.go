package auth

import (
	"sync"
)

var flushQueue struct {
	queue  map[string]bool
	qMutex sync.Mutex
}

func init() {
	flushQueue.queue = make(map[string]bool)
}

func FlushSessionForUser(name string) {
	flushQueue.qMutex.Lock()

	flushQueue.queue[name] = true

	flushQueue.qMutex.Unlock()
}

func HasToRefresh(name string) bool {
	flushQueue.qMutex.Lock()

	exists := flushQueue.queue[name]
	delete(flushQueue.queue, name)

	flushQueue.qMutex.Unlock()
	return exists
}
