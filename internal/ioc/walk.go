package ioc

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

// walkConcurrent visits every file under root, calling fn from several
// goroutines at once.
//
// filepath.WalkDir is sequential, and this layer opts back into node_modules,
// so on a real tree the walk itself — not the file reads — is the cost: 56k
// files per second measured, against a tree of millions. Directories are
// handed to a worker pool as they are discovered, so one enormous
// node_modules no longer serialises the whole sweep.
//
// fn must be safe to call concurrently. Unreadable directories are reported
// through fn with a non-nil error and never abort the walk: a forensic sweep
// that stops at the first permission error is useless on a real machine.
func walkConcurrent(root string, workers int, fn func(path string, d fs.DirEntry, err error)) {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}

	var wg sync.WaitGroup
	// pending counts directories queued but not yet processed, so the walk can
	// tell "no work right now" from "no work left".
	var pending sync.WaitGroup
	queue := make(chan string, workers*64)

	push := func(dir string) {
		pending.Add(1)
		go func() { queue <- dir }()
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for dir := range queue {
				entries, err := os.ReadDir(dir)
				if err != nil {
					fn(dir, nil, err)
					pending.Done()
					continue
				}
				for _, e := range entries {
					path := filepath.Join(dir, e.Name())
					if e.IsDir() {
						if e.Name() == ".git" {
							continue
						}
						push(path)
						continue
					}
					fn(path, e, nil)
				}
				pending.Done()
			}
		}()
	}

	push(root)
	pending.Wait()
	close(queue)
	wg.Wait()
}
