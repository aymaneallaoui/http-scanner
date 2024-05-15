package modules

import (
	"sync"
)

var (
	modulesMu sync.RWMutex
	modules   = make(map[string]ScanModule)
)

func RegisterModule(module ScanModule) {
	modulesMu.Lock()
	defer modulesMu.Unlock()

	modules[module.Name()] = module
}

func GetModule(name string) (ScanModule, bool) {
	modulesMu.RLock()
	defer modulesMu.RUnlock()

	module, ok := modules[name]
	return module, ok
}

func GetModules() []ScanModule {
	modulesMu.RLock()
	defer modulesMu.RUnlock()

	result := make([]ScanModule, 0, len(modules))
	for _, module := range modules {
		result = append(result, module)
	}

	return result
}
