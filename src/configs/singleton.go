package configs

import (
	"sync"
)

var (
	// modelOnce ensures the singleton is instantiated only once.
	modelOnce = &sync.Once{}
	// modelSingleton points to the singleton value.
	modelSingleton *Model
)

// Get provides the config singleton.
func Get() *Model {
	// This statement only executes once.
	modelOnce.Do(func() {
		modelSingleton = withViper()
	})
	// Returning the loaded configs.
	return modelSingleton
}
