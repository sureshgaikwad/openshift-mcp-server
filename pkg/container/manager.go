package container

import (
	"context"
	"fmt"
)

// Manager manages container runtime instances
type Manager struct {
	runtimes map[string]ContainerRuntime
	primary  ContainerRuntime
}

// NewManager creates a new container runtime manager
func NewManager() *Manager {
	manager := &Manager{
		runtimes: make(map[string]ContainerRuntime),
	}

	// Try to initialize available runtimes
	manager.initRuntimes()

	return manager
}

// initRuntimes initializes available container runtimes
func (m *Manager) initRuntimes() {
	// Try Podman first (preferred for OpenShift/RHEL environments)
	if podman, err := NewPodmanRuntime(); err == nil && podman.IsAvailable() {
		m.runtimes["podman"] = podman
		if m.primary == nil {
			m.primary = podman
		}
		fmt.Printf("✅ Podman runtime initialized successfully\n")
	} else {
		fmt.Printf("⚠️  Podman runtime not available: %v\n", err)
	}

	// Add Docker runtime support as fallback
	if docker, err := NewDockerRuntime(); err == nil && docker.IsAvailable() {
		m.runtimes["docker"] = docker
		if m.primary == nil {
			m.primary = docker
		}
		fmt.Printf("✅ Docker runtime initialized successfully\n")
	} else {
		fmt.Printf("⚠️  Docker runtime not available: %v\n", err)
	}

	// Log available runtimes for debugging
	if len(m.runtimes) == 0 {
		fmt.Printf("❌ No container runtimes available. Check PATH or install Podman/Docker.\n")
		fmt.Printf("💡 Tip: Set PODMAN_BINARY or DOCKER_BINARY environment variables to specify custom paths.\n")
	} else {
		availableRuntimes := make([]string, 0, len(m.runtimes))
		for name := range m.runtimes {
			availableRuntimes = append(availableRuntimes, name)
		}
		fmt.Printf("🚀 Available container runtimes: %v (primary: %s)\n", availableRuntimes, m.primary.Name())
	}
}

// GetRuntime returns a specific container runtime by name
func (m *Manager) GetRuntime(name string) (ContainerRuntime, error) {
	runtime, exists := m.runtimes[name]
	if !exists {
		return nil, fmt.Errorf("container runtime '%s' not found or not available", name)
	}
	return runtime, nil
}

// GetPrimaryRuntime returns the primary (default) container runtime
func (m *Manager) GetPrimaryRuntime() (ContainerRuntime, error) {
	if m.primary == nil {
		return nil, fmt.Errorf("no container runtime available")
	}
	return m.primary, nil
}

// GetAvailableRuntimes returns a list of available runtime names
func (m *Manager) GetAvailableRuntimes() []string {
	runtimes := make([]string, 0, len(m.runtimes))
	for name := range m.runtimes {
		runtimes = append(runtimes, name)
	}
	return runtimes
}

// IsAnyRuntimeAvailable checks if any container runtime is available
func (m *Manager) IsAnyRuntimeAvailable() bool {
	return m.primary != nil
}

// GetRuntimeInfo returns information about all available runtimes
func (m *Manager) GetRuntimeInfo(ctx context.Context) (map[string]*RuntimeInfo, error) {
	info := make(map[string]*RuntimeInfo)

	for name, runtime := range m.runtimes {
		runtimeInfo, err := runtime.Info(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get info for runtime '%s': %w", name, err)
		}
		info[name] = runtimeInfo
	}

	return info, nil
}

// GetRuntimeVersions returns version information about all available runtimes
func (m *Manager) GetRuntimeVersions(ctx context.Context) (map[string]*RuntimeVersion, error) {
	versions := make(map[string]*RuntimeVersion)

	for name, runtime := range m.runtimes {
		version, err := runtime.Version(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get version for runtime '%s': %w", name, err)
		}
		versions[name] = version
	}

	return versions, nil
}

// SetPrimaryRuntime sets the primary runtime by name
func (m *Manager) SetPrimaryRuntime(name string) error {
	runtime, exists := m.runtimes[name]
	if !exists {
		return fmt.Errorf("container runtime '%s' not found or not available", name)
	}

	m.primary = runtime
	return nil
}

// RegisterRuntime registers a custom container runtime
func (m *Manager) RegisterRuntime(name string, runtime ContainerRuntime) error {
	if !runtime.IsAvailable() {
		return fmt.Errorf("runtime '%s' is not available", name)
	}

	m.runtimes[name] = runtime

	// Set as primary if no primary runtime exists
	if m.primary == nil {
		m.primary = runtime
	}

	return nil
}
