# Container Runtime API Layer

This document describes the comprehensive container runtime API layer that has been added to the OpenShift MCP Server to provide native container management capabilities using Podman and other container runtimes.

## Overview

The container runtime API layer provides a unified interface for interacting with container runtimes like Podman, enabling the MCP server to build, push, pull, and manage container images and containers locally without requiring external dependencies.

## Architecture

### Core Components

1. **Container Package (`pkg/container/`)**
   - `types.go` - Defines all interfaces, types, and data structures
   - `manager.go` - Manages multiple container runtimes and provides runtime selection
   - `podman.go` - Podman runtime implementation

2. **MCP Integration (`pkg/mcp/containers.go`)**
   - Contains all MCP tool definitions for container operations
   - Integrates with the container API layer
   - Provides user-friendly MCP tools for AI assistants

### Container Runtime Interface

The `ContainerRuntime` interface provides a comprehensive set of operations:

#### Image Operations
- `BuildImage()` - Build container images from Dockerfiles
- `PushImage()` - Push images to container registries
- `PullImage()` - Pull images from container registries
- `ListImages()` - List available images
- `InspectImage()` - Get detailed image information
- `RemoveImage()` - Remove images
- `TagImage()` - Tag images with new names

#### Container Operations
- `RunContainer()` - Run containers from images
- `ListContainers()` - List containers
- `InspectContainer()` - Get detailed container information
- `StopContainer()` - Stop running containers
- `RemoveContainer()` - Remove containers
- `ContainerLogs()` - Get container logs
- `ExecContainer()` - Execute commands in containers

#### Runtime Information
- `Version()` - Get runtime version information
- `Info()` - Get runtime system information
- `IsAvailable()` - Check if runtime is available
- `Name()` - Get runtime name

## Available MCP Tools

The following MCP tools are now available for AI assistants:

### Image Management Tools

1. **container_build_image**
   - Build container images using Dockerfile
   - Parameters: imageTag (required), dockerfile, context, platform, target, noCache, pull, quiet, buildArgs, labels, runtime

2. **container_push_image**
   - Push container images to registries
   - Parameters: imageTag (required), registry, username, password, skipTlsVerify, quiet, runtime

3. **container_pull_image**
   - Pull container images from registries
   - Parameters: imageTag (required), registry, username, password, skipTlsVerify, quiet, runtime

4. **container_list_images**
   - List available container images
   - Parameters: all, filter, quiet, runtime

5. **container_inspect_image**
   - Inspect container image details
   - Parameters: imageId (required), runtime

6. **container_remove_image**
   - Remove container images
   - Parameters: imageId (required), force, runtime

7. **container_tag_image**
   - Tag container images
   - Parameters: sourceImage (required), targetImage (required), runtime

### Container Management Tools

8. **container_run**
   - Run containers from images
   - Parameters: image (required), name, command, entrypoint, env, workingDir, user, ports, volumes, labels, detach, remove, interactive, tty, privileged, readOnly, restartPolicy, runtime

9. **container_list**
   - List containers
   - Parameters: all, filter, quiet, size, runtime

10. **container_inspect**
    - Inspect container details
    - Parameters: containerId (required), runtime

11. **container_stop**
    - Stop running containers
    - Parameters: containerId (required), timeout, runtime

12. **container_remove**
    - Remove containers
    - Parameters: containerId (required), force, runtime

13. **container_logs**
    - Get container logs
    - Parameters: containerId (required), follow, since, until, timestamps, tail, runtime

14. **container_exec**
    - Execute commands in containers
    - Parameters: containerId (required), command (required), user, workingDir, env, privileged, interactive, tty, runtime

### Runtime Information Tools

15. **container_runtime_info**
    - Get container runtime information
    - Parameters: runtime (optional)

16. **container_runtime_version**
    - Get container runtime version
    - Parameters: runtime (optional)

17. **validate_base_image_ubi**
    - Validate if Dockerfile uses Red Hat UBI base images
    - Parameters: dockerfilePath (path to local Dockerfile)

## Runtime Support

### Podman Runtime

The primary container runtime implementation is Podman, which is preferred for OpenShift and RHEL environments:

- **Native Integration**: Direct integration with Podman binary
- **Feature Complete**: Supports all container and image operations
- **Security Focused**: Rootless container support
- **Registry Support**: Works with all OCI-compliant registries
- **Red Hat Compatibility**: Optimized for Red Hat ecosystems

### Extensible Design

The architecture is designed to support multiple container runtimes:

- **Runtime Manager**: Automatically detects available runtimes
- **Primary Runtime**: Selects the best available runtime (Podman preferred)
- **Runtime Selection**: Tools can specify which runtime to use
- **Future Extensibility**: Easy to add Docker or other runtime implementations

## Usage Examples

### Building an Image

```json
{
  "tool": "container_build_image",
  "arguments": {
    "imageTag": "quay.io/myorg/myapp:v1.0.0",
    "dockerfile": "Dockerfile",
    "context": ".",
    "buildArgs": {
      "VERSION": "1.0.0",
      "BUILD_DATE": "2024-01-01"
    },
    "labels": {
      "maintainer": "myorg",
      "version": "1.0.0"
    }
  }
}
```

### Running a Container

```json
{
  "tool": "container_run",
  "arguments": {
    "image": "registry.redhat.io/ubi9/ubi:latest",
    "name": "my-app",
    "command": ["bash", "-c", "echo Hello World"],
    "env": ["ENV_VAR=value"],
    "ports": ["8080:80"],
    "volumes": ["/host/data:/container/data:ro"],
    "detach": true
  }
}
```

### Listing Images

```json
{
  "tool": "container_list_images",
  "arguments": {
    "all": true,
    "filter": "reference=quay.io/*"
  }
}
```

### Validating UBI Base Images

```json
{
  "tool": "validate_base_image_ubi",
  "arguments": {
    "dockerfilePath": "./Dockerfile"
  }
}
```

## Integration Benefits

### For OpenShift Environments

1. **Native Container Operations**: Direct container management without external tools
2. **UBI Image Validation**: Built-in validation for Red Hat Universal Base Images
3. **Registry Integration**: Seamless integration with OpenShift internal registry
4. **Security Compliance**: Supports rootless containers and security policies

### For AI Assistants

1. **Comprehensive Container Management**: Full lifecycle container operations
2. **Unified Interface**: Consistent API across different container runtimes
3. **Rich Metadata**: Detailed information about images and containers
4. **Error Handling**: Proper error reporting and status information

### For Development Workflows

1. **Local Development**: Build and test containers locally
2. **CI/CD Integration**: Automated container building and pushing
3. **Multi-Platform Support**: Cross-platform container building
4. **Registry Management**: Push to multiple registries

## Error Handling

The API layer provides comprehensive error handling:

- **Runtime Availability**: Checks if container runtime is available
- **Operation Status**: Returns success/failure status for all operations
- **Detailed Errors**: Provides detailed error messages and output
- **Graceful Degradation**: Falls back to alternative runtimes when possible

## Security Considerations

1. **Runtime Security**: Leverages container runtime security features
2. **Registry Authentication**: Supports secure registry authentication
3. **Privilege Management**: Controlled privilege escalation
4. **Resource Isolation**: Proper container resource isolation

## Future Enhancements

1. **Docker Runtime**: Add Docker runtime implementation
2. **BuildKit Integration**: Support for advanced BuildKit features
3. **Multi-Architecture Builds**: Enhanced cross-platform building
4. **Container Networking**: Advanced networking configuration
5. **Volume Management**: Enhanced volume and storage management
6. **Registry Management**: Built-in registry management tools

## Conclusion

The container runtime API layer transforms the OpenShift MCP Server into a comprehensive container management platform, enabling AI assistants to perform complex container operations locally while maintaining security, performance, and compatibility with OpenShift environments.
