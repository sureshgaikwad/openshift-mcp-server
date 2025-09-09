# Intelligent Dockerfile Detection for OpenShift MCP Server

The MCP server now includes intelligent Dockerfile detection that automatically selects the most appropriate Dockerfile based on your deployment context and available files.

## 🎯 Detection Priority

The MCP server automatically detects and uses Dockerfiles in the following priority order:

### **1. Dockerfile.ocp (Highest Priority)**
- **Purpose**: OpenShift-optimized builds
- **Base Images**: Red Hat UBI (Universal Base Images)
- **Features**: 
  - FIPS compliance (`GOEXPERIMENT=strictfipsruntime`)
  - Red Hat enterprise base images
  - OpenShift-specific labels and metadata
  - Optimized for OpenShift Container Platform

**Example Usage:**
```dockerfile
FROM registry.redhat.io/ubi9/go-toolset:1.24.4-1754467841 AS builder
FROM registry.redhat.io/rhel9-4-els/rhel-minimal:9.4
# OpenShift-optimized configuration
```

### **2. Dockerfile.ci (Medium Priority)**  
- **Purpose**: CI/CD pipeline builds
- **Base Images**: OpenShift CI registry images
- **Features**:
  - Enterprise contract compliance
  - CI/CD optimized build process
  - Automated testing integration
  - Multi-platform support

**Example Usage:**
```dockerfile
FROM registry.ci.openshift.org/ocp/builder:rhel-9-golang-1.24-openshift-4.20 AS builder
FROM registry.ci.openshift.org/ocp/4.20:base-rhel9
# CI/CD optimized configuration
```

### **3. Dockerfile (Fallback)**
- **Purpose**: Standard container builds
- **Base Images**: Public registry images
- **Features**:
  - General-purpose container build
  - Public base images
  - Standard Docker practices

**Example Usage:**
```dockerfile
FROM golang:latest AS builder
FROM registry.access.redhat.com/ubi9/ubi-minimal:latest
# Standard configuration
```

## 🔧 How It Works

### **Automatic Detection**

When you use container tools without specifying a Dockerfile, the MCP server:

1. **Scans the build context directory**
2. **Checks for Dockerfiles in priority order**
3. **Selects the first available Dockerfile**
4. **Reports which Dockerfile was selected**

```json
{
  "tool": "container_build_image",
  "arguments": {
    "imageTag": "my-app:latest"
    // No dockerfile specified - auto-detection kicks in
  }
}
```

**Output:**
```
🐳 Detected Dockerfile.ocp: OpenShift-optimized Dockerfile with Red Hat UBI base images
📁 Context Directory: .
🐳 Dockerfile Used: Dockerfile.ocp
🏷️  Image Tag: my-app:latest
```

### **Manual Override**

You can always override the automatic detection:

```json
{
  "tool": "container_build_image", 
  "arguments": {
    "imageTag": "my-app:latest",
    "dockerfile": "Dockerfile.ci"  // Explicit override
  }
}
```

**Output:**
```
🎯 Using user-specified Dockerfile: Dockerfile.ci
```

## 🏗️ Build Context Examples

### **OpenShift Production Build**
```json
{
  "tool": "container_build_image",
  "arguments": {
    "imageTag": "quay.io/myorg/openshift-mcp:v1.0.0",
    "platform": "linux/amd64",
    "buildArgs": {
      "BUILDER_IMAGE": "registry.redhat.io/ubi9/go-toolset:latest",
      "BASE_IMAGE": "registry.redhat.io/rhel9-4-els/rhel-minimal:latest"
    }
  }
}
```
→ **Auto-selects**: `Dockerfile.ocp`

### **CI/CD Pipeline Build**
```json
{
  "tool": "container_build_image",
  "arguments": {
    "imageTag": "registry.ci.openshift.org/myorg/mcp:latest",
    "dockerfile": "Dockerfile.ci",
    "noCache": true,
    "platform": "linux/amd64"
  }
}
```
→ **Uses**: `Dockerfile.ci` (explicit)

### **Development Build**
```json
{
  "tool": "container_build_image",
  "arguments": {
    "imageTag": "localhost/mcp-dev:latest",
    "dockerfile": "Dockerfile"
  }
}
```
→ **Uses**: `Dockerfile` (explicit)

## 🔍 UBI Validation Integration

The `validate_base_image_ubi` tool also uses intelligent detection:

```json
{
  "tool": "validate_base_image_ubi",
  "arguments": {}
}
```

**Detection Logic:**
1. Checks `Dockerfile.ocp` first (most likely to have UBI)
2. Falls back to `Dockerfile.ci` 
3. Finally checks `Dockerfile`

**Expected Results:**
- **Dockerfile.ocp**: ✅ PASSED (Uses Red Hat UBI images)
- **Dockerfile.ci**: ✅ PASSED (Uses OpenShift CI UBI images) 
- **Dockerfile**: ⚠️ WARNING (May use non-UBI base images)

## 📊 Available Dockerfiles in Repository

Current repository contains:

| Dockerfile | Purpose | Base Image Type | UBI Compliant |
|------------|---------|----------------|---------------|
| `Dockerfile.ocp` | OpenShift Production | Red Hat UBI | ✅ Yes |
| `Dockerfile.ci` | CI/CD Pipeline | OpenShift CI UBI | ✅ Yes |  
| `Dockerfile` | Development/General | Mixed | ⚠️ Partial |

## 🎛️ Configuration Options

### **Environment Variables**

Control detection behavior with environment variables:

```bash
# Force a specific Dockerfile
export DOCKERFILE_OVERRIDE="Dockerfile.ci"

# Disable auto-detection (use explicit paths only)
export DISABLE_DOCKERFILE_DETECTION="true"
```

### **Build Arguments**

Customize builds with appropriate build arguments:

```json
{
  "tool": "container_build_image",
  "arguments": {
    "imageTag": "my-app:latest",
    "buildArgs": {
      "BUILDER_IMAGE": "registry.redhat.io/ubi9/go-toolset:1.24.4",
      "BASE_IMAGE": "registry.redhat.io/ubi9/ubi-minimal:latest",
      "TARGETOS": "linux",
      "TARGETARCH": "amd64"
    }
  }
}
```

## 🚀 Best Practices

### **For OpenShift Deployments**
1. ✅ **Use auto-detection** - Let the system choose `Dockerfile.ocp`
2. ✅ **Validate UBI compliance** - Run `validate_base_image_ubi` 
3. ✅ **Set appropriate build args** - Use Red Hat registry images
4. ✅ **Target correct platform** - Specify `linux/amd64` or `linux/arm64`

### **For CI/CD Pipelines**
1. ✅ **Explicit Dockerfile selection** - Use `"dockerfile": "Dockerfile.ci"`
2. ✅ **Enable no-cache builds** - Use `"noCache": true`
3. ✅ **Multi-platform builds** - Specify target platforms
4. ✅ **Enterprise compliance** - Use OpenShift CI registry images

### **For Development**
1. ✅ **Use standard Dockerfile** - Override with `"dockerfile": "Dockerfile"`
2. ✅ **Enable caching** - Omit `noCache` for faster builds
3. ✅ **Local registry tags** - Use `localhost/` or local registry
4. ✅ **Quick iterations** - Use smaller base images when possible

## 🔧 Troubleshooting

### **"No Dockerfile found"**
```bash
# Check available Dockerfiles
ls -la Dockerfile*

# Verify build context
ls -la ./
```

### **"Wrong Dockerfile selected"**
```json
{
  "dockerfile": "Dockerfile.ci"  // Explicit override
}
```

### **"Build arguments not working"**
- Ensure Dockerfile supports the build arguments
- Check ARG declarations in the Dockerfile
- Verify argument names match exactly

### **"UBI validation fails"**
- Check if using the correct Dockerfile (should be `.ocp` or `.ci`)
- Verify base image registry URLs
- Ensure UBI images are specified correctly

## 📚 Integration Examples

### **With OpenShift Builds**
```yaml
apiVersion: build.openshift.io/v1
kind: BuildConfig
metadata:
  name: mcp-server
spec:
  source:
    type: Git
    git:
      uri: https://github.com/openshift/openshift-mcp-server
  strategy:
    type: Docker
    dockerStrategy:
      dockerfilePath: Dockerfile.ocp  # Explicit OpenShift Dockerfile
```

### **With Tekton Pipelines**
```yaml
apiVersion: tekton.dev/v1beta1
kind: Task
metadata:
  name: build-mcp-server
spec:
  steps:
  - name: build
    image: registry.redhat.io/ubi9/buildah
    script: |
      # Auto-detection will choose Dockerfile.ocp
      buildah build -t $(params.IMAGE_NAME) .
```

---

**The MCP server now intelligently selects the best Dockerfile for your OpenShift and enterprise container builds!** 🚀
