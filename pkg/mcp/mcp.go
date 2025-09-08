package mcp

import (
	"github.com/containers/kubernetes-mcp-server/pkg/output"
	kubernetes "github.com/containers/kubernetes-mcp-server/pkg/kubernetes"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"slices"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"k8s.io/klog/v2"
	"github.com/containers/kubernetes-mcp-server/pkg/config"
	authenticationapiv1 "k8s.io/api/authentication/v1"
)

// NewServer constructs a new MCP Server instance
func NewServer(cfg Configuration) (*Server, error) {
	// Initialize Kubernetes manager
	manager, err := kubernetes.NewManager(cfg.StaticConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes manager: %w", err)
	}
	
	// Create a Kubernetes client instance from the manager
	k, err := manager.Derived(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %w", err)
	}
	
	return &Server{
		configuration: &cfg,
		enabledTools: []string{"validateBaseImageUBI", "buildContainerImage", "pushContainerImage"},
		k: k, // Initialize Kubernetes client
	}, nil
}
	// Stub for validateBaseImageUBI tool handler
	func (s *Server) validateBaseImageUBI(ctx context.Context, ctr mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return NewTextResult("validateBaseImageUBI stub executed", nil), nil
	}

	// Stub for buildContainerImage tool handler
	func (s *Server) buildContainerImage(ctx context.Context, ctr mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return NewTextResult("buildContainerImage stub executed", nil), nil
	}

	// Stub for pushContainerImage tool handler
	func (s *Server) pushContainerImage(ctx context.Context, ctr mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return NewTextResult("pushContainerImage stub executed", nil), nil
	}

type ContextKey string

const TokenScopesContextKey = ContextKey("TokenScopesContextKey")

type Configuration struct {
	Profile    Profile
	ListOutput output.Output
	StaticConfig *config.StaticConfig
}

type Server struct {
	// k is the Kubernetes client manager
	k *kubernetes.Kubernetes
	enabledTools []string
	configuration *Configuration
}

// ServeStdio stub implementation
func (s *Server) ServeStdio() error {
	// TODO: Implement actual stdio serving logic
	return nil
}

// Implements KubernetesApiTokenVerifier
func (s *Server) KubernetesApiVerifyToken(ctx context.Context, token, audience string) (*authenticationapiv1.UserInfo, []string, error) {
	// TODO: Implement actual token verification logic
	return &authenticationapiv1.UserInfo{}, nil, nil
}

// ServeSse returns an http.Handler for SSE endpoint
func (s *Server) ServeSse(baseURL string, httpServer *http.Server) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotImplemented)
		_, _ = w.Write([]byte("SSE not implemented"))
	})
}

// ServeHTTP returns an http.Handler for streaming endpoint
func (s *Server) ServeHTTP(httpServer *http.Server) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		
		w.Header().Set("Content-Type", "application/json")
		
		// Create the underlying MCP server and handle the request
		mcpServer := server.NewMCPServer("kubernetes-mcp-server", "1.0.0")
		s.setupMCPServer(mcpServer)
		
		// Use the server's built-in HTTP handler
		streamableServer := server.NewStreamableHTTPServer(mcpServer)
		streamableServer.ServeHTTP(w, r)
	})
}

// setupMCPServer configures the MCP server with all tools
func (s *Server) setupMCPServer(mcpServer *server.MCPServer) {
	// Get the profile to access all original tools
	profile := ProfileFromString("full")
	if profile != nil {
		// Add all tools from the profile (this includes all original 19+ tools)
		allTools := profile.GetTools(s)
		mcpServer.AddTools(allTools...)
	} else {
		// Fallback: manually add the new tools if profile is not found
		// Add validateBaseImageUBI tool
		validateUBITool := mcp.Tool{
			Name:        "validateBaseImageUBI",
			Description: "Validates if the base image used for container build is Red Hat provided universal base image",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]interface{}{
					"image": map[string]interface{}{
						"type":        "string",
						"description": "Container image name to validate",
					},
				},
				Required: []string{"image"},
			},
		}
		mcpServer.AddTool(validateUBITool, s.validateBaseImageUBI)

		// Add buildContainerImage tool
		buildTool := mcp.Tool{
			Name:        "buildContainerImage",
			Description: "Builds a container image using provided Dockerfile",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]interface{}{
					"dockerfile": map[string]interface{}{
						"type":        "string",
						"description": "Path to Dockerfile",
					},
					"context": map[string]interface{}{
						"type":        "string",
						"description": "Build context directory",
					},
					"tag": map[string]interface{}{
						"type":        "string",
						"description": "Image tag",
					},
				},
				Required: []string{"dockerfile", "context", "tag"},
			},
		}
		mcpServer.AddTool(buildTool, s.buildContainerImage)

		// Add pushContainerImage tool
		pushTool := mcp.Tool{
			Name:        "pushContainerImage",
			Description: "Pushes a container image to a registry",
			InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"image": map[string]interface{}{
					"type":        "string",
					"description": "Image name with tag to push",
				},
				"registry": map[string]interface{}{
					"type":        "string",
					"description": "Registry URL",
				},
			},
			Required: []string{"image"},
		},
		}
		mcpServer.AddTool(pushTool, s.pushContainerImage)
	}
}



// GetKubernetesAPIServerHost returns the Kubernetes API server host from the configuration.
func (s *Server) GetKubernetesAPIServerHost() string {
       if s.k == nil {
	       return ""
       }
       return s.k.GetAPIServerHost()
}

func (s *Server) GetEnabledTools() []string {
	return s.enabledTools
}

func (s *Server) Close() {
       if s.k != nil {
	       s.k.Close()
       }
}

func NewTextResult(content string, err error) *mcp.CallToolResult {
	if err != nil {
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{
				mcp.TextContent{
					Type: "text",
					Text: err.Error(),
				},
			},
		}
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{
				Type: "text",
				Text: content,
			},
		},
	}
}

func contextFunc(ctx context.Context, r *http.Request) context.Context {
	// Get the standard Authorization header (OAuth compliant)
       authHeader := r.Header.Get(string(kubernetes.OAuthAuthorizationHeader))
	if authHeader != "" {
	       return context.WithValue(ctx, kubernetes.OAuthAuthorizationHeader, authHeader)
	}

	// Fallback to custom header for backward compatibility
       customAuthHeader := r.Header.Get(string(kubernetes.CustomAuthorizationHeader))
	if customAuthHeader != "" {
	       return context.WithValue(ctx, kubernetes.OAuthAuthorizationHeader, customAuthHeader)
	}

	return ctx
}

func toolCallLoggingMiddleware(next server.ToolHandlerFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, ctr mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		klog.V(5).Infof("mcp tool call: %s(%v)", ctr.Params.Name, ctr.Params.Arguments)
		if ctr.Header != nil {
			buffer := bytes.NewBuffer(make([]byte, 0))
			if err := ctr.Header.WriteSubset(buffer, map[string]bool{"Authorization": true, "authorization": true}); err == nil {
				klog.V(7).Infof("mcp tool call headers: %s", buffer)
			}
		}
		return next(ctx, ctr)
	}
}

func toolScopedAuthorizationMiddleware(next server.ToolHandlerFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, ctr mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		scopes, ok := ctx.Value(TokenScopesContextKey).([]string)
		if !ok {
			return NewTextResult("", fmt.Errorf("authorization failed: Access denied: Tool '%s' requires scope 'mcp:%s' but no scope is available", ctr.Params.Name, ctr.Params.Name)), nil
		}
		if !slices.Contains(scopes, "mcp:"+ctr.Params.Name) && !slices.Contains(scopes, ctr.Params.Name) {
			return NewTextResult("", fmt.Errorf("authorization failed: Access denied: Tool '%s' requires scope 'mcp:%s' but only scopes %s are available", ctr.Params.Name, ctr.Params.Name, scopes)), nil
		}
		return next(ctx, ctr)
	}
}
