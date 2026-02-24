package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"text/template"
)

type NameEntry struct {
	Name string `json:"name"`
	Port int    `json:"port"`
}

type Registry struct {
	mu      sync.RWMutex
	names   map[string]int
	nextPort int
}

func NewRegistry() *Registry {
	return &Registry{
		names:    make(map[string]int),
		nextPort: 10042,
	}
}

func (r *Registry) IsAvailable(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, exists := r.names[name]
	return !exists
}

func (r *Registry) Claim(name string) (int, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.names[name]; exists {
		return 0, false
	}
	port := r.findFreePort()
	r.names[name] = port
	return port, true
}

func (r *Registry) GetAll() map[string]int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make(map[string]int)
	for k, v := range r.names {
		result[k] = v
	}
	return result
}

func (r *Registry) findFreePort() int {
	for {
		port := r.nextPort
		r.nextPort++
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err == nil {
			ln.Close()
			return port
		}
	}
}

var namePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$`)

var caddyfileTmpl = template.Must(template.New("caddyfile").Parse(`{
	auto_https off
	admin localhost:2019
}

:5000 {
	{{- range $name, $port := .Routes }}
	handle_path /{{ $name }}/* {
		reverse_proxy localhost:{{ $port }}
	}
	{{- end }}

	handle /check-name {
		reverse_proxy localhost:3000
	}
	handle /claim-name {
		reverse_proxy localhost:3000
	}
	handle /status {
		reverse_proxy localhost:3000
	}

	handle {
		respond "Tunneling Hub is running. Use /check-name?name=xxx or POST /claim-name to get started." 200
	}
}
`))

func generateCaddyfile(routes map[string]int) error {
	f, err := os.Create("Caddyfile")
	if err != nil {
		return fmt.Errorf("failed to create Caddyfile: %w", err)
	}
	defer f.Close()

	data := struct {
		Routes map[string]int
	}{
		Routes: routes,
	}
	return caddyfileTmpl.Execute(f, data)
}

func reloadCaddy() error {
	cmd := exec.Command("./bin/caddy", "reload", "--config", "Caddyfile")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("caddy reload failed: %s: %w", string(output), err)
	}
	log.Println("Caddy config reloaded successfully")
	return nil
}

func main() {
	registry := NewRegistry()

	if err := generateCaddyfile(registry.GetAll()); err != nil {
		log.Fatalf("Failed to generate initial Caddyfile: %v", err)
	}
	log.Println("Initial Caddyfile generated")

	mux := http.NewServeMux()

	mux.HandleFunc("/check-name", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		name := r.URL.Query().Get("name")
		if name == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "name parameter is required"})
			return
		}

		name = strings.ToLower(name)
		if !namePattern.MatchString(name) {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "name must be alphanumeric (hyphens and underscores allowed), 1-63 chars"})
			return
		}

		available := registry.IsAvailable(name)
		json.NewEncoder(w).Encode(map[string]bool{"available": available})
	})

	mux.HandleFunc("/claim-name", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(map[string]string{"error": "POST method required"})
			return
		}

		var req struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON body"})
			return
		}

		req.Name = strings.ToLower(req.Name)
		if req.Name == "" || !namePattern.MatchString(req.Name) {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "name must be alphanumeric (hyphens and underscores allowed), 1-63 chars"})
			return
		}

		port, ok := registry.Claim(req.Name)
		if !ok {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"available": false,
				"error":     "name is already taken",
			})
			return
		}

		if err := generateCaddyfile(registry.GetAll()); err != nil {
			log.Printf("Failed to regenerate Caddyfile: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "failed to update routing config"})
			return
		}

		if err := reloadCaddy(); err != nil {
			log.Printf("Failed to reload Caddy: %v", err)
		}

		log.Printf("Claimed name '%s' on port %d", req.Name, port)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"name":    req.Name,
			"port":    port,
			"message": fmt.Sprintf("Name '%s' claimed. Connect chisel reverse tunnel to port %d. Traffic at /%s/* will be forwarded.", req.Name, port, req.Name),
		})
	})

	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		routes := registry.GetAll()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"active_routes": routes,
			"count":         len(routes),
		})
	})

	log.Println("API server starting on :3000")
	if err := http.ListenAndServe("0.0.0.0:3000", mux); err != nil {
		log.Fatalf("API server failed: %v", err)
	}
}
