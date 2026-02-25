package main

import (
        "database/sql"
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
        "time"

        _ "github.com/lib/pq"
)

type Registry struct {
        db       *sql.DB
        mu       sync.Mutex
        cache    map[string]int
}

func NewRegistry(db *sql.DB) (*Registry, error) {
        r := &Registry{
                db:    db,
                cache: make(map[string]int),
        }
        if err := r.loadFromDB(); err != nil {
                return nil, fmt.Errorf("failed to load existing names: %w", err)
        }
        return r, nil
}

func (r *Registry) loadFromDB() error {
        rows, err := r.db.Query("SELECT name, port FROM claimed_names ORDER BY id")
        if err != nil {
                return err
        }
        defer rows.Close()

        for rows.Next() {
                var name string
                var port int
                if err := rows.Scan(&name, &port); err != nil {
                        return err
                }
                r.cache[name] = port
        }
        log.Printf("Loaded %d existing name(s) from database", len(r.cache))
        return rows.Err()
}

func (r *Registry) IsAvailable(name string) (bool, error) {
        var count int
        err := r.db.QueryRow("SELECT COUNT(*) FROM claimed_names WHERE name = $1", name).Scan(&count)
        if err != nil {
                return false, err
        }
        return count == 0, nil
}

func (r *Registry) Claim(name string) (int, error) {
        r.mu.Lock()
        defer r.mu.Unlock()

        var count int
        err := r.db.QueryRow("SELECT COUNT(*) FROM claimed_names WHERE name = $1", name).Scan(&count)
        if err != nil {
                return 0, fmt.Errorf("db check failed: %w", err)
        }
        if count > 0 {
                return 0, nil
        }

        port := r.findFreePort()

        _, err = r.db.Exec(
                "INSERT INTO claimed_names (name, port) VALUES ($1, $2)",
                name, port,
        )
        if err != nil {
                return 0, fmt.Errorf("db insert failed: %w", err)
        }

        r.cache[name] = port
        return port, nil
}

func (r *Registry) GetAll() map[string]int {
        r.mu.Lock()
        defer r.mu.Unlock()
        result := make(map[string]int)
        for k, v := range r.cache {
                result[k] = v
        }
        return result
}

func (r *Registry) findFreePort() int {
        maxPort := 10042
        for _, p := range r.cache {
                if p >= maxPort {
                        maxPort = p + 1
                }
        }
        for port := maxPort; ; port++ {
                ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
                if err == nil {
                        ln.Close()
                        return port
                }
        }
}

type RateLimiter struct {
        mu       sync.Mutex
        visitors map[string]*visitor
}

type visitor struct {
        tokens    float64
        lastSeen  time.Time
}

func NewRateLimiter() *RateLimiter {
        rl := &RateLimiter{
                visitors: make(map[string]*visitor),
        }
        go rl.cleanup()
        return rl
}

func (rl *RateLimiter) Allow(ip string, maxTokens float64, refillRate float64) bool {
        rl.mu.Lock()
        defer rl.mu.Unlock()

        v, exists := rl.visitors[ip]
        now := time.Now()

        if !exists {
                rl.visitors[ip] = &visitor{tokens: maxTokens - 1, lastSeen: now}
                return true
        }

        elapsed := now.Sub(v.lastSeen).Seconds()
        v.tokens += elapsed * refillRate
        if v.tokens > maxTokens {
                v.tokens = maxTokens
        }
        v.lastSeen = now

        if v.tokens < 1 {
                return false
        }
        v.tokens--
        return true
}

func (rl *RateLimiter) cleanup() {
        for {
                time.Sleep(5 * time.Minute)
                rl.mu.Lock()
                for ip, v := range rl.visitors {
                        if time.Since(v.lastSeen) > 10*time.Minute {
                                delete(rl.visitors, ip)
                        }
                }
                rl.mu.Unlock()
        }
}

func getClientIP(r *http.Request) string {
        if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
                parts := strings.Split(forwarded, ",")
                return strings.TrimSpace(parts[0])
        }
        if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
                return realIP
        }
        host, _, _ := net.SplitHostPort(r.RemoteAddr)
        return host
}

var namePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$`)

var caddyfileTmpl = template.Must(template.New("caddyfile").Parse(`{
        auto_https off
        admin localhost:2019
}

:5000 {
        handle_path /tunnel/* {
                reverse_proxy localhost:8080 {
                        header_up X-Forwarded-Proto {http.request.scheme}
                }
        }
        handle /tunnel {
                reverse_proxy localhost:8080 {
                        header_up X-Forwarded-Proto {http.request.scheme}
                }
        }

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
        dbURL := os.Getenv("DATABASE_URL")
        if dbURL == "" {
                log.Fatal("DATABASE_URL environment variable is not set")
        }

        db, err := sql.Open("postgres", dbURL)
        if err != nil {
                log.Fatalf("Failed to connect to database: %v", err)
        }
        defer db.Close()

        db.SetMaxOpenConns(25)
        db.SetMaxIdleConns(5)
        db.SetConnMaxLifetime(5 * time.Minute)

        if err := db.Ping(); err != nil {
                log.Fatalf("Failed to ping database: %v", err)
        }
        log.Println("Connected to PostgreSQL database")

        _, err = db.Exec(`
                CREATE TABLE IF NOT EXISTS claimed_names (
                        id SERIAL PRIMARY KEY,
                        name VARCHAR(63) UNIQUE NOT NULL,
                        port INTEGER NOT NULL,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                )
        `)
        if err != nil {
                log.Fatalf("Failed to ensure schema: %v", err)
        }

        registry, err := NewRegistry(db)
        if err != nil {
                log.Fatalf("Failed to initialize registry: %v", err)
        }

        if err := generateCaddyfile(registry.GetAll()); err != nil {
                log.Fatalf("Failed to generate initial Caddyfile: %v", err)
        }
        log.Println("Initial Caddyfile generated with persisted routes")

        limiter := NewRateLimiter()
        mux := http.NewServeMux()

        mux.HandleFunc("/check-name", func(w http.ResponseWriter, r *http.Request) {
                w.Header().Set("Content-Type", "application/json")

                ip := getClientIP(r)
                if !limiter.Allow(ip, 30, 5) {
                        w.WriteHeader(http.StatusTooManyRequests)
                        json.NewEncoder(w).Encode(map[string]string{"error": "rate limit exceeded, try again shortly"})
                        return
                }

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

                available, err := registry.IsAvailable(name)
                if err != nil {
                        log.Printf("DB error checking name '%s': %v", name, err)
                        w.WriteHeader(http.StatusInternalServerError)
                        json.NewEncoder(w).Encode(map[string]string{"error": "internal error"})
                        return
                }
                json.NewEncoder(w).Encode(map[string]bool{"available": available})
        })

        mux.HandleFunc("/claim-name", func(w http.ResponseWriter, r *http.Request) {
                w.Header().Set("Content-Type", "application/json")

                ip := getClientIP(r)
                if !limiter.Allow(ip, 10, 1) {
                        w.WriteHeader(http.StatusTooManyRequests)
                        json.NewEncoder(w).Encode(map[string]string{"error": "rate limit exceeded, try again shortly"})
                        return
                }

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

                port, err := registry.Claim(req.Name)
                if err != nil {
                        log.Printf("DB error claiming name '%s': %v", req.Name, err)
                        w.WriteHeader(http.StatusInternalServerError)
                        json.NewEncoder(w).Encode(map[string]string{"error": "internal error"})
                        return
                }
                if port == 0 {
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
                        "name":        req.Name,
                        "port":        port,
                        "tunnel_path": "/tunnel",
                        "message":     fmt.Sprintf("Name '%s' claimed. Connect chisel client to the server's /tunnel path with remote R:%d:<local-addr>. Traffic at /%s/* will be forwarded.", req.Name, port, req.Name),
                })
        })

        mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
                w.Header().Set("Content-Type", "application/json")

                ip := getClientIP(r)
                if !limiter.Allow(ip, 30, 5) {
                        w.WriteHeader(http.StatusTooManyRequests)
                        json.NewEncoder(w).Encode(map[string]string{"error": "rate limit exceeded, try again shortly"})
                        return
                }

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
