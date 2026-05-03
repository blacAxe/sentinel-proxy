package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"encoding/json"

	// "github.com/omar/sentinel-proxy/proxy"
	"github.com/omar/sentinel-proxy/internal/db"
	"github.com/omar/sentinel-proxy/internal/logger"
	"github.com/omar/sentinel-proxy/internal/metrics"
	"github.com/omar/sentinel-proxy/internal/middleware"
	"github.com/omar/sentinel-proxy/internal/rules"
)

var (
	reverseProxy *httputil.ReverseProxy
	origin       *url.URL
	targetMutex  sync.Mutex
)

func updateTargetHandler(w http.ResponseWriter, r *http.Request) {
	newURL := r.URL.Query().Get("url")
	if newURL == "" {
		http.Error(w, "URL is required", http.StatusBadRequest)
		return
	}

	parsedURL, err := url.Parse(newURL)
	if err != nil {
		logToSentinel("[ERROR] Invalid URL provided")
		return
	}

	targetMutex.Lock()
	origin = parsedURL
	reverseProxy = httputil.NewSingleHostReverseProxy(origin)

	// Re-apply the Director logic to the new proxy
	reverseProxy.Director = func(req *http.Request) {
		req.Header.Add("X-Forwarded-Host", req.Host)
		req.URL.Scheme = origin.Scheme
		req.URL.Host = origin.Host
		req.Host = origin.Host
	}
	targetMutex.Unlock()

	logToSentinel("Now Shielding: " + newURL)
	w.WriteHeader(http.StatusOK)
}

// Helper to send log to both terminal and UI
func logToSentinel(msg string) {
	fmt.Println(msg)
	// This ensures that if the UI isn't open, the backend doesn't wait
	select {
	case logger.LogChan <- msg:
	default:
	}
}

// This function manages the health of app if running locally
func startAndMonitorApp(appPath string) {
	appFolder := filepath.Dir(appPath)

	for {
		fmt.Printf("[HEALER] Starting target application: %s\n", appPath)
		cmd := exec.Command("node", appPath)
		cmd.Dir = appFolder
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		err := cmd.Start()
		if err != nil {
			fmt.Printf("[ERROR] Failed to start app: %v\n", err)
			time.Sleep(5 * time.Second)
			continue
		}

		fmt.Printf("[HEALER] App started (PID: %d). Monitoring...\n", cmd.Process.Pid)
		err = cmd.Wait()
		fmt.Printf("[ALERT] App exited: %v. Restarting in 3s...\n", err)
		time.Sleep(3 * time.Second)
	}
}

func main() {

	os.MkdirAll("data", os.ModePerm)

	logChan := make(chan string, 100)

	logger.LogChan = logChan

	logger.Init()
	rules.LoadRules()
	db.Init()
	// Initialize the Global Proxy with a default target
	defaultTarget := "https://self-healing-security-lab.onrender.com"
	var err error
	origin, err = url.Parse(defaultTarget)
	if err != nil {
		log.Fatal("Invalid default target URL")
	}

	reverseProxy = httputil.NewSingleHostReverseProxy(origin)

	reverseProxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		if err != nil && err.Error() == "context canceled" {
			return // ignore browser cancel noise
		}

		log.Printf("[PROXY ERROR] %v\n", err)
		http.Error(w, "Proxy error", http.StatusBadGateway)
	}

	// Define the director logic ONCE here for the global proxy
	reverseProxy.Director = func(r *http.Request) {
		targetMutex.Lock()
		r.Header.Add("X-Forwarded-Host", r.Host)
		r.URL.Scheme = origin.Scheme
		r.URL.Host = origin.Host
		r.Host = origin.Host
		targetMutex.Unlock()

		// Don't remember the old site
		r.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
	}

	// ===== MIDDLEWARE CHAIN =====
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Allow dashboard + internal routes WITHOUT middleware
		if strings.HasPrefix(r.URL.Path, "/dashboard") ||
			strings.HasPrefix(r.URL.Path, "/logs") ||
			strings.HasPrefix(r.URL.Path, "/stats") {
			http.DefaultServeMux.ServeHTTP(w, r)
			return
		}

		// Apply middleware to everything else
		chain := middleware.Chain(middleware.RateLimiter, middleware.WAF)
		secured := chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reverseProxy.ServeHTTP(w, r)
		}))

		secured.ServeHTTP(w, r)
	})

	// ===== ROUTES =====

	// Dashboard UI
	http.Handle("/dashboard/", http.StripPrefix("/dashboard/", http.FileServer(http.Dir("./web/static"))))

	// Logs (SSE)
	http.HandleFunc("/logs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		for msg := range logger.LogChan {
			fmt.Fprintf(w, "data: %s\n\n", msg)
			w.(http.Flusher).Flush()
		}
	})

	// Metrics
	http.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		stats := metrics.GetStats()
		timeline := metrics.GetTimeline()

		topAttack, attackCount := metrics.GetTopAttack()
		topIP, ipCount := metrics.GetTopIP()

		response := map[string]interface{}{
			"total":        stats.Total,
			"allowed":      stats.Allowed,
			"blocked":      stats.Blocked,
			"top_attack":   topAttack,
			"attack_count": attackCount,
			"top_ip":       topIP,
			"ip_count":     ipCount,
			"timeline":     timeline,
		}

		json.NewEncoder(w).Encode(response)
	})

	// Start server
	logToSentinel("Sentinel Proxy is shielding: " + defaultTarget)
	logToSentinel("Local access: http://localhost:8080")

	log.Fatal(http.ListenAndServe(":8080", handler))
}
