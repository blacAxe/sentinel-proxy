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
)

var logChan = make(chan string)

var (
	proxy       *httputil.ReverseProxy
	origin      *url.URL
	targetMutex sync.Mutex
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
	proxy = httputil.NewSingleHostReverseProxy(origin)

	// Re-apply the Director logic to the new proxy
	proxy.Director = func(req *http.Request) {
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
	case logChan <- msg:
	default:
	}
}

// This function checks if a request contains forbidden patterns
func isMalicious(query string) bool {
	query = strings.ToLower(query)

	// Right now only blocking the word banana to test the proxy
	// Can add more patterns here like "or 1=1" or "<script>"
	if strings.Contains(query, "banana") {
		return true
	}
	return false
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
	// Initialize the Global Proxy with a default target
	defaultTarget := "https://self-healing-security-lab.onrender.com"
	var err error
	origin, err = url.Parse(defaultTarget)
	if err != nil {
		log.Fatal("Invalid default target URL")
	}

	proxy = httputil.NewSingleHostReverseProxy(origin)

	// Define the director logic ONCE here for the global proxy
	proxy.Director = func(r *http.Request) {
		targetMutex.Lock()
		r.Header.Add("X-Forwarded-Host", r.Host)
		r.URL.Scheme = origin.Scheme
		r.URL.Host = origin.Host
		r.Host = origin.Host
		targetMutex.Unlock()

		// "Don't remember the old site!"
		r.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
	}

	// This tells Go to serve index.html from the /static folder
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/dashboard/", http.StripPrefix("/dashboard/", fs))

	// This is the "Log Pipe". The UI connects to this to get real-time updates.
	http.HandleFunc("/logs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		for msg := range logChan {
			fmt.Fprintf(w, "data: %s\n\n", msg)
			w.(http.Flusher).Flush()
		}
	})

	http.HandleFunc("/update-target", updateTargetHandler)

	// Main request handler
	// This handler will catch EVERYTHING that isn't /dashboard or /logs
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path == "/" {
            // Use a temporary redirect (Found) and set no-cache
            w.Header().Set("Cache-Control", "no-cache")
            http.Redirect(w, r, "/proxy/", http.StatusTemporaryRedirect)
            return
        }

		// Security Check (Logs only the main page or malicious attempts)
		if r.URL.Path == "/proxy/" || isMalicious(r.URL.RawQuery) {
			logToSentinel(fmt.Sprintf("[SENTINEL] Request for: %s", r.URL.Path))
		}

		if isMalicious(r.URL.RawQuery) {
			logToSentinel("[BLOCK] Malicious pattern detected!")
			http.Error(w, "SENTINEL BLOCK", http.StatusForbidden)
			return
		}

		// The Path Fix:
		// If the browser asks for /proxy/css/style.css, strip /proxy and send /css/style.css to Render
		if strings.HasPrefix(r.URL.Path, "/proxy/") {
			r.URL.Path = strings.TrimPrefix(r.URL.Path, "/proxy")
		}

		// Serve the request
		proxy.ServeHTTP(w, r)
	})

	logToSentinel("Sentinel Proxy is shielding: " + defaultTarget)
	logToSentinel("Local access: http://localhost:8080")

	// Start server
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Printf("Could not start proxy: %v\n", err)
	}
}
