package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

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
	// To use the healer locally, uncomment the line below
	// go startAndMonitorApp("C:/Users/.../App/app.js")

	// Target URL for the cloud app
	targetApp := "https://your-url.com"
	origin, _ := url.Parse(targetApp)

	// Set up the reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(origin)

	// Rewrites the host header so Render accepts the connection
	oldDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		oldDirector(r)
		r.Host = origin.Host
	}

	// Main request handler
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("[SENTINEL] Request for Path: %s\n", r.URL.Path)

		// Use helper function to check for bad stuff in the query
		if isMalicious(r.URL.RawQuery) {
			fmt.Println("[SENTINEL] Blocked a request based on security rules")
			http.Error(w, "SENTINEL BLOCK: The custom proxy caught this!", http.StatusForbidden)
			return
		}

		// If everything is okay, pass the request to Render
		proxy.ServeHTTP(w, r)
	})

	fmt.Println("Sentinel Proxy is shielding: " + targetApp)
	fmt.Println("Local access: http://localhost:8080")

	// Start the server
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Printf("Could not start proxy: %v\n", err)
	}
}
