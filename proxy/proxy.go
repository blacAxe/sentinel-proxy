package proxy

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/omar/sentinel-proxy/logger"
	"github.com/omar/sentinel-proxy/rules"
)

var requestCounts = make(map[string]int)

func WAFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		query := r.URL.RawQuery

		blocked, reason := rules.IsMalicious(query)

		ip := r.Header.Get("X-Forwarded-For")

		if ip == "" {
			var err error
			ip, _, err = net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				ip = r.RemoteAddr // fallback
			}
		}

		if strings.Contains(r.URL.Path, ".css") ||
			strings.Contains(r.URL.Path, ".js") ||
			strings.Contains(r.URL.Path, "favicon") {
			next.ServeHTTP(w, r)
			return
		}

		requestCounts[ip]++

		if requestCounts[ip] > 10 {
			fmt.Printf("[BLOCKED] ip=%s reason=RATE_LIMIT\n", ip)
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}

		if blocked {
			fmt.Printf("[BLOCKED] ip=%s rule=%s path=%s query=%s\n", ip, reason, r.URL.Path, query)
			logger.Log("BLOCK: " + reason + " | " + query)
			http.Error(w, "Blocked by Sentinel", http.StatusForbidden)
			return
		}

		fmt.Printf("[ALLOW] ip=%s path=%s query=%s\n", ip, r.URL.Path, query)
		logger.Log("ALLOW: " + query)

		next.ServeHTTP(w, r)
	})
}

func init() {
	go func() {
		for {
			time.Sleep(10 * time.Second)
			requestCounts = make(map[string]int)
		}
	}()
}
