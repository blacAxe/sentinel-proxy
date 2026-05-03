package proxy

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/omar/sentinel-proxy/internal/logger"
	"github.com/omar/sentinel-proxy/internal/rules"
)

type Client struct {
	Requests []int64
}

var clients = make(map[string]*Client)

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

		now := time.Now().Unix()

		client, exists := clients[ip]
		if !exists {
			client = &Client{}
			clients[ip] = client
		}

		// keep only last 10 seconds
		var validRequests []int64
		for _, t := range client.Requests {
			if now-t < 10 {
				validRequests = append(validRequests, t)
			}
		}

		if blocked {
			fmt.Printf("[BLOCKED] ip=%s rule=%s path=%s query=%s\n", ip, reason, r.URL.Path, query)
			logger.Log(logger.LogEntry{
				IP:     ip,
				Path:   r.URL.Path,
				Query:  query,
				Action: "BLOCK",
				Reason: reason,
			})
			http.Error(w, "Blocked by Sentinel", http.StatusForbidden)
			return
		}

		fmt.Printf("[ALLOW] ip=%s path=%s query=%s\n", ip, r.URL.Path, query)
		logger.Log(logger.LogEntry{
			IP:     ip,
			Path:   r.URL.Path,
			Query:  query,
			Action: "ALLOW",
			Reason: reason,
		})

		next.ServeHTTP(w, r)
	})
}
