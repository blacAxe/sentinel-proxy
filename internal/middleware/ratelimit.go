package middleware

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/omar/sentinel-proxy/internal/logger"
)

type Client struct {
	Requests []int64
}

var clients = make(map[string]*Client)

func RateLimiter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if strings.HasPrefix(r.URL.Path, "/stats") ||
			strings.HasPrefix(r.URL.Path, "/logs") ||
			strings.HasPrefix(r.URL.Path, "/dashboard") {
			next.ServeHTTP(w, r)
			return
		}

		ip := r.Header.Get("X-Forwarded-For")
		if ip == "" {
			ip, _, _ = net.SplitHostPort(r.RemoteAddr)
		}

		now := time.Now().Unix()

		client, exists := clients[ip]
		if !exists {
			client = &Client{}
			clients[ip] = client
		}

		var valid []int64
		for _, t := range client.Requests {
			if now-t < 10 {
				valid = append(valid, t)
			}
		}

		client.Requests = append(valid, now)

		if len(client.Requests) > 10 {
			logger.Log(logger.LogEntry{
				IP:     ip,
				Path:   r.URL.Path,
				Query:  r.URL.RawQuery,
				Action: "BLOCK",
				Reason: "RATE_LIMIT",
			})

			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}