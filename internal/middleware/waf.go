package middleware

import (
	"net"
	"net/http"
	"strings"

	"github.com/omar/sentinel-proxy/internal/logger"
	"github.com/omar/sentinel-proxy/internal/rules"
	"github.com/omar/sentinel-proxy/internal/metrics"
	"github.com/omar/sentinel-proxy/internal/services"
)

func WAF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.RawQuery

		ip := r.Header.Get("X-Forwarded-For")
		if ip == "" {
			ip, _, _ = net.SplitHostPort(r.RemoteAddr)
		}

		metrics.IncIP(ip)
		metrics.IncTotal()
		metrics.IncTimeline()
		
		if strings.Contains(r.URL.Path, ".css") ||
			strings.Contains(r.URL.Path, ".js") ||
			strings.Contains(r.URL.Path, "favicon") {
			next.ServeHTTP(w, r)
			return
		}

		blocked, reason := rules.IsMalicious(query)

		if blocked {
			logger.Log(logger.LogEntry{
				IP:     ip,
				Path:   r.URL.Path,
				Query:  query,
				Action: "BLOCK",
				Reason: reason,
			})

			http.Error(w, "Blocked by Sentinel", http.StatusForbidden)
			metrics.IncBlocked()
			metrics.IncAttack(reason)
			return
		}

		logger.Log(logger.LogEntry{
			IP:     ip,
			Path:   r.URL.Path,
			Query:  query,
			Action: "ALLOW",
		})

		metrics.IncAllowed()
		services.CheckAlerts()

		next.ServeHTTP(w, r)
	})
}