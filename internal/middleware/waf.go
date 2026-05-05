package middleware

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/omar/sentinel-proxy/internal/events"
	"github.com/omar/sentinel-proxy/internal/logger"
	"github.com/omar/sentinel-proxy/internal/metrics"
	"github.com/omar/sentinel-proxy/internal/rules"
	"github.com/omar/sentinel-proxy/internal/services"
)

func WAF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		requestID, _ := r.Context().Value(RequestIDKey).(string)

		w.Header().Set("X-Request-ID", requestID)

		decodedQuery, _ := url.QueryUnescape(r.URL.RawQuery)
		query := strings.ToLower(decodedQuery)

		ip := r.Header.Get("X-Forwarded-For")
		if ip == "" {
			ip, _, _ = net.SplitHostPort(r.RemoteAddr)
		}

		metrics.IncIP(ip)
		metrics.IncTotal()
		metrics.IncTimeline()

		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			next.ServeHTTP(w, r)
			return
		}

		if strings.Contains(r.URL.Path, ".css") ||
			strings.Contains(r.URL.Path, ".js") ||
			strings.Contains(r.URL.Path, "favicon") ||
			strings.HasPrefix(r.URL.Path, "/api/") { 
			next.ServeHTTP(w, r)
			return
		}

		blocked, reason := rules.EvaluateRequest(r, query)

		if blocked {
			event := events.SecurityEvent{
				EventType:      "request_inspected",
				RequestID: 		requestID,
				IP:             ip,
				Path:           r.URL.Path,
				Method:         r.Method,
				Query:          query,
				AttackDetected: true,
				AttackType:     reason,
				Action:         "blocked",
				Timestamp:      time.Now().Unix(),
			}

			logger.LogEvent(event)
			events.SendEvent(event)

			metrics.IncBlocked()
			metrics.IncAttack(reason)
			services.CheckAlerts()

			http.Error(w, "Blocked by Sentinel", http.StatusForbidden)
			return
		}

		// ONLY runs if NOT blocked
		event := events.SecurityEvent{
			EventType:      "request_inspected",
			RequestID: 		requestID,
			IP:             ip,
			Path:           r.URL.Path,
			Method:         r.Method,
			Query:          query,
			AttackDetected: false,
			AttackType:     "",
			Action:         "allowed",
			Timestamp:      time.Now().Unix(),
		}

		logger.LogEvent(event)
		events.SendEvent(event)

		metrics.IncAllowed()
		services.CheckAlerts()

		next.ServeHTTP(w, r)

	})
}
