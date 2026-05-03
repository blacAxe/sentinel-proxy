# **Sentinel Go Security Proxy and Self Healer WAF**

## **Category**
Security Engineering

A lightweight security gateway built in Go to protect web applications. 
It sits between the user and the backend and filters requests before they reach the server.

## **Architecture**

* **Sentinel Proxy** in Go handles incoming traffic[cite: 8]
* **Rule engine** inspects requests for malicious patterns[cite: 8]
* **Zero Trust Middleware:** Validates JWT "Passkeys" from an Identity Provider (IdP)[cite: 8]
* **LumenLog Bridge** exports security events to external pipelines[cite: 8]
* **Target App** is a Node application running locally or on Render[cite: 8]

## **Core Features**

* **Reverse proxy** built with native Go HTTP tools[cite: 8]
* **Identity-Aware Protection:** Restricts sensitive routes (e.g., `/api/secret-data`) to authorized JWT holders only[cite: 8].
* **Rule based detection** for SQL injection and XSS patterns[cite: 8]
* **Rate limiting** per IP to prevent abuse[cite: 8]
* **JSON-Powered Dashboard:** Real-time metrics and logs streamed via SSE in structured JSON format[cite: 8].
* **Self healing** process monitor for local apps[cite: 8]

## **Latest Update: Zero Trust & Identity Integration**

Sentinel has evolved from a simple WAF to an Identity-Aware Proxy (IAP)[cite: 8].

* **IdP Integration:** Implemented JWT verification logic using secure signing keys to protect high-value API endpoints[cite: 8].
* **Enhanced JSON Logging:** Refactored the internal logger to produce structured JSON, enabling the dashboard to parse and display attack data dynamically[cite: 8].
* **LumenLog Bridge:** Every block or allow event is now serialized and shipped via HTTP to a central collector[cite: 8].

## **Event Flow**

Sentinel now acts as a central event producer for the entire security stack:

1. Request comes in[cite: 8] 
2. **Identity Check:** Middleware verifies JWT if the route is protected[cite: 8]
3. Request is inspected by WAF and rate limiter[cite: 8]
4. Structured event is created with unique ID[cite: 8]
5. **Event is bridged to LumenLog Ingestor (Redpanda + ClickHouse)**[cite: 8]

## **Example Output**

ALLOW | IP: ::1 | Query: /dashboard[cite: 8]

BLOCKED | SQLi UNION | IP: ::1 | Query: ?id=1 union select[cite: 8]

**[AUTH SUCCESS] Access granted to secure route**[cite: 8]

## **How to Run**

1. `go mod tidy`[cite: 8]
2. `go run cmd/sentinel/main.go`[cite: 8]
3. Open `http://localhost:8081/dashboard/`[cite: 8]

## **Tech Stack**

* **Go** (Net/HTTP, Reverse Proxy)[cite: 8]
* **JWT-Go** (Token Verification)[cite: 8]
* **SQLite** (Local Persistence)[cite: 8]
* **Protobuf/JSON** (Event Serialization)[cite: 8]