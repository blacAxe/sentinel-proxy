# **Sentinel Go Security Proxy and Self Healer WAF**

## **Category**
Security Engineering

A lightweight security gateway built in Go to protect web applications. 
It sits between the user and the backend and filters requests before they reach the server.

## **Architecture**

* **Sentinel Proxy** in Go handles incoming traffic
* **Rule engine** inspects requests for malicious patterns
* **LumenLog Bridge** exports security events to external pipelines
* **Target App** is a Node application running locally or on Render

## **Core Features**

* **Reverse proxy** built with native Go HTTP tools
* **Rule based detection** for SQL injection and XSS patterns
* **Rate limiting** per IP to prevent abuse
* **Real time request logging** in terminal and dashboard
* **Self healing** process monitor for local apps

## **Latest Update: Unified Security Pipeline**

This update moves Sentinel from a standalone proxy to a core producer in a distributed observability platform.

* **LumenLog Integration:** Added a dedicated event sender to bridge logs to the LumenLog Ingestor
* **Structured Event Export:** Every block or allow event is now serialized and shipped via HTTP to a central collector
* **Distributed Tracing:** Every request produces a unique Request ID that persists from the WAF to the database
* **Real-time Alerting:** Integrated with external services to trigger instant security notifications

## **Event Flow**

Sentinel now acts as a central event producer for the entire security stack:

1. Request comes in  
2. Request is inspected by WAF and rate limiter
3. Structured event is created with unique ID
4. Event is used for local dashboard and SQLite storage
5. **Event is bridged to LumenLog Ingestor (Redpanda + ClickHouse)**

## **Example Output**

ALLOW ip equals local path slash proxy query empty

BLOCKED ip equals local rule SQLi UNION path slash proxy query id equals one union test

**[BRIDGE] Sentinel Event Pushed to LumenLog**

## **Dashboard**

The dashboard shows a live view of what the proxy is doing:

* total requests
* allowed vs blocked traffic
* block rate percentage
* top attack pattern
* top IP sending requests
* live request log stream

## **How to Run**

1. go mod tidy  
2. go run main.go  
3. open http localhost 8080

## **Tech Stack**

* **Go** (Net/HTTP, Reverse Proxy)
* **SQLite** (Local Persistence)
* **Protobuf/JSON** (Event Serialization)
* **LumenLog Bridge** (External Ingestion)

## **Notes**

This project demonstrates the transition from a simple local WAF to a distributed security engineering platform. By bridging events to external brokers like Redpanda, Sentinel now supports long-term analytics and professional security operations.