# Geeks Tunnel: System Architecture & Deployment Guide

This document is a comprehensive guide to understanding the "Geeks Tunnel" VPN infrastructure. usage of this guide will allow you to replicate the entire stack on any Linux server (e.g., in Mumbai/Singapore) with full understanding of each component.

---

## 1. High-Level Architecture

The system is a **Hybrid VPN Control Plane** that combines modern Web Technologies with low-level Linux Kernel networking.

### **The "Brain" (Control Plane)**
*   **Frontend**: Vanilla HTML/JS + WebSocket (Real-time Dashboard).
*   **Backend API**: Python FastAPI (Async I/O).
*   **Database**: MySQL (Per-client state, usage logs, audit).
*   **Proxy**: Nginx (SSL Termination, Static File Serving).

### **The "Muscle" (Data Plane)**
*   **VPN Protocol**: WireGuard (Kernel Module).
*   **Networking**: UDP Port 51820.
*   **Routing**: Linux IP Forwarding + iptables NAT.

---

## 2. Component Details

### A. Frontend (The Dashboard)
*   **Location**: `/frontend/`
*   **Tech**: Plain HTML, CSS, JavaScript (No React/Vue build step required).
*   **Logic**:
    *   `index.html`: Main dashboard. Connects to `wss://domain.com/ws/stats` for live updates.
    *   `login.html`: Branded entry point.
*   **Key Behavior**:
    *   **Real-time Update**: Recalculates "Peak Bandwidth" every 3-10 seconds using deltas from the backend.
    *   **Launch Icon**: Visual flair for provisioning.

### B. Backend (The API)
*   **Location**: `/app/`
*   **Tech**: Python 3.10+, FastAPI, Uvicorn, Async SQLAlchemy.
*   **Critical Files**:
    *   `main.py`: The entry point. Manages the **Adaptive Polling Loop** (Fast 3s when you watch, Sleep 10s when away).
    *   `wg.py`: The wrapper around the `wg` Linux command. Parses output to JSON.
    *   `auth.py`: Handles Admin login using **Secure, Signed Cookies** (ItsDangerous) + **Bcrypt** hashing.
*   **Resource Usage**: Very low (~50MB RAM). Adaptive Polling ensures near 0% CPU when idle.

### C. Database (The Memory)
*   **Engine**: MySQL 8.0 (Containerized in `docker-compose.db.yml`).
*   **Schema (`database.py`)**:
    *   `users`: Stores `public_key`, `allowed_ip`, `total_rx`, `total_tx`, `status`.
    *   `admin`: Stores the hashed admin password.
*   **Why MySQL?**: Robustness against corruption compared to SQLite.
*   **Persistence**: Data is stored in `./data/mysql`. If this folder is deleted, all user history is lost (but WireGuard configs remain on disk).

---

## 3. Deployment Stack

The system runs on **Docker Compose** but acts as a "Host Network" logic controller.

### 1. Reverse Proxy (Nginx)
*   **File**: `nginx/Dockerfile`, `nginx/nginx-ssl.conf`.
*   **Role**:
    1.  Listens on Port 443 (HTTPS).
    2.  Serves `/frontend` files directly.
    3.  Proxies `/api` and `/ws` requests to Python Backend (Port 8000).
*   **SSL**: Uses **LetsEncrypt** certs mounted from the host (`/etc/letsencrypt`).

### 2. The WireGuard Interface
*   **Config**: `/etc/wireguard/wg0.conf` (On Host).
*   **Operation**: The Python Backend writes directly to this file and reloads the interface (`wg syncconf`).
*   **Networking**:
    *   User IPs: `10.50.0.X`
    *   Traffic is NAT-ed via `iptables -t nat -A POSTROUTING`.

---

## 4. Resource & Scalability Analysis

| Component | Resource Impact | Bottleneck | Scalability Limit |
| :--- | :--- | :--- | :--- |
| **WireGuard** | CPU (Encryption) | **CPU Speed** | ~1Gbps per Core |
| **Backend API** | CPU (Polling) | Polling Frequency | ~1000 Concurrent Admins (unlikely) |
| **Database** | Disk I/O | Disk Speed | ~1 Million User Records |
| **Bandwidth** | Network I/O | **Distance/Latency** | **The speed of light (Your current issue)** |

### Current Optimizations (v3.0.4)
1.  **Adaptive Polling**: Stops asking "Who is online?" when nobody is looking.
2.  **BBR Congestion Control**: Google's algorithm to push data faster over long distances.
3.  **MTU 1420**: Maximizes packet payload size.

---

## 5. Security & Authentication

1.  **Admin Auth**:
    *   You log in -> Server verifies Hash -> Sets `vpn_admin_session` cookie.
    *   Cookie is **Signed** (cannot be forged) and valid for 24 hours.
2.  **VPN Auth**:
    *   Cryptographic Key Pairs (Curve25519). Only the holder of the **Private Key** can connect.
    *   **No passwords** for VPN users (Key-based auth is unbreakable by brute force).

---

## 6. Replication Guide (How to move to India/Singapore)

If you provision a new server (e.g., DigitalOcean Bangalore or AWS Mumbai), here is the **Exact Runbook**:

1.  **DNS**: Point `wg.yourdomain.com` to the new Server IP.
2.  **Certificates**: Run `certbot certonly --standalone -d wg.yourdomain.com` to get SSL.
3.  **Clone Code**:
    ```bash
    git clone https://github.com/geekcoderr/VPN-Server-Console.git /opt/vpn-control
    ```
4.  **Install System**:
    ```bash
    cd /opt/vpn-control
    sudo ./setup.sh
    ```
5.  **Optimize Network**:
    ```bash
    sudo ./optimize_speed.sh
    ```
6.  **Admin Setup**:
    ```bash
    python3 reset_password.py admin "NewSecurePassword"
    ```
6.  **Start Services**:
    ```bash
    docker-compose -f docker-compose.db.yml up -d  # Start Database
    systemctl start vpn-control                    # Start Backend
    docker-compose -f docker-compose.yml up -d     # Start Frontend/Proxy
    ```

**Blockers/Watchouts**:
*   **Port 51820 (UDP)**: MUST be open in the Cloud Firewall (Security Group).
*   **Port 443/80 (TCP)**: Must be open for Web UI and SSL usage.
*   **Kernel Headers**: Some cheap VPS don't allow kernel modules. Use standard Ubuntu 22.04/24.04.
