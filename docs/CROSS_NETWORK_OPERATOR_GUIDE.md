# CLICOM Cross-Network Operator & Deployment Guide
================================================================

## 1. Overview & Architecture

CLICOM is a secure, server-mediated command-line push-to-talk (PTT) and tactical communications system. Communication between CLICOM nodes and the central CLICOM server runs over stream-oriented TCP and is cryptographically protected by TLS 1.3.

### Core Security & Architecture Model
- **Central Star Architecture**: All communications flow strictly through the central `clicom-server`. CLICOM does NOT use peer-to-peer (P2P) mesh, UDP hole punching, or multicast.
- **Single Port Simplicity**: Control messaging, authentication, floor arbitration, and Opus audio streaming all share a single TCP connection per node (default port: `4821`).
- **Transport Security Boundary (Hop-by-Hop TLS 1.3)**:
  - Transport Layer Security (TLS 1.3) protects the communication link between each node and the central server (`node <-> server`).
  - **No Application End-to-End Encryption (E2E)**: The server terminates TLS, decrypts incoming packets, authenticates credentials, validates audio sequence counters and floor ownership, and mediates speech analysis. Relayed audio is decrypted at the server before being forwarded over the recipient's TLS connection. E2E private audio encryption is reserved for future protocol revisions (`CLIP_SPEECH_MODE_E2E_PRIVATE = 0x02`), but does NOT exist in the current system.
  - CRC32 within packet headers is used strictly for framing validation, not cryptographic integrity.
- **Server Authoritative Arbitration**: Floor control and PTT leases (default 5,000 ms lease with watchdog enforcement) are managed exclusively by the server.
- **Fail-Closed Design**: If TLS fails, certificate verification fails, or authentication fails, the connection is aborted immediately. The system never silently falls back to unencrypted transmission.

---

## 2. Environment Verification: Local Loopback vs. Real WAN Deployment

> [!IMPORTANT]
> **Explicit Demarcation**: All automated unit, integration, and fuzz test suites in the CLICOM test harness execute against local loopback interfaces (`127.0.0.1`). Real-world cross-network / WAN deployment involves external routing, firewall traversal, and DNS infrastructure that cannot be executed in automated sandboxes. Real WAN connectivity across disparate physical networks has NOT been demonstrated by the test harness.

| Category | Local Loopback / Test Suite | Cross-Network / WAN Deployment |
| :--- | :--- | :--- |
| **Server Bind Host** | `127.0.0.1` | `0.0.0.0` (all interfaces) or specific WAN IP |
| **Client Target Host**| `127.0.0.1` or `localhost` | Public FQDN (e.g. `clicom.example.org`) or Public IP |
| **Port Forwarding** | Not needed | Port `4821` forwarded from edge router to server host |
| **Firewall Rules** | Loopback allowed by default | Inbound TCP `4821` allowed on server; outbound TCP `4821` on client |
| **TLS Certificate** | Test CA (`certs/ca.crt`), `localhost` SAN | Production CA-signed cert with FQDN DNS SAN or Public IP SAN |
| **NAT Traversal** | Loopback bypasses NAT | Handled by stateful outbound NAT on client, Port Forward on server |

---

## 3. Server Configuration & WAN Readiness

### 3.1 Listen Address Binding
By default, `clicom-server` binds strictly to `127.0.0.1` to prevent accidental public network exposure:
- Configuration file default: `bind_address = 127.0.0.1` in `config/server.conf`.
- Command-line default: `127.0.0.1`.

To expose the server across a local area network (LAN) or wide area network (WAN), the operator must explicitly configure the bind host:
```bash
# Via command-line flag:
clicom-server --bind 0.0.0.0 --port 4821 --cert certs/server.crt --key certs/server.key

# Note: Automatic parsing of config/server.conf at startup is not yet active in the CLI entrypoint;
# pass operational parameters via command-line flags (--bind, --port, --cert, --key).
```

### 3.2 Server Firewall Configuration
Ensure the host firewall permits incoming TCP connections on port `4821`:
- **Linux (ufw)**: `sudo ufw allow 4821/tcp`
- **Linux (nftables/iptables)**: `iptables -A INPUT -p tcp --dport 4821 -j ACCEPT`
- **Windows Firewall**:
  ```powershell
  New-NetFirewallRule -DisplayName "CLICOM Server Port 4821" -Direction Inbound -LocalPort 4821 -Protocol TCP -Action Allow
  ```

### 3.3 Router & NAT Port Forwarding
If the server resides behind a NAT router:
1. Forward external TCP port `4821` to the server host's internal LAN IP address on port `4821`.
2. Ensure Hairpin NAT (NAT loopback) is supported if testing clients from within the same LAN using the WAN address.

---

## 4. Client Configuration & WAN Targeting

Clients must be configured with the server's public network identity:

```bash
# Connect using public FQDN (recommended):
clicom --node "OPERATOR-ALPHA" --host clicom.example.org --port 4821 --ca certs/ca.crt

# Connect using public IP address literal:
clicom --node "OPERATOR-ALPHA" --host 203.0.113.10 --port 4821 --ca certs/ca.crt

# Note: Automatic parsing of config/client.conf at startup is not yet active in the CLI entrypoint;
# pass operational parameters via command-line flags (--host, --port, --ca, --server-name).
```

---

## 5. TLS 1.3 Certificate & PKI Management

CLICOM requires strict TLS 1.3 authentication. Plaintext mode is restricted to debugging (`--insecure-plaintext`) and must never be used on public networks.

### 5.1 FQDNs vs. IP Literals (RFC 6066 & RFC 6125 Compliance)
- **FQDN Hostnames (e.g. `clicom.example.org`)**:
  - The client transmits the hostname in the Server Name Indication (SNI) TLS extension per RFC 6066.
  - The server certificate MUST contain a matching `subjectAltName` (SAN) of type `dNSName`.
- **IP Address Literals (e.g. `203.0.113.10`)**:
  - Per RFC 6066 §3, IP addresses are **forbidden** from being transmitted in SNI. CLICOM's transport strictly suppresses SNI when connecting to IP literals.
  - Verification is performed using `X509_VERIFY_PARAM_set1_ip_asc`.
  - The server certificate MUST include a matching `subjectAltName` of type `iPAddress` (e.g., `IP:203.0.113.10`). A standard DNS SAN will be rejected with error 64 (`IP address mismatch`).

### 5.2 Generating WAN Production / Staging Certificates
To generate an internal enterprise root CA and a server certificate with both FQDN and IP SAN:

```bash
# 1. Generate Root CA Private Key & Certificate:
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -new -x509 -sha256 -key ca.key -out ca.crt -days 3650 \
    -subj "/C=US/O=CLICOM Operator/CN=CLICOM Root CA"

# 2. Generate Server Private Key & CSR:
openssl ecparam -name prime256v1 -genkey -noout -out server.key
openssl req -new -sha256 -key server.key -out server.csr \
    -subj "/C=US/O=CLICOM Operator/CN=clicom.example.org"

# 3. Create OpenSSL extension config (san.ext):
cat <<EOF > san.ext
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = clicom.example.org
DNS.2 = localhost
IP.1 = 203.0.113.10
IP.2 = 127.0.0.1
EOF

# 4. Sign Server Certificate with CA:
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 825 -sha256 -extfile san.ext
```

Distribute `ca.crt` to all client endpoints. Keep `server.key` and `ca.key` strictly confidential.

---

## 6. WAN Resilience, Heartbeats, and Rate Limiting

### 6.1 Heartbeat Lifecycle & WAN Latency Tolerances
- **Heartbeat Ping**: Sent every 15 seconds if no ordinary application frames are traversing the connection.
- **Heartbeat ACK Deadline**: 5,000 ms.
- **Liveness Watchdog**: Disconnection occurs only after two consecutive missed heartbeats. This allows for intermittent latency spikes, packet loss bursts, or temporary routing reconvergence without premature disconnections.

### 6.2 Rate Limiting Protection (Anti-DoS)
- Server-side rate limiter enforces a limit of **5 failed authentication attempts per source IP within a rolling 60-second window**.
- Applies collectively to both client node authentication (`CLIP_MSG_AUTH`) and administrative authentication (`CLIP_MSG_ADMIN_AUTH_REQ`).
- **Client-Visible Behavior & Information Leakage Prevention**:
  - When an IP is rate-limited, the server logs a warning internally (`AUTH rejected for IP ...: rate limit active`) and responds with standard generic failure frames:
    - Node auth: `CLIP_MSG_AUTH_FAIL` carrying error code `CLIP_ERR_AUTH`.
    - Admin auth: `CLIP_MSG_ADMIN_AUTH_RESP` carrying error code `CLIP_ERR_AUTH`.
  - The server intentionally does NOT transmit a distinctive rate-limit error over the wire, preventing attackers from probing rate-limiter boundaries or learning system internals.
  - After sending the generic failure response, the connection is closed.
- If multiple clients share an egress NAT gateway, operators should coordinate credential provisioning to prevent collective lockouts.

### 6.3 Client Auto-Reconnection & Backoff Policy
Clients implement bounded exponential backoff:
- Delays: 1s -> 2s -> 4s -> 8s -> 16s -> capped at 30s.
- Backoff counter resets ONLY after a complete recovery lifecycle:
  1. TCP connect succeeds.
  2. TLS 1.3 handshake succeeds.
  3. Node authentication succeeds.
  4. Initial state synchronization completes cleanly.

---

## 7. Diagnostic & Troubleshooting Playbook

CLICOM logs explicit status and diagnostic codes to stderr. Use the table below to diagnose cross-network connectivity issues:

| Observed Log / Error Code | Diagnostic Root Cause | Operator Corrective Action |
| :--- | :--- | :--- |
| `CLIP_ERR_NOT_FOUND`<br>`DNS resolution failed for host...` | DNS failure: host name cannot be resolved by client OS resolver. | Check client DNS configuration (`nslookup <host>`). Verify DNS A/AAAA records for server FQDN. |
| `CLIP_ERR_CONN_REFUSED`<br>`TCP connect to ... failed: ...` | TCP connection refused or timed out. | 1. Check if server process is running.<br>2. Confirm server is bound to `0.0.0.0`, not `127.0.0.1`.<br>3. Verify edge router port forwarding on port 4821.<br>4. Inspect host and network firewall rules. |
| `CLIP_ERR_TLS_CERT_VERIFY`<br>`unable to get local issuer certificate (20)` | Untrusted CA: Client does not possess or trust the CA that issued server cert. | Ensure client `--ca` specifies the valid CA certificate file (`ca.crt`). |
| `CLIP_ERR_TLS_CERT_VERIFY`<br>`hostname mismatch (62)` | Hostname mismatch: The target host does not match any DNS SAN in server cert. | Verify client `--host` or `--server-name` matches the server certificate's DNS `subjectAltName`. |
| `CLIP_ERR_TLS_CERT_VERIFY`<br>`IP address mismatch (64)` | IP literal mismatch: Server cert lacks an `iPAddress` SAN matching the target IP. | Reissue server certificate with `IP:<address>` in `subjectAltName`, or connect via FQDN. |
| `CLIP_ERR_TLS_VERSION`<br>`negotiated '...', strictly require TLSv1.3` | Downgrade attack or outdated TLS stack. | Ensure server and client OpenSSL libraries support TLS 1.3. Plaintext fallback is forbidden. |
| `CLIP_ERR_AUTH`<br>`Authentication FAILED` / `AUTH rejected...` | Invalid credentials, unknown UUID, or client IP currently rate-limited (5 failures/60s). | Check client credentials, or wait for the 60-second sliding block window to expire if rate-limited. Inspect server logs for `rate limit active` warnings. |
| `Heartbeat timeout: missed 2 heartbeats` | WAN network disconnection, unrouteable peer, or severed link. | Inspect network routing stability; client auto-reconnection will engage automatically. |

---

## 8. Summary Checklist for Go-Live

1. [ ] Server configured with `--bind 0.0.0.0` and `--port 4821`.
2. [ ] Valid TLS 1.3 server certificate generated with appropriate FQDN or IP SANs.
3. [ ] Router port forwarding configured for TCP `4821`.
4. [ ] Inbound firewall rule active on server host.
5. [ ] CA certificate distributed to authorized client nodes.
6. [ ] Node credentials generated and securely saved (DPAPI on Windows).
7. [ ] Administrator account provisioned via `clicom-server --create-admin`.
