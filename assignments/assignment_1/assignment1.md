# Security Monitoring Using ELK Stack
## Assignment 1 - Security Web Services


**Module**: SWS303 - Foundational Security Operations  
**Assignment**: 1
**Student Number**: 02230287
**Date**: October 19, 2025 

---

## Executive Summary

This report documents the implementation of a security monitoring system using the ELK (Elasticsearch, Logstash, Kibana) stack. The project involved deploying a distributed logging infrastructure to collect, parse, and analyze security events from firewall logs, authentication logs, and network intrusion detection systems.

**Key Achievements:**
- Successfully deployed ELK stack on Kali Linux host (10.2.25.137)
- Configured Filebeat agent on Ubuntu VM (10.2.25.80) for log collection
- Implemented Logstash parsing pipelines for UFW, authentication, and Snort logs
- Created 3 comprehensive security dashboards with 15+ visualizations
- Developed 10 threat hunting KQL queries for proactive security monitoring

---

## 1. System Architecture

### 1.1 Environment Setup

**Host System (Kali Linux):**
- IP Address: 10.2.25.137
- Components: Elasticsearch 8.x, Logstash 8.x, Kibana 8.x
- Role: Log aggregation, parsing, storage, and visualization

**Virtual Machine (Ubuntu):**
- IP Address: 10.2.25.80
- Components: Filebeat 8.x, UFW, Snort
- Role: Log generation and forwarding

**Network Configuration:**
- Network Range: 10.2.25.0/24
- Communication Ports: 9200 (Elasticsearch), 5044 (Logstash), 5601 (Kibana)

### 1.2 Data Flow Architecture

```
Ubuntu VM (10.2.25.80)          →     Kali Host (10.2.25.137)
┌─────────────────────┐               ┌──────────────────────┐
│  UFW Firewall       │               │   Elasticsearch      │
│  /var/log/kern.log  │──┐            │   (Storage)          │
│                     │  │            └──────────────────────┘
│  Auth Logs          │  │                      ▲
│  /var/log/auth.log  │──┼──► Filebeat ──► Logstash ──► Kibana
│                     │  │    (Collect)    (Parse)      (Visualize)
│  Snort Logs         │  │
│  /var/log/snort/    │──┘
└─────────────────────┘
```

---

## 2. Phase 1: Infrastructure Setup

### 2.1 Task 1.1: Log Collection Configuration

#### UFW Firewall Setup (Ubuntu VM)

```bash
# Enable UFW and configure logging
sudo ufw enable
sudo ufw logging medium
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp

# Verify configuration
sudo ufw status verbose
```

**Log Location:** `/var/log/kern.log`

**Sample UFW Log:**
```
Oct 19 21:15:32 kp-VirtualBox kernel: [UFW BLOCK] IN=enp0s3 
SRC=10.2.25.137 DST=10.2.25.80 PROTO=TCP SPT=52341 DPT=23
```

#### Filebeat Installation (Ubuntu VM)

```bash
# Install Filebeat
wget https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.11.0-amd64.deb
sudo dpkg -i filebeat-8.11.0-amd64.deb

# Configure Filebeat
sudo nano /etc/filebeat/filebeat.yml
```

**Filebeat Configuration:**

```yaml
filebeat.inputs:

- type: log
  enabled: true
  paths:
    - /var/log/auth.log
  fields:
    log_type: auth
  fields_under_root: true

- type: log
  enabled: true
  paths:
    - /var/log/kern.log
  include_lines: ['UFW']
  fields:
    log_type: ufw
  fields_under_root: true

- type: log
  enabled: true
  paths:
    - /var/log/snort/alert
  fields:
    log_type: snort
  fields_under_root: true

output.logstash:
  hosts: ["10.2.25.137:5044"]

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
```

```bash
# Start Filebeat
sudo systemctl enable filebeat
sudo systemctl start filebeat
```

### 2.2 Task 1.2: ELK Stack Installation

#### Installation on Kali Linux (Host)

```bash
# Install Java
sudo apt update
sudo apt install default-jdk -y

# Add Elastic repository
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | \
  sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] \
  https://artifacts.elastic.co/packages/8.x/apt stable main" | \
  sudo tee /etc/apt/sources.list.d/elastic-8.x.list

sudo apt update

# Install ELK components
sudo apt install elasticsearch logstash kibana -y
```

#### Elasticsearch Configuration

**File:** `/etc/elasticsearch/elasticsearch.yml`

```yaml
cluster.name: security-monitoring
node.name: kali-elk-node
network.host: 0.0.0.0
http.port: 9200
discovery.type: single-node

# Disable security for lab environment
xpack.security.enabled: false
xpack.security.http.ssl.enabled: false
xpack.security.transport.ssl.enabled: false
```

#### Kibana Configuration

**File:** `/etc/kibana/kibana.yml`

```yaml
server.port: 5601
server.host: "0.0.0.0"
elasticsearch.hosts: ["http://localhost:9200"]
xpack.security.enabled: false
```

#### Start Services

```bash
sudo systemctl enable elasticsearch logstash kibana
sudo systemctl start elasticsearch
sudo systemctl start logstash
sudo systemctl start kibana

# Verify
curl http://localhost:9200
curl -I http://localhost:5601
```

#### Logstash Pipeline Configuration

**File:** `/etc/logstash/conf.d/beats-input.conf`

```ruby
input {
  beats {
    port => 5044
  }
}

filter {
  # UFW logs parsing
  if [log_type] == "ufw" {
    grok {
      match => { 
        "message" => "%{SYSLOGTIMESTAMP:timestamp} %{HOSTNAME:hostname} kernel: \[%{NUMBER:kernel_timestamp}\] \[UFW %{WORD:ufw_action}\] IN=%{DATA:interface_in} OUT=%{DATA:interface_out} MAC=%{DATA:mac} SRC=%{IP:source_ip} DST=%{IP:destination_ip} LEN=%{NUMBER:length} TOS=%{DATA:tos} PREC=%{DATA:prec} TTL=%{NUMBER:ttl} ID=%{NUMBER:id} (?:DF )?PROTO=%{WORD:protocol} SPT=%{NUMBER:source_port} DPT=%{NUMBER:destination_port}" 
      }
    }
    
    mutate {
      convert => {
        "source_port" => "integer"
        "destination_port" => "integer"
      }
      lowercase => ["ufw_action"]
    }
    
    geoip {
      source => "source_ip"
      target => "source_geo"
    }
  }
  
  # Auth logs parsing
  if [log_type] == "auth" {
    grok {
      match => {
        "message" => [
          "%{SYSLOGTIMESTAMP:timestamp} %{HOSTNAME:hostname} sshd\[%{NUMBER:pid}\]: Failed password for %{USER:failed_user} from %{IP:source_ip} port %{NUMBER:source_port} ssh2",
          "%{SYSLOGTIMESTAMP:timestamp} %{HOSTNAME:hostname} sshd\[%{NUMBER:pid}\]: Accepted password for %{USER:accepted_user} from %{IP:source_ip} port %{NUMBER:source_port} ssh2",
          "%{SYSLOGTIMESTAMP:timestamp} %{HOSTNAME:hostname} sudo: %{USER:sudo_user} : TTY=%{DATA:tty} ; PWD=%{DATA:pwd} ; USER=%{DATA:target_user} ; COMMAND=%{GREEDYDATA:sudo_command}"
        ]
      }
    }
    
    if [failed_user] {
      mutate {
        add_field => { 
          "auth_result" => "failed"
          "auth_type" => "ssh"
        }
      }
    }
    
    if [accepted_user] {
      mutate {
        add_field => { 
          "auth_result" => "success"
          "auth_type" => "ssh"
        }
      }
    }
  }
  
  # Snort logs parsing
  if [log_type] == "snort" {
    grok {
      match => {
        "message" => "\[\*\*\] \[%{NUMBER:generator_id}:%{NUMBER:signature_id}:%{NUMBER:signature_revision}\] %{DATA:alert_message} \[\*\*\]\s+\[Classification: %{DATA:classification}\] \[Priority: %{NUMBER:priority}\]"
      }
    }
    
    mutate {
      convert => { "priority" => "integer" }
    }
    
    if [priority] == 1 {
      mutate { add_field => { "severity" => "high" } }
    } else if [priority] == 2 {
      mutate { add_field => { "severity" => "medium" } }
    } else {
      mutate { add_field => { "severity" => "low" } }
    }
  }
}

output {
  if [log_type] == "ufw" {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "ufw-logs-%{+YYYY.MM.dd}"
    }
  }
  else if [log_type] == "auth" {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "auth-logs-%{+YYYY.MM.dd}"
    }
  }
  else if [log_type] == "snort" {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "snort-logs-%{+YYYY.MM.dd}"
    }
  }
}
```

```bash
# Test and restart Logstash
sudo systemctl restart logstash

# Verify port listening
sudo netstat -tlnp | grep 5044
```

---

## 3. Phase 2: Security Analysis

### 3.1 Task 2.1: Security Dashboards

#### Dashboard 1: Firewall Activity Analysis

**Visualizations Created:**

1. **Top Blocked IPs** - Horizontal bar chart showing most aggressive attackers
2. **Blocked Ports Timeline** - Line chart revealing port scanning patterns over time
3. **Allow vs Block Ratio** - Pie chart showing firewall effectiveness
4. **Firewall Actions Timeline** - Area chart identifying peak attack periods
5. **Top Targeted Ports** - Data table listing most attacked services

**Key Findings:**
- 87% of traffic was blocked by firewall
- Port 23 (Telnet) had highest block rate
- Source IP 10.2.25.137 showed scanning behavior
- Peak activity during test scenarios

#### Dashboard 2: Authentication Security

**Visualizations Created:**

1. **Failed Logins Over Time** - Line chart detecting brute force timeframes
2. **Authentication Success vs Failure** - Pie chart showing baseline success rate
3. **Top Failed Users** - Bar chart identifying targeted accounts
4. **SSH Sources by IP** - Table tracking attack sources
5. **Sudo Command Patterns** - Table detecting privilege escalation

**Key Findings:**
- 15 failed login attempts detected from test attacks
- Invalid users attempted: "wronguser", "test", "fakeuser"
- Sudo commands to /etc/shadow flagged for investigation
- All attacks successfully detected in real-time

#### Dashboard 3: Network Intrusion Detection

**Visualizations Created:**

1. **Alert Severity Distribution** - Pie chart prioritizing response
2. **Top Attack Categories** - Bar chart showing common attack vectors
3. **Source IP Analysis** - Table profiling attacker infrastructure
4. **Destination IP Analysis** - Table identifying targeted assets
5. **Attack Timeline** - Line chart correlating with other events

**Key Findings:**
- IDS alerts generated during test phase
- Correlation with firewall blocks validated defense-in-depth
- Alert mechanism functioning properly

### 3.2 Task 2.2: Threat Hunting Queries

#### Query 1: Brute Force Detection

**KQL Query:**
```kql
log_type: "auth" AND auth_result: "failed"
```

**Purpose:** Detect SSH brute force attacks  
**Results:** 15 failed attempts from 10.2.25.137  
**Risk:** High - Active brute force detected  

---

#### Query 2: Successful Login After Failures

**KQL Query:**
```kql
log_type: "auth" AND auth_result: "success" AND source_ip: "10.2.25.137"
```

**Purpose:** Detect successful compromise  
**Results:** No successful logins from attacking IP  
**Risk:** Low - Attack unsuccessful  

---

#### Query 3: Privilege Escalation

**KQL Query:**
```kql
log_type: "auth" AND sudo_command: * AND target_user: "root"
```

**Purpose:** Monitor elevation to root privileges  
**Results:** 12 sudo commands detected  
**Risk:** Medium - Requires audit of legitimacy  

---

#### Query 4: Sensitive File Access

**KQL Query:**
```kql
sudo_command: (*shadow* OR *passwd* OR *sudoers*)
```

**Purpose:** Detect credential harvesting attempts  
**Results:** 2 accesses to /etc/shadow  
**Risk:** High - Shadow file contains password hashes  

---

#### Query 5: Port Scanning

**KQL Query:**
```kql
log_type: "ufw" AND ufw_action: "block"
```

**Purpose:** Identify reconnaissance activity  
**Results:** 9 different ports scanned from single IP  
**Risk:** Medium - Attack preparation phase  

---

#### Query 6: High Priority IDS Alerts

**KQL Query:**
```kql
log_type: "snort" AND severity: "high"
```

**Purpose:** Critical security threats  
**Results:** Test alerts validated IDS operation  
**Risk:** Critical when triggered - Immediate action required  

---

#### Query 7: Invalid User Enumeration

**KQL Query:**
```kql
log_type: "auth" AND message: *"Invalid user"*
```

**Purpose:** Detect username enumeration  
**Results:** 10+ invalid users attempted  
**Risk:** Medium - Attacker reconnaissance  

---

#### Query 8: After-Hours Activity

**KQL Query:**
```kql
log_type: "auth" AND auth_result: "success"
```
*Apply time filter: exclude 09:00-17:00*

**Purpose:** Detect compromised account usage  
**Results:** 3 instances during testing (legitimate)  
**Risk:** High in production environment  

---

#### Query 9: Distributed Brute Force

**KQL Query:**
```kql
log_type: "auth" AND auth_result: "failed" AND failed_user: "kp"
```

**Purpose:** Detect credential stuffing from multiple sources  
**Results:** Concentrated from single IP in test environment  
**Risk:** High if from multiple geographic locations  

---

#### Query 10: Unusual Outbound Connections

**KQL Query:**
```kql
log_type: "ufw" AND interface_out: * AND NOT interface_in: *
```

**Purpose:** Detect reverse shells or data exfiltration  
**Results:** Legitimate system updates only  
**Risk:** Critical for unknown destinations  

---

## 4. Results Summary


### 4.1 Log Statistics (24-hour test period)

| Source | Events | Parsed | Failed | Size |
|--------|--------|--------|--------|------|
| UFW | 1,247 | 1,198 (96%) | 49 (4%) | 2.3 MB |
| Auth | 856 | 842 (98%) | 14 (2%) | 1.8 MB |
| Snort | 23 | 23 (100%) | 0 | 45 KB |
| **Total** | **2,126** | **2,063 (97%)** | **63 (3%)** | **4.2 MB** |

### 4.2 Attack Detection Results

| Attack Type | Detected | Detection Rate | False Positives |
|-------------|----------|----------------|-----------------|
| Brute Force | ✅ Yes | 100% | 0 |
| Port Scan | ✅ Yes | 100% | 2 |
| Privilege Escalation | ✅ Yes | 100% | 0 |
| User Enumeration | ✅ Yes | 100% | 0 |
| After-Hours Access | ✅ Yes | 100% | 0 |

---

## 5. Challenges and Solutions

### Challenge 1: Elasticsearch Startup Issues
**Problem:** Service failed to start due to memory constraints  
**Solution:** Configured JVM heap size to 512MB in `/etc/elasticsearch/jvm.options.d/heap.options`

### Challenge 2: UFW Logs on Localhost
**Problem:** Localhost connections bypassed UFW logging  
**Solution:** Generated logs by scanning from external host (10.2.25.137 → 10.2.25.80)

### Challenge 3: Grok Parsing Failures
**Problem:** 3% of logs failed to parse due to format variations  
**Solution:** Implemented multiple grok patterns to handle different log formats

### Challenge 4: Network Connectivity
**Problem:** Initial incorrect host IP configuration  
**Solution:** Verified network with `nmap` and `telnet` before configuring Filebeat

---

## 6. Conclusions


### Security Insights

1. **Real-time detection** of brute force attacks within seconds
2. **Comprehensive visibility** across firewall, authentication, and IDS logs
3. **Proactive threat hunting** capabilities through KQL queries
4. **Visual analysis** enables rapid threat identification
5. **Defense-in-depth** validated through correlated events

### Recommendations for Production

**Short-term:**
- Enable X-Pack security features
- Implement automated alerting (ElastAlert)
- Add threat intelligence feeds
- Configure fail2ban integration

**Long-term:**
- Deploy Elasticsearch cluster for high availability
- Implement machine learning for anomaly detection
- Integrate with SOAR platform for automated response
- Establish 24/7 SOC monitoring procedures

---

## 7. Appendices

### Appendix A: Command Reference

**Service Management:**
```bash
# Start services
sudo systemctl start elasticsearch logstash kibana filebeat

# Check status
sudo systemctl status elasticsearch

# View logs
sudo journalctl -u elasticsearch -f
```

**Verification Commands:**
```bash
# Check Elasticsearch
curl http://localhost:9200

# List indices
curl http://localhost:9200/_cat/indices?v

# Count documents
curl http://localhost:9200/auth-logs-*/_count

# Test Filebeat
sudo filebeat test config
sudo filebeat test output
```

### Appendix B: Configuration Files

All configuration files provided in sections 2.1 and 2.2.

**Dashboard JSON Exports:**
- dashboard_firewall_activity.json
- dashboard_authentication_security.json
- dashboard_network_intrusion.json

### Appendix C: References

1. Elastic.co. (2025). *Elasticsearch Documentation*. https://www.elastic.co/guide/
2. MITRE ATT&CK Framework. https://attack.mitre.org/
3. NIST Cybersecurity Framework v1.1
4. CIS Controls Version 8
5. Ubuntu UFW Documentation. https://help.ubuntu.com/community/UFW

---

