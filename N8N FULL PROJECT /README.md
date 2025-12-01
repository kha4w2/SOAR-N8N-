# 🚀 SIEM Implementation Project

## 📋 Project Overview
This project demonstrates a complete Security Information and Event Management (SIEM) solution implementation with three main components:
1. **SIEM Log Collection** using Winlogbeat
2. **Log Processing** using Fluent Bit
3. **Security Automation** using n8N

---

## 🛡️ 1. SIEM - Winlogbeat Integration

### 🔧 Configuring Winlogbeat Output and Kibana Integration
This step involves configuring the Winlogbeat agent to communicate with both Kibana and Elasticsearch. The configuration specifies the Kibana endpoint for dashboard setup and defines the Elasticsearch output where all generated logs will be transmitted securely.

**Configuration:**
```yaml
setup.kibana:
  host: "http://192.168.6.130:5601"

output.elasticsearch:
  hosts: ["https://192.168.6.130:9200"]
  protocol: "https"
  username: "elastic"
  password: "FYQEm=bUNr-6yUeyfdic"
  ssl.enabled: true
  ssl.verification_mode: none
```

### 🚀 Starting and Testing Winlogbeat Service
This step involves restarting the Winlogbeat service and verifying its configuration and connectivity. The test configuration ensures the YAML configuration is valid, while test output checks connectivity to Elasticsearch. Successful execution confirms that logs will be properly sent and indexed.

**Commands Used:**
```powershell
# Restart Winlogbeat service
restart-Service winlogbeat

# Navigate to Winlogbeat directory
cd "C:\Program Files\Winlogbeat"

# Test the configuration
.\winlogbeat.exe test config -c .\winlogbeat.yml -e

# Test output to Elasticsearch
.\winlogbeat.exe test output -e
```

**Notes:**
- Logs confirm successful setup, Beat ID, host information, and Elasticsearch connection.
- Warnings about SSL/TLS verification being disabled indicate that the connection uses HTTPS without certificate validation (common in lab environments).

### 🔍 Viewing and Analyzing Logs in Kibana Discover
This step involves accessing the Kibana Discover interface to view and analyze the logs collected by Winlogbeat. It allows filtering, sorting, and inspecting events such as authorization changes, sensitive privilege use, and other security-related actions. This verification ensures that logs are correctly indexed and available for monitoring.

---

## 📊 2. Fluent Bit Log Processing

### ⚙️ Configuring Fluent Bit Input and Elasticsearch Output
This step configures Fluent Bit to read raw log files from the specified path and parse them using a defined parser. It then sends the parsed logs to Elasticsearch, specifying the host, port, credentials, and index name, ensuring proper ingestion of logs for further analysis.

**Configuration:**
```ini
[SERVICE]
    Flush        1
    Daemon       Off
    Log_Level    info
    Parsers_File parsers.conf
    HTTP_Server  On
    Storage.metrics On

[INPUT]
    Name   tail
    Path   C:\Program Files\fluent-bit\conf\RawLog.conf
    Parser PARSER-Logs
    Tag    rawlog.tag
    Refresh_Interval 1
    DB     C:\Program Files\fluent-bit\conf\rawlog.db

[OUTPUT]
    Name         es
    Host         192.168.6.130
    Port         9200
    HTTP_User    elastic
    HTTP_Passwd  FYQEm=bUNr-6yUeyfdic
    tls          On
    tls.verify   Off
    Match        *
    Index        group2-khaled-elgohary-fluentbit
    Format       json_lines
    Trace_Output On
    Suppress_Type_Name On
```

### 🧩 Creating Regex Parser in Fluent Bit
This step defines a custom parser in Fluent Bit using a regular expression to extract key fields from raw log entries. It captures important information such as source and destination IPs, ports, device identifiers, policy IDs, and actions, enabling structured log indexing in Elasticsearch.

**Configuration Used:**
```ini
[PARSER]
    Name    PARSER-Logs
    Format  regex
    Regex   date=(?<date>\d{4}-\d{2}-\d{2})\s+time=(?<time>\d{2}:\d{2}:\d{2})\s+devname="(?<devname>[^"]+)"\s+devid="(?<devid>[^"]+)"\s+logid="(?<logid>[^"]+)"\s+type="(?<type>[^"]+)"\s+subtype="(?<subtype>[^"]+)"\s+eventtype="(?<eventtype>[^"]+)"\s+level="(?<level>[^"]+)"\s+vd="(?<vd>[^"]+)"\s+policyid=(?<policyid>\d+)\s+sessionid=(?<sessionid>\d+)\s+srcip=(?<srcip>\d{1,3}(?:\.\d{1,3}){3})\s+srcport=(?<srcport>\d+)\s+dstip=(?<dstip>\d{1,3}(?:\.\d{1,3}){3})\s+dstport=(?<dstport>\d+)\s+srcintf="(?<srcintf>[^"]+)"\s+dstintf="(?<dstintf>[^"]+)"\s+service="(?<service>[^"]+)"\s+hostname="(?<hostname>[^"]+)"\s+profile="(?<profile>[^"]+)"\s+direction="(?<direction>[^"]+)"\s+virusname="(?<virusname>[^"]+)"\s+action="(?<action>[^"]+)"\s+msg="(?<msg>[^"]+)"
```

### ▶️ Running and Verifying Fluent Bit Service
This step starts the Fluent Bit agent using the configured .conf file. The service initializes input (tailing log files), applies the parser, and starts output workers to send data to Elasticsearch. Logs confirm that Fluent Bit is running successfully and ready to forward structured log events.

**Command Used:**
```powershell
# Run Fluent Bit with the specified configuration
.\fluent-bit.exe -c "C:\Program Files\fluent-bit\conf\fluent-bit.conf"
```

### 🧪 Manually Injecting Malware Logs into Elasticsearch via Fluent Bit
In this step, raw malware detection logs from RawLog.conf are manually provided to Fluent Bit for testing and indexing. The logs are parsed using the configured parser and sent to the Elasticsearch index group2-khaled-elgohary-fluentbit. This manual insertion allows verification of parsing rules, field extraction, and correct indexing before automating log collection.

**Notes:**
- Logs are manually inserted to test parsing and output.

### ✅ Verifying Manually Injected Logs in Kibana Discover
This step involves verifying that the manually injected logs appear correctly in Kibana Discover interface, confirming successful parsing, field extraction, and indexing.

---

## ⚡ 3. SOAR - n8N Automation Platform

### 🐳 Starting n8N Docker Container
This step involves starting the n8N Docker container for security orchestration and automation.

---

## 🔐 Security Alert Automation Workflow

This n8n workflow automates the collection, enrichment, and reporting of security alerts from multiple sources, including DFIR‑IRIS and VirusTotal. It ensures SOC teams receive timely, actionable, and well-formatted reports for rapid investigation.

### 🔐 Step 1 — API Authentication Token Request
**🧩 Node Name:** Generate Token  
This step sends a POST request to the API authentication endpoint to generate a Bearer token used to authorize all subsequent workflow API calls.

**🌐 Endpoint:** `POST /auth/token`  
**🎯 Purpose:** Obtain `access_token`, `token_type`, and `expires_in` for secure backend API communication.

### 🔎 Step 2 — Validate Token Response
**🧩 Node Name:** IF  
Checks whether the authentication response contains a valid `access_token` before proceeding to the next steps.

**🎯 Purpose:** Ensure the workflow continues only if the token was successfully generated.

### 📡 Step 3 — Fetch Alerts List
**🧩 Node Name:** GET Alerts  
Sends an authenticated GET request to the `/alerts/` endpoint to retrieve all security alerts from the SOAR backend.

**🔐 Authentication:** Uses the `Authorization: Bearer <token>` header generated in previous steps.  
**🌐 Endpoint:** `GET /alerts`  
**🎯 Purpose:** Retrieve a detailed list of alerts including ID, title, severity, category, timestamps, affected systems, and risk score.

### 🔄 Step 4 — Split Alerts into Individual Items
**🧩 Node Name:** Split Out  
Extracts each alert object from `data.alerts` and outputs them as separate workflow items.

**🎯 Purpose:** Transform the alerts array into individual alert entries to allow processing, filtering, or routing each alert independently.

### 📨 Step 5 — Fetch Detailed Alert Information
**🧩 Node Name:** HTTP Request (GET Alert Details)  
Sends an authenticated GET request to retrieve full details for each individual alert using its unique `_id`.

**🌐 Endpoint:** `GET /alerts/{{ $json._id }}`  
**🔐 Authentication:** `Authorization: Bearer {{ $('Generate Token').item.json.data.access_token }}`  
**🎯 Purpose:** Expand each alert with its complete information such as event details, logs, ports, affected systems, and risk metadata.

### 🧮 Step 6 — Aggregate & Extract Public IP Addresses
**🧩 Node Name:** Aggregate + Code (JavaScript)  
Combines all `source_ip` and `destination_ip` values from the alert details, removes duplicates, excludes private ranges, and returns a clean list of public IPs.

**🎯 Purpose:** Generate a single normalized array of **public IP addresses** to be used in enrichment or threat-intelligence checks.

**JavaScript Logic:**
```javascript
const sourceIPs = $input.first().json.source_ip || [];
const destIPs = $input.first().json.destination_ip || [];
let allIPs = [...sourceIPs, ...destIPs];
allIPs = allIPs.map(ip => ip && typeof ip === "string" ? ip.trim() : ip).filter(ip => ip);
const uniqueIPs = [...new Set(allIPs)];
const publicIPRegex = /^(?!10\.)(?!127\.)(?!192\.168\.)(?!172\.(1[6-9]|2\d|3[0-1])\.)(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const publicIPs = uniqueIPs.filter(ip => publicIPRegex.test(ip));
return [{ json: { ips: publicIPs } }];
```

### ⏱ Step 7 — Rate Limit Wait
**🧩 Node Name:** Wait  
This step introduces a delay between API requests to comply with **VirusTotal API rate limits**.

**🎯 Purpose:** Ensure that requests to VirusTotal do not exceed **4 requests per minute**, preventing throttling or rejection of API calls.

**📝 Steps:** Wait Time: 20 seconds | Wait Unit: Seconds

### 🛡 Step 8 — VirusTotal IP Enrichment
**🧩 Node Name:** VirusTotal HTTP Request  
This step queries the **VirusTotal API** for each public IP obtained from the alerts. The request retrieves detailed threat intelligence, including IP reputation, ASN, geolocation, and historical analysis.

**🌐 Endpoint:** `GET https://www.virustotal.com/api/v3/ip_addresses/{{ $json.ips }}`  
**🔐 Authentication:** Uses a personal **VirusTotal API Key** stored securely in n8n credentials.  
**🎯 Purpose:** Identify whether IPs are malicious, suspicious, or clean and retrieve additional metadata for SOC investigations.

### ⚖ Step 9 — Check IP Malicious Status
**🧩 Node Name:** IF  
This step evaluates each IP returned by VirusTotal to determine if it is flagged as malicious. The decision routes alerts to different branches for further handling.

**🎯 Purpose:** 
- **True Branch:** IP has one or more malicious votes → trigger further investigation or alerting.
- **False Branch:** IP has no malicious votes → log as safe or skip automated actions.

**📝 Conditions:** `{{ $json.data.attributes.last_analysis_stats.malicious }} > 0`

### 🧠 Step 10 — Generate HTML Report (Google Gemini)
**🧩 Node Name:** Message a Model (Google Gemini API)  
This step uses Google Gemini to generate a structured **HTML report** for each malicious IP returned from VirusTotal. The HTML output is later sent to the SOC team via email.

**🤖 Model Used:** `gemini-2.5-flash`  
**🔐 Authentication:** Uses a Google Gemini API credential with API Key stored securely in n8n credentials.

### 📧 Step 11 — Send HTML Report via Email
**🧩 Node Name:** Send Email  
This step sends the **HTML report** generated by the previous "Message a Model" node to the SOC team. It ensures all alert data and threat intelligence is delivered in a professional, readable format.

**📬 Parameters:**
- **From:** `khaledelgohary4000-gmail.com`
- **To:** SOC team email (e.g., `soc-team@company.com`)
- **Subject:** `[SOC Alert] Security Alert Report`
- **Body:** `{{ $json.html_report }}` (HTML content from the previous node)

### 🧩 Step 12 — Create Alert in DFIR‑IRIS
**🧩 Node Name:** DFIR‑IRIS HTTP Request  
**Method:** `POST`  
**Endpoint:** `https://v200.beta.dfir-iris.org/alerts/add`

This step creates a new alert inside **DFIR‑IRIS v2.0** using data extracted from the previous "Get Alert" node. The JSON body is mapped dynamically using n8n expressions to ensure each alert is pushed to IRIS with full context.

**Purpose:** Automatically forward alerts retrieved from your SIEM or detection source into DFIR‑IRIS and preserve all metadata including source IP, rule name, event time, IOCs, entities, and affected assets.

---

## 📋 Project Summary
This project successfully implements:
- ✅ **SIEM log collection** via Winlogbeat
- ✅ **Log processing and parsing** via Fluent Bit
- ✅ **Security automation** via n8N workflows
- ✅ **Threat intelligence enrichment** via VirusTotal
- ✅ **Automated reporting** via email and DFIR-IRIS integration

---

**🔒 Security | 📊 Monitoring | ⚡ Automation**
