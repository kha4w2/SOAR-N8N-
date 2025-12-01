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

<img width="975" height="518" alt="image" src="https://github.com/user-attachments/assets/1498a0e3-04a6-46f3-8bf4-8d0a570f0114" />

<img width="975" height="521" alt="image" src="https://github.com/user-attachments/assets/3466e81e-0ba1-4669-aa34-dd900aca2c34" />

<img width="975" height="518" alt="image" src="https://github.com/user-attachments/assets/58c0ba40-39d7-4768-8b90-ffe55a0897a6" />


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

<img width="975" height="517" alt="image" src="https://github.com/user-attachments/assets/c32239e3-affc-41ec-95ca-43d4dafc632f" />

<img width="975" height="517" alt="image" src="https://github.com/user-attachments/assets/29dd07f9-7c11-48f6-8066-3d3e5a72be47" />


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

<img width="975" height="488" alt="image" src="https://github.com/user-attachments/assets/f0bd0539-b079-42b8-8647-da52902ac968" />

<img width="975" height="610" alt="image" src="https://github.com/user-attachments/assets/14ee4b9f-a3e9-4ebc-a81d-8f000db66287" />


---

## 📊 2. Fluent Bit Log Processing

### ⚙️ Configuring Fluent Bit Input and Elasticsearch Output
This step configures Fluent Bit to read raw log files from the specified path and parse them using a defined parser. It then sends the parsed logs to Elasticsearch, specifying the host, port, credentials, and index name, ensuring proper ingestion of logs for further analysis.

<img width="975" height="552" alt="image" src="https://github.com/user-attachments/assets/66160c2f-f83d-4555-9fa4-65498eba4f4a" />

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

<img width="975" height="143" alt="image" src="https://github.com/user-attachments/assets/eece1cd4-3fc9-43cc-8532-e59ee0f8107b" />

**Configuration Used:**
```ini
[PARSER]
    Name    PARSER-Logs
    Format  regex
    Regex   date=(?<date>\d{4}-\d{2}-\d{2})\s+time=(?<time>\d{2}:\d{2}:\d{2})\s+devname="(?<devname>[^"]+)"\s+devid="(?<devid>[^"]+)"\s+logid="(?<logid>[^"]+)"\s+type="(?<type>[^"]+)"\s+subtype="(?<subtype>[^"]+)"\s+eventtype="(?<eventtype>[^"]+)"\s+level="(?<level>[^"]+)"\s+vd="(?<vd>[^"]+)"\s+policyid=(?<policyid>\d+)\s+sessionid=(?<sessionid>\d+)\s+srcip=(?<srcip>\d{1,3}(?:\.\d{1,3}){3})\s+srcport=(?<srcport>\d+)\s+dstip=(?<dstip>\d{1,3}(?:\.\d{1,3}){3})\s+dstport=(?<dstport>\d+)\s+srcintf="(?<srcintf>[^"]+)"\s+dstintf="(?<dstintf>[^"]+)"\s+service="(?<service>[^"]+)"\s+hostname="(?<hostname>[^"]+)"\s+profile="(?<profile>[^"]+)"\s+direction="(?<direction>[^"]+)"\s+virusname="(?<virusname>[^"]+)"\s+action="(?<action>[^"]+)"\s+msg="(?<msg>[^"]+)"
```

### ▶️ Running and Verifying Fluent Bit Service
This step starts the Fluent Bit agent using the configured .conf file. The service initializes input (tailing log files), applies the parser, and starts output workers to send data to Elasticsearch. Logs confirm that Fluent Bit is running successfully and ready to forward structured log events.

<img width="975" height="467" alt="image" src="https://github.com/user-attachments/assets/46e83da7-13e5-442e-9d90-96d35f0c2399" />

**Command Used:**
```powershell
# Run Fluent Bit with the specified configuration
.\fluent-bit.exe -c "C:\Program Files\fluent-bit\conf\fluent-bit.conf"
```

### 🧪 Manually Injecting Malware Logs into Elasticsearch via Fluent Bit

In this step, raw malware detection logs from RawLog.conf are manually provided to Fluent Bit for testing and indexing. The logs are parsed using the configured parser and sent to the Elasticsearch index group2-khaled-elgohary-fluentbit. This manual insertion allows verification of parsing rules, field extraction, and correct indexing before automating log collection.

<img width="975" height="520" alt="image" src="https://github.com/user-attachments/assets/de031ebe-fb45-4dfc-b6ae-b0cd7f8b6d09" />

**Notes:**
- Logs are manually inserted to test parsing and output.

### ✅ Verifying Manually Injected Logs in Kibana Discover

This step involves verifying that the manually injected logs appear correctly in Kibana Discover interface, confirming successful parsing, field extraction, and indexing.

<img width="975" height="520" alt="image" src="https://github.com/user-attachments/assets/f6470341-e44f-49fc-8fe4-54130ac0674d" />

<img width="975" height="489" alt="image" src="https://github.com/user-attachments/assets/d8b7bd69-35d4-40a6-96a3-3d77da2c6ce9" />


---
# 3. SOAR (n8n)

## 🚀 Start and Verify n8n Docker Container

<img width="975" height="185" alt="image" src="https://github.com/user-attachments/assets/d776fd26-2d59-499e-9e10-5f8761b96c92" />

This step involves starting the n8n Docker container for security orchestration and automation workflows.

---

## 🔍 Fetch Logs from Elasticsearch

<img width="975" height="419" alt="image" src="https://github.com/user-attachments/assets/f568b239-2eba-4902-82a7-b4c51ca0b855" />

<img width="975" height="434" alt="image" src="https://github.com/user-attachments/assets/ae57b7d5-5d4e-4684-b49e-c0640db43290" />

<img width="975" height="601" alt="image" src="https://github.com/user-attachments/assets/d82b3142-13c0-449a-8c17-2c18444935e4" />

<img width="978" height="176" alt="image" src="https://github.com/user-attachments/assets/3bbaf53c-b116-48b9-9e3a-118a29b5788d" />


This step retrieves all logs from the specified Elasticsearch index to process them in the workflow.

**JSON Body Configuration:**
```json
{
  "query": {
    "match_all": {}
  },
  "size": 100
}
```

**Purpose:** Retrieve the most recent 100 log entries from Elasticsearch for analysis.

---

## 🔄 Split Logs into Individual Items

<img width="975" height="608" alt="image" src="https://github.com/user-attachments/assets/1751cb1c-0b91-4970-887c-51b8b1373fab" />

<img width="975" height="301" alt="image" src="https://github.com/user-attachments/assets/58877ebb-06dc-4141-afa4-1e3702de0837" />


This step separates the Elasticsearch response into individual log entries for easier processing in the workflow.

**Node Used:** *Split In*  
**Function:** Converts array of logs into separate workflow items for parallel processing.

---

## 📍 Extract Destination IPs

<img width="975" height="611" alt="image" src="https://github.com/user-attachments/assets/450464da-4de8-48e9-88fb-72f890718c6a" />

This step maps each log entry to its destination IP (`dstip`) for further threat analysis.

**Process:**  
- Iterates through each log item
- Extracts `_source.dstip` field
- Passes IP addresses to next node

---

## 🧹 Remove Duplicate IPs

<img width="975" height="611" alt="image" src="https://github.com/user-attachments/assets/08aac16f-adde-44a0-a79b-4affbec78be3" />

<img width="975" height="190" alt="image" src="https://github.com/user-attachments/assets/4398ad27-605f-4ec3-9c43-0f5e6cec43d6" />


This step filters out repeated destination IPs to ensure each IP is unique for analysis.

**Function:**  
- Takes all extracted IPs
- Removes duplicates using Set
- Returns unique IP list

---

## 🌐 Filter Public Destination IPs

<img width="975" height="602" alt="image" src="https://github.com/user-attachments/assets/f4009d57-e2fb-4b0c-b673-3bf7a8c0473f" />

<img width="975" height="173" alt="image" src="https://github.com/user-attachments/assets/f41b81ea-1772-480c-aba2-f18d4390f048" />


This step extracts all destination IPs, removes duplicates, and excludes private IP ranges to focus only on public IPs.

**Code Node Configuration:**
```javascript
const destIPs = $input.all()
  .map(item => item.json._source?.dstip)
  .filter(ip => ip && typeof ip === "string" ? ip.trim() : null);
const uniqueIPs = [...new Set(destIPs)];
const publicIPRegex = /^(?!10\.)(?!127\.)(?!192\.168\.)(?!172\.(1[6-9]|2\d|3[0-1])\.).+$/;
const publicIPs = uniqueIPs.filter(ip => publicIPRegex.test(ip));
return publicIPs.map(ip => ({ json: { dstip: ip } }));
```

**Regex Explanation:** Excludes:
- `10.x.x.x` (Private)
- `127.x.x.x` (Loopback)
- `192.168.x.x` (Private)
- `172.16.x.x` to `172.31.x.x` (Private)

---

## 📤 Prepare IPs for Threat Intelligence

<img width="975" height="435" alt="image" src="https://github.com/user-attachments/assets/a478a36e-583e-4b16-8f0f-8490cfe7e129" />

This step formats each split IP as a separate item to send to the next nodes for scanning or enrichment.

**Purpose:** Ensures each IP is properly formatted for VirusTotal API calls.

---

## 🛡️ VirusTotal IP Reputation Check

<img width="975" height="574" alt="image" src="https://github.com/user-attachments/assets/6dc9bb23-6574-475b-ada1-93b165d2b505" />

This step queries VirusTotal for each IP to determine if it is malicious or clean.

**API Endpoint:** `GET /api/v3/ip_addresses/{ip}`  
**Parameters:**
- IP Address from previous node
- VirusTotal API Key (stored in credentials)

**Response Includes:**
- Malicious/Suspicious count
- Last analysis statistics
- ASN and geolocation data
- Reputation score

---

## ⚠️ Filter Malicious IPs

<img width="975" height="611" alt="image" src="https://github.com/user-attachments/assets/091d2ea0-61ae-4929-87fb-29e0a2aca223" />

This step separates IPs flagged as malicious by VirusTotal from clean ones for further processing.

**Condition Node:**
```javascript
{{ $json.data.attributes.last_analysis_stats.malicious > 0 }}
```

**True Branch:** IP has malicious flags → Continue to reporting  
**False Branch:** IP is clean → End workflow for this IP

---

## 📊 Generate HTML Report

<img width="975" height="603" alt="image" src="https://github.com/user-attachments/assets/7640675d-1b7f-4626-9f7c-23082cf0b96b" />

This step converts malicious IP data from VirusTotal into an HTML report to send via email to the SOC team.

**Report Includes:**
- Malicious IP address
- Number of malicious/suspicious detections
- Country and ASN information
- Last analysis timestamp
- Related threat intelligence

**Format:** Professional HTML template with SOC branding

---

## 📧 Send Email Notification

<img width="975" height="590" alt="image" src="https://github.com/user-attachments/assets/5487d22e-298d-46a7-b019-b8991a2d2407" />

<img width="975" height="603" alt="image" src="https://github.com/user-attachments/assets/9aef7125-29d6-4317-ba79-0203f0a858d8" />

This step sends the generated HTML report containing malicious IPs to the SOC team via SMTP.

**Email Configuration:**
- **To:** `soc-team@company.com`
- **Subject:** `[SOC Alert] Malicious IP Detected - {{timestamp}}`
- **Body:** HTML report from previous node
- **Priority:** High

**SMTP Settings:**
- Server: Your SMTP server
- Port: 587 (TLS)
- Authentication: Required

---

## ✅ Final Report Delivered

<img width="975" height="61" alt="image" src="https://github.com/user-attachments/assets/ca83650a-60df-4a79-b4a2-1b2c83f81217" />


<img width="975" height="383" alt="image" src="https://github.com/user-attachments/assets/e125f031-3407-4f04-be2a-5ab81967e671" />

<img width="971" height="698" alt="image" src="https://github.com/user-attachments/assets/55cae48a-e436-4b1c-b23e-dc8a75be3f7b" />

This step confirms that the HTML alert with malicious IP details was successfully sent to the SOC team for immediate investigation.

**Success Indicators:**
- Email sent confirmation
- Delivery status
- Timestamp of notification

---

## 🔄 Final Workflow Overview

<img width="975" height="611" alt="image" src="https://github.com/user-attachments/assets/b8c4dbb5-5525-4f5a-a422-f9e2d40bd6c9" />

**Workflow Summary:**
1. **Start** → n8n container initialized
2. **Fetch** → Get logs from Elasticsearch
3. **Split** → Separate log entries
4. **Extract** → Get destination IPs
5. **Deduplicate** → Remove duplicate IPs
6. **Filter** → Keep only public IPs
7. **Enrich** → Check IPs in VirusTotal
8. **Analyze** → Filter malicious IPs
9. **Report** → Generate HTML report
10. **Notify** → Send email to SOC
11. **Confirm** → Delivery verification

**Total Nodes:** 11  
**Execution Time:** ~2-3 minutes (including API rate limiting)  
**Automation Frequency:** Can be scheduled hourly/daily

---

## 🎯 Key Benefits

✅ **Automated Threat Detection** – No manual IP checking required  
✅ **Real-time Alerts** – SOC team notified immediately  
✅ **Reduced False Positives** – Public IP filtering eliminates internal traffic  
✅ **Centralized Reporting** – All alerts in consistent HTML format  
✅ **Scalable** – Can process hundreds of IPs per run  

---

## ⚙️ Prerequisites

1. **n8n Docker Container** running
2. **Elasticsearch** credentials and index access
3. **VirusTotal API** key with sufficient quota
4. **SMTP Server** configured for email sending
5. **Network Access** to all required endpoints

---

**صلى الله على سيدنا محمد 🌹**  
*Remember to send blessings upon the Prophet ﷺ when implementing security solutions.*
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
