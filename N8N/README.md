<img width="1613" height="692" alt="image" src="https://github.com/user-attachments/assets/c7d4c7ca-1618-4033-aa10-f332483436b7" />

### 🔐 Step 1 — API Authentication Token Request

**🧩 Node Name:** Generate Token  

📝  This step sends a POST request to the API authentication endpoint to generate a Bearer token used to authorize all subsequent workflow API calls.

**🌐 Endpoint:**  
`POST /auth/token`

**🎯 Purpose:**  
Obtain `access_token`, `token_type`, and `expires_in` for secure backend API communication.

**📝 Steps:**  

<img width="1302" height="693" alt="image" src="https://github.com/user-attachments/assets/5b44cd76-58b3-4ed9-82fe-7d2e736a0f51" />

<img width="1291" height="542" alt="image" src="https://github.com/user-attachments/assets/2ffef75a-47f4-4e94-b435-c59b3c402345" />

<img width="1298" height="636" alt="image" src="https://github.com/user-attachments/assets/01c7aa09-fa85-4510-9f1a-d93080b665aa" />

<img width="1302" height="682" alt="image" src="https://github.com/user-attachments/assets/51341e4a-ce0d-4d0d-b831-54e6479aae01" />


### 🔎 Step 2 — Validate Token Response

**🧩 Node Name:** IF  

📝  Checks whether the authentication response contains a valid `access_token` before proceeding to the next steps.

**🎯 Purpose:**  
Ensure the workflow continues only if the token was successfully generated.

**📝 Steps:**  

<img width="1305" height="622" alt="image" src="https://github.com/user-attachments/assets/124f55a0-46a8-4898-aac9-6ccba9636d55" />

<img width="600" height="168" alt="image" src="https://github.com/user-attachments/assets/54f83706-d50e-4416-a057-094c55f7050f" />

### 📡 Step 3 — Fetch Alerts List

**🧩 Node Name:** GET Alerts  

📝 Sends an authenticated GET request to the `/alerts/` endpoint to retrieve all security alerts from the SOAR backend.

**🔐 Authentication:**  
Uses the `Authorization: Bearer <token>` header generated in previous steps.

**🌐 Endpoint:**  
`GET /alerts`

**🎯 Purpose:**  
Retrieve a detailed list of alerts including ID, title, severity, category, timestamps, affected systems, and risk score.

<img width="1308" height="592" alt="image" src="https://github.com/user-attachments/assets/183d5274-be95-455d-b437-26e41a7acd2a" />

<img width="1287" height="687" alt="image" src="https://github.com/user-attachments/assets/248ac9c2-536b-443c-b0e4-6d1b0d7c9592" />

<img width="1857" height="912" alt="image" src="https://github.com/user-attachments/assets/19339a66-1114-499d-83cd-08e922c0511b" />

<img width="766" height="162" alt="image" src="https://github.com/user-attachments/assets/b2a3a9b9-6a0c-4283-8156-6ac67a5715e9" />


### 🔄 Step 4 — Split Alerts into Individual Items

**🧩 Node Name:** Split Out  

📝 Extracts each alert object from `data.alerts` and outputs them as separate workflow items.

**🎯 Purpose:**  
Transform the alerts array into individual alert entries to allow processing, filtering, or routing each alert independently.

<img width="1918" height="890" alt="image" src="https://github.com/user-attachments/assets/3c868de1-75d0-4bc6-b2f5-05d5e1b1944b" />

<img width="967" height="151" alt="image" src="https://github.com/user-attachments/assets/39e1ce68-88d0-4046-8299-e04151b0498b" />


### 📨 Step 5 — Fetch Detailed Alert Information

**🧩 Node Name:** HTTP Request (GET Alert Details)

📝 Sends an authenticated GET request to retrieve full details for each individual alert using its unique `_id`.

**🌐 Endpoint:**  
`GET /alerts/{{ $json._id }}`

**🔐 Authentication:**  
`Authorization: Bearer {{ $('Generate Token').item.json.data.access_token }}`

**🎯 Purpose:**  
Expand each alert with its complete information such as event details, logs, ports, affected systems, and risk metadata.

<img width="1897" height="883" alt="image" src="https://github.com/user-attachments/assets/bf7685b6-ed0a-4ba1-8801-9eab6eec26bc" />

<img width="1177" height="162" alt="image" src="https://github.com/user-attachments/assets/a0d3f34f-0c60-4ded-b01a-1f395d8363b2" />


### 🧮 Step 6 — Aggregate & Extract Public IP Addresses

**🧩 Node Name:** Aggregate + Code (JavaScript)

📝 Combines all `source_ip` and `destination_ip` values from the alert details, removes duplicates, excludes private ranges, and returns a clean list of public IPs.

**🎯 Purpose:**  
Generate a single normalized array of **public IP addresses** to be used in enrichment or threat-intelligence checks.

**🧠 Logic Used (JavaScript):**

```javascript
// Read aggregated data
const sourceIPs = $input.first().json.source_ip || [];
const destIPs = $input.first().json.destination_ip || [];

// Combine arrays
let allIPs = [...sourceIPs, ...destIPs];

// Clean null/empty
allIPs = allIPs
  .map(ip => ip && typeof ip === "string" ? ip.trim() : ip)
  .filter(ip => ip);

// Remove duplicates
const uniqueIPs = [...new Set(allIPs)];

// Private IP regex (exclude private ranges)
const publicIPRegex = /^(?!10\.)(?!127\.)(?!192\.168\.)(?!172\.(1[6-9]|2\d|3[0-1])\.)(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

// Filter only public IPs
const publicIPs = uniqueIPs.filter(ip => publicIPRegex.test(ip));

// Return ONE item only
return [
  {
    json: {
      ips: publicIPs
    }
  }
];
```
<img width="1913" height="892" alt="image" src="https://github.com/user-attachments/assets/bc1ee335-5995-4531-962b-50ff992ce16e" />

### ⏱ Step 7 — Rate Limit Wait

**🧩 Node Name:** Wait  

📝  This step introduces a delay between API requests to comply with **VirusTotal API rate limits**.

**🎯 Purpose:**  
Ensure that requests to VirusTotal do not exceed **4 requests per minute**, preventing throttling or rejection of API calls.

**📝 Steps:**  
- Wait Time: 20 seconds  
- Wait Unit: Seconds  
- Applied after splitting IPs to ensure each batch respects the API rate limit

<img width="1892" height="906" alt="image" src="https://github.com/user-attachments/assets/4fa67882-b9a8-42bc-b6a9-44bdd5c08b36" />

### 🛡 Step 8 — VirusTotal IP Enrichment

**🧩 Node Name:** VirusTotal HTTP Request  

📝  This step queries the **VirusTotal API** for each public IP obtained from the alerts. The request retrieves detailed threat intelligence, including IP reputation, ASN, geolocation, and historical analysis.

**🌐 Endpoint:**  
`GET https://www.virustotal.com/api/v3/ip_addresses/{{ $json.ips }}`

**🔐 Authentication:**  
Uses a personal **VirusTotal API Key** stored securely in n8n credentials.

**🎯 Purpose:**  
- Identify whether IPs are malicious, suspicious, or clean.  
- Retrieve additional metadata for SOC investigations:
  - ASN, Netblock, Country, Continent  
  - IP Owner / Organization  
  - Last Analysis Date and Reputation Score  
  - WHOIS and RDAP info  

**📝 Notes:**  
- Apply **Wait Node** between requests to respect VirusTotal rate limits (4 requests/min).  
- Output can be split and aggregated for reporting or automated response.

<img width="1361" height="720" alt="image" src="https://github.com/user-attachments/assets/5533352b-4de1-4e4e-b22c-5904f1ecc4ad" />

<img width="1337" height="686" alt="image" src="https://github.com/user-attachments/assets/79043a3b-308a-4937-b64f-ca1666834b85" />

<img width="1356" height="650" alt="image" src="https://github.com/user-attachments/assets/1959f854-9913-4938-a392-2827baaeaf5d" />

<img width="1357" height="693" alt="image" src="https://github.com/user-attachments/assets/0290ce9e-d8cb-419d-82ef-a0ff80455e3c" />

<img width="1902" height="897" alt="image" src="https://github.com/user-attachments/assets/a1fedd53-917f-4372-ab3f-796ba3e80f60" />

<img width="1342" height="653" alt="image" src="https://github.com/user-attachments/assets/93a17da3-0593-40cc-9be7-42cb26b3f4d1" />

### ⚖ Step 9 — Check IP Malicious Status

**🧩 Node Name:** IF  

📝  This step evaluates each IP returned by VirusTotal to determine if it is flagged as malicious. The decision routes alerts to different branches for further handling.

**🎯 Purpose:**  
- **True Branch:** IP has one or more malicious votes → trigger further investigation or alerting.  
- **False Branch:** IP has no malicious votes → log as safe or skip automated actions.

**📝 Conditions:**  
- `{{ $json.data.attributes.last_analysis_stats.malicious }} > 0`  
- Convert types where required to ensure proper numeric comparison.

**📝 Notes:**  
- True Branch can trigger additional playbooks or notifications.  
- False Branch can continue normal processing or be logged for records.

<img width="1861" height="907" alt="image" src="https://github.com/user-attachments/assets/b8e99a19-f904-45e5-a2c3-c37a54bb625a" />

### 🧠 Step 10 — Generate HTML Report (Google Gemini)

**🧩 Node Name:** Message a Model (Google Gemini API)

📝 This step uses Google Gemini to generate a structured **HTML report** for each malicious IP returned from VirusTotal.  
The HTML output is later sent to the SOC team via email.

**🎯 Purpose:**  
Transform raw VirusTotal data into a clean, readable, and SOC‑ready HTML report without any intro text or explanations — just the content needed for the email.

**🤖 Model Used:**  
`gemini-2.5-flash`

**📝 Prompt Used:**  
The prompt instructs the model to:
- Receive VirusTotal data for an IP  
- Generate a **ready‑to‑send HTML report**  
- Exclude any AI intro/outro text  
- Avoid including “```html” blocks  
- Produce clean HTML only

**🔐 Authentication:**  
Uses a Google Gemini API credential with:
- Host: `https://generativelanguage.googleapis.com`
- API Key stored securely in n8n credentials

**📝 Notes:**  
- This node only generates HTML; it does **not** send emails directly.  
- The output is passed to the next node where the email is sent.  
- The model role is set to *model*, and output is simplified as JSON for easier handling in n8n.

<img width="761" height="352" alt="image" src="https://github.com/user-attachments/assets/f089b71c-f07f-4fa6-942b-127afc82d5a8" />

<img width="752" height="350" alt="image" src="https://github.com/user-attachments/assets/9e459eee-5971-4e72-bca0-6c134b45d04e" />

<img width="1867" height="907" alt="image" src="https://github.com/user-attachments/assets/0f256bf4-208b-49b3-82ae-ef519123e54b" />

### 📧 Step 11 — Send HTML Report via Email

**🧩 Node Name:** Send Email  

📝 This step sends the **HTML report** generated by the previous “Message a Model” node to the SOC team. It ensures all alert data and threat intelligence is delivered in a professional, readable format.

**🎯 Purpose:**  
- Deliver the VirusTotal + Gemini-generated HTML report to SOC.  
- Ensure immediate visibility of malicious or suspicious IPs.  
- Maintain a record of all alerts for auditing.

**📬 Parameters:**  
- **From:** `khaledelgohary4000-gmail.com`  
- **To:** SOC team email (e.g., `soc-team@company.com`)  
- **Subject:** `[SOC Alert] Security Alert Report`  
- **Body:** `{{ $json.html_report }}` (HTML content from the previous node)  
- **Attachments:** Optional JSON/CSV export of enriched IP data.

**📝 Notes:**  
- Node relies on a properly configured **SMTP credential**.  
- This node does not generate HTML; it only sends the content produced earlier.  
- Output can be logged for confirmation or error handling.

<img width="1900" height="910" alt="image" src="https://github.com/user-attachments/assets/85b16277-2f84-4f71-bc98-7d0e9f2d8a13" />

<img width="1911" height="925" alt="image" src="https://github.com/user-attachments/assets/1328bf9a-058b-4f75-95a9-525187d3e3cf" />

<img width="1367" height="732" alt="image" src="https://github.com/user-attachments/assets/dd07f384-524e-4c7b-b0e2-7cd3ea6b936a" />

<img width="1562" height="452" alt="image" src="https://github.com/user-attachments/assets/961bbe49-51fe-42c7-8965-fe6ce5faa873" />

### 🧩 Step 12 — Create Alert in DFIR‑IRIS

**Node Type:** DFIR‑IRIS HTTP Request  
**Method:** `POST`  
**Endpoint:** `https://v200.beta.dfir-iris.org/alerts/add`

This step creates a new alert inside **DFIR‑IRIS v2.0** using data extracted from the previous “Get Alert” node. The JSON body is mapped dynamically using n8n expressions to ensure each alert is pushed to IRIS with full context.

**Purpose:**
- Automatically forward alerts retrieved from your SIEM or detection source into DFIR‑IRIS.  
- Preserve all metadata including source IP, rule name, event time, IOCs, entities, and affected assets.  
- Allow IRIS analysts to start triage immediately with enriched context.

**JSON Body Example:**
```json
{ {
  "alert_title": "{{ $json.data.alerts[0].title }}",
  "alert_description": "{{ $json.data.alerts[0].rule_name }}",
  "alert_source": "{{ $json.data.alerts[0].source_ip }}",
  "alert_source_content": {
    "_id": "{{ $json.data.alerts[0]._id }}",

    "description": "Contoso user performed 11 suspicious activities MITRE Technique used Account Discovery (T1087) and subtechnique used Domain Account (T1087.002)",
    "entities": [
      {
        "entityRole": "Source",
        "entityType": 2,
        "id": "6204bdaf-ad46-4e99-a25d-374a0532c666",
        "inst": 0,
        "label": "user1",
        "pa": "user1@contoso.com",
        "saas": 11161,
        "type": "account"
      },
      {
        "entityRole": "Related",
        "id": "55017817-27af-49a7-93d6-8af6c5030fdb",
        "label": "DC3",
        "type": "device"
      },
      {
        "id": 20940,
        "label": "Active Directory",
        "type": "service"
      },
      {
        "entityRole": "Related",
        "id": "95c59b48-98c1-40ff-a444-d9040f1f68f2",
        "label": "DC4",
        "type": "device"
      },
      {
        "id": "5bfd18bfab73c36ba10d38ca",
        "label": "Honeytoken activity",
        "policyType": "ANOMALY_DETECTION",
        "type": "policyRule"
      },
      {
        "entityRole": "Source",
        "id": "34f3ecc9-6903-4df7-af79-14fe2d0d4553",
        "label": "Client1",
        "type": "device"
      },
      {
        "entityRole": "Related",
        "id": "d68772fe-1171-4124-9f73-0f410340bd54",
        "label": "DC1",
        "type": "device"
      },
      {
        "type": "groupTag",
        "id": "5f759b4d106abbe4a504ea5d",
        "label": "All Users"
      }
    ],
    "idValue": 15795464,
    "isSystemAlert": false,
    "resolutionStatusValue": 0,
    "severityValue": 5,
    "statusValue": 1,
    "stories": [
      0
    ],
    "threatScore": 34,
    "timestamp": 1621941916475,
    "title": "Honeytoken activity",
    "comment": "",
    "handledByUser": "administrator@contoso.com",
    "resolveTime": "2021-05-13T14:02:34.904Z",
    "URL": "https://contoso.portal.cloudappsecurity.com/#/alerts/603f704aaf7417985bbf3b22"
  },
  "alert_severity_id": 4,
  "alert_status_id": 3,
  "alert_context": {
    "context_key": "context_value"
  },
  "alert_source_event_time": "2023-03-26T03:00:30",
  "alert_note": "A note on",
  "alert_tags": "defender,anothertag",
  "alert_iocs": [
    {
      "ioc_value": "tarzan5",
      "ioc_description": "description of Tarzan",
      "ioc_tlp_id": 1,
      "ioc_type_id": 2,
      "ioc_tags": "tag1,tag2",
      "ioc_enrichment": {
        "provider_1": {
          "data": 2,
          "new_data": 3
        },
        "provider_3": {
          "enric": "true"
        }
      }
    },
    {
      "ioc_value": "tarzan2",
      "ioc_description": "description_hey",
      "ioc_tlp_id": 2,
      "ioc_type_id": 4,
      "ioc_tags": "tag1,tag2",
      "ioc_enrichment": {
        "provider_1": {
          "data": "a very long\nblablablabdjsjofiasofiasjdxaisjhfaiosxhd bla\nddijwedoijwedw\ndhasdhaifuhafiassfsakjfhaskljfhaslkfjhaslkfdjhdqwleiuhxioauwedhoqwiuhzndoqwuehxdnzoiuwehfoqwiufhxnwoquhoiwefhxnqwoiuhwqomifuhqzwofuhqwofeuzhqwofeiuqhwe fifuhqwiofuh qwofuqh fuq hwfoiqwhfoiquhfe quhfqiouwhf qoufhq hufou qufhqowiufhowufih qwfuhqwioufh wqoufh wifhufdhas",
          "new_data": 3
        },
        "provider_3": {
          "enric": "true"
        }
      }
    }
  ],
  "alert_assets": [
    {
      "asset_name": "My super asset",
      "asset_description": "Asset description",
      "asset_type_id": 1,
      "asset_ip": "1.1.1.1",
      "asset_domain": "",
      "asset_tags": "tag1,tag2",
      "asset_enrichment": {
        "enrich1": {
          "A key": "A value"
        }
      }
    }
  ],
  "alert_customer_id": 1,
  "alert_classification_id": 1
} }
```
<img width="1872" height="865" alt="image" src="https://github.com/user-attachments/assets/15afe75a-89ff-4133-a45d-897c2a8595b1" />

<img width="1918" height="923" alt="image" src="https://github.com/user-attachments/assets/61d76997-c97e-4412-b110-b50967c74db1" />









