import json
import requests
from openai import OpenAI

# ============================
# CONFIG
# ============================

OPENAI_API_KEY = "API KEY"
VT_API_KEY = "API KEY"

OPENSEARCH_URL = "YOUR SIEM URL, I use Opensearch; you can see on my GitHub repository how I set up an environment"
OPENSEARCH_USER = "user"
OPENSEARCH_PASS = "pass"

jira_host = 'Jira URL'
jira_http = 'https'
jira_url = jira_http + "://" + jira_host
jira_api_search = '/rest/api/2/search?expand=renderedFields&jql='
jira_create_comment = '/rest/api/2/issue/{}/comment'
jira_user = 'user'
jira_pass = 'pass'

VPN_PROVIDERS = [
    "nordvpn","expressvpn","protonvpn","surfshark","mullvad",
    "privateinternetaccess","pia","cyberghost","hidemyass",
    "ipvanish","windscribe"
]

TORRENT_PORTS = {6881, 6882, 6883, 6884, 6885, 51413}
TORRENT_KEYWORDS = ["bittorrent", "torrent", "utorrent", "qbittorrent", "transmission"]

SYSTEM_MESSAGE = """
You are a experienced Senior Security Engineer/Incident Responder. 
You are working for a company that offers Security Operation Services for multiple clients, called Cymed.
You are investigating a Security Alert triggered by a network connection towards or from an IP Threat Intel indicator.
You gather all the information you have internally about the threat indicator, as well as the details of the original network event, Client, Timestamp, src and dst IP address, ports and so on.
You are checking if there were other network connections for this indicator across all clients as well and pulling this information (if available).
You are also doing indicator enrichment using Virus total and Abuse IP information, with reports, comments, relations and other observed data.
You collect full network event logs from the SIEM, if available.
It is really important to validate the hits behavior (ports, connections) to data from Virus Total and from Abuse IP. We need to know if behavior matches reports.
Also Cymed Analysts have visibility only into network (netflow data) for customers. Other data sources are not available. During investigations analysts usually check the data flow and if it matches the reports.
Often it happens that such alerts are results of torrent activity, where clients use torrent applications. Please Mark such alerts as False Positive and leave a note that we are speaking of torrent activity.

You need to analyse the event and answer the following questions:
1. What is the Classification of this Alert: True Positive / Suspicious / False Positive / Inconclusive
2. What is the confidence of the indicator: Low/Medium/High (based on matching the behavior we see in logs with the reports from Abuse and Virus Total)
3. What is the Urgency of the Alert, based on the data observed: Low/Medium/High/Critical (based on the severity of the indicator)
4. Does the Hits Behavior Match the reports from Virus Total or Abuse IP ?
5. Does this behavior look like active beaconing?
6. What type of traffic is being generated towards the indicator ?
7. Are there multiple source IPs from the original Client that connect to that indicator? simple answer, yes or no. If yes, list the src IPs
8. Are there other clients from where we see similar behaviour? simple answer, yes or no. If yes, list the other Clients involved
9. What other next steps are required in order to complete the investigations.
10. What recommandations are to remediate this alert?
"""

# ============================
# HELPERS
# ============================

def generate_jira_headers():
    import base64
    token = base64.b64encode(f"{jira_user}:{jira_pass}".encode()).decode()
    return {
        "Authorization": f"Basic {token}",
        "Content-Type": "application/json"
    }

def vt_lookup(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    r = requests.get(url, headers=headers)
    return r.json()

def vpn_score_from_vt(vt_data):
    score = 0
    try:
        attrs = vt_data["data"]["attributes"]
        as_owner = attrs.get("as_owner", "").lower()
        categories = " ".join(attrs.get("categories", {}).keys()).lower()

        for vpn in VPN_PROVIDERS:
            if vpn in as_owner:
                score += 60
            if vpn in categories:
                score += 40

        if "hosting" in as_owner or "datacenter" in as_owner:
            score += 10

    except:
        pass

    return min(score, 100)

def search_opensearch_for_history(indicator_ip, client, limit=50):
    index = f"netflow-{client}-*"
    query = {
        "size": limit,
        "query": {
            "bool": {
                "should": [
                    {"term": {"src_ip": indicator_ip}},
                    {"term": {"dst_ip": indicator_ip}}
                ]
            }
        }
    }

    url = f"{OPENSEARCH_URL}/{index}/_search"
    r = requests.post(
        url,
        auth=(OPENSEARCH_USER, OPENSEARCH_PASS),
        headers={"Content-Type": "application/json"},
        data=json.dumps(query),
        verify=False
    )

    try:
        return r.json()
    except:
        return {"hits": {"hits": []}}

def looks_like_torrent_traffic(history):
    hits = history.get("hits", {}).get("hits", [])
    for h in hits:
        src_port = h.get("_source", {}).get("src_port")
        dst_port = h.get("_source", {}).get("dst_port")
        app = h.get("_source", {}).get("app", "").lower()
        proto = h.get("_source", {}).get("protocol", "").lower()

        if src_port in TORRENT_PORTS or dst_port in TORRENT_PORTS:
            return True

        for kw in TORRENT_KEYWORDS:
            if kw in app or kw in proto:
                return True

    return False

def extract_indicator_ip(event):
    return event.get("dst_ip") or event.get("src_ip")

def classify_event(vpn_score, is_torrent):
    if is_torrent:
        return "False Positive - Torrent"
    if vpn_score >= 60:
        return "VPN Suspicious"
    return "Ignore"

# ============================
# JIRA
# ============================

def create_jira_issue(summary, description):
    print("MOCK JIRA: create_jira_issue called")
    print("SUMMARY:", summary)
    print("DESCRIPTION:", description)
    return "TEST-123"   # issue key simulator

def add_comment(issue_key, comment):
    print(f"MOCK JIRA: add_comment called for {issue_key}")
    print("COMMENT:", comment)
    return True

# ============================
# AI
# ============================

def get_ai_response(user_message_ai):
    client = OpenAI(api_key=OPENAI_API_KEY)
    completion = client.chat.completions.create(
        model="gpt-5-mini",
        messages=[
            {"role": "system", "content": SYSTEM_MESSAGE},
            {"role": "user", "content": user_message_ai}
        ]
    )
    return completion.choices[0].message.content

def build_ai_prompt(event, history, vt_data, vpn_score, is_torrent):
    return f"""
=== ORIGINAL EVENT ===
{json.dumps(event, indent=2)}

=== HISTORY ===
{json.dumps(history, indent=2)}

=== VT DATA ===
{json.dumps(vt_data, indent=2)}

VPN Score: {vpn_score}
Torrent-like: {is_torrent}
"""

# ============================
# MAIN PROCESSOR
# ============================
def build_jira_summary(event, classification, indicator_ip):
    src = event.get("src_ip", "?")
    dst = event.get("dst_ip", "?")
    client = event.get("client", "UnknownClient")

    return f"[{classification}] {indicator_ip} contacted by {client} (src {src} → dst {dst})"

def build_jira_description(event, classification, vpn_score, is_torrent):
    client = event.get("client", "UnknownClient")
    timestamp = event.get("timestamp", "UnknownTimestamp")
    indicator_ip = event.get("dst_ip") or event.get("src_ip")

    return f"""
Automated alert generated by SOAR engine.

Client: {client}
Timestamp: {timestamp}
Indicator: {indicator_ip}
Classification: {classification}
VPN Score: {vpn_score}/100
Torrent-like traffic: {is_torrent}

This alert was generated automatically based on network behavior and threat intelligence.
Full investigation details will be added as a comment.
"""

def process_alert(event): 
    print("STEP 1: Entered function") 
    indicator_ip = extract_indicator_ip(event) 
    print("STEP 2: Indicator IP =", indicator_ip) 
    vt_data = vt_lookup(indicator_ip) 
    print("STEP 3: VT lookup OK") 
    vpn_score = vpn_score_from_vt(vt_data) 
    print("STEP 4: VPN score =", vpn_score) 
    history = search_opensearch_for_history(indicator_ip, event["client"]) 
    print("STEP 5: OpenSearch history OK") 
    is_torrent = looks_like_torrent_traffic(history) 
    print("STEP 6: Torrent detection =", is_torrent) 
    classification = classify_event(vpn_score, is_torrent) 
    print("STEP 7: Classification =", classification) 
    summary = build_jira_summary(event, classification, indicator_ip) 
    print("STEP 8: Summary built") 
    description = build_jira_description(event, classification, vpn_score, is_torrent) 
    print("STEP 9: Description built") 
    issue_key = create_jira_issue(summary, description) 
    print("STEP 10: Jira issue =", issue_key)
    
    if not issue_key: 
        print("STEP 11: Jira creation failed") 
        return "Failed to create Jira issue." 
        
    if "Torrent" in classification: 
        print("STEP 12: Torrent FP branch") 
        add_comment(issue_key, "False Positive: Torrent activity detected.") 
        return f"Ticket {issue_key} created (FP torrent)." 
        
    ai_prompt = build_ai_prompt(event, history, vt_data, vpn_score, is_torrent) 
    print("STEP 13: AI prompt built") 
    ai_result = get_ai_response(ai_prompt) 
    print("STEP 14: AI response OK") 
    add_comment(issue_key, ai_result) 
    print("STEP 15: Comment added") 
    return f"Ticket {issue_key} created with AI investigation."

test_event = {
    "client": "ClientX",
    "src_ip": "10.1.2.3",
    "dst_ip": "185.159.157.5",
    "timestamp": "2026-01-09 12:55:00"
}

print(process_alert(test_event))