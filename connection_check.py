from openai import OpenAI
import json
import requests
import os

openai_api_key = "API KEY"
system_message = """
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
jira_host = 'Jira URL'
jira_http = 'https'
jira_url = jira_http + "://" + jira_host
jira_api_search = '/rest/api/2/search?jql='
jira_create_comment = '/rest/api/2/issue/{}/comment'
jira_user = 'user'
jira_pass = 'pass'

def generate_headers():
    credentials = jira_user + ":" + jira_pass
    encoded_credentials = base64.encodebytes(str.encode(credentials)).decode().replace('\n','')
    headers = {
        'Authorization': 'Basic {}'.format(encoded_credentials),
        'Content-Type': 'application/json',
        'X-Atlassian-Token': 'no-check'
    }
    return headers    

def get_ai_response(user_message_ai, system_message):
    client = OpenAI(api_key=openai_api_key
    completion = client.chat.completions.create(
        model="gpt-5-mini",
        messages=[
            {"role": "system", "content": system_message},
            {"role": "user", "content": user_messa)
ge_ai}
        ]
    )

    return json.loads(completion.to_json())['choices'][0]['message']['content']
    
def search_opensearch_for_history(indicator_ip, client, limit=10):
    return {"hits": {"hits": []}}

def vt_lookup(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": "VT API KEY"}
    r = requests.get(url, headers=headers)
    return r.json()
    
def build_ai_prompt(original_event, history, vt_data):
    return f"""
=== ORIGINAL EVENT ===
{json.dumps(original_event, indent=2)}

=== CONNECTION HISTORY ===
{json.dumps(history, indent=2)}

=== VIRUSTOTAL ENRICHMENT ===
{json.dumps(vt_data, indent=2)}

Please analyze the event using the rules from the system prompt.
"""
def process_alert(original_event):
    # 1. History
    history = search_opensearch_for_history(
        indicator_ip=original_event["dst_ip"],
        client=original_event["client"],
        limit=10
    )

    # 2. Enrichment
    vt_data = vt_lookup(original_event["dst_ip"])

    # 3. Build prompt
    user_message_ai = build_ai_prompt(original_event, history, vt_data)

    # 4. AI analysis
    ai_result = get_ai_response(user_message_ai, system_message)

    return ai_result

fake_event = {
    "client": "ClientA",
    "timestamp": "2025-01-01T12:00:00Z",
    "src_ip": "10.0.0.5",
    "dst_ip": "8.8.8.8",
    "src_port": 54321,
    "dst_port": 443,
    "protocol": "TCP"
}

result = process_alert(fake_event)
print(result)