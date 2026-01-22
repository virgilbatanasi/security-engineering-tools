from openai import OpenAI
import pandas as pd
import json

import requests

def vt_lookup(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": "API_KEY"}
    r = requests.get(url, headers=headers)
    return r.json()

openai_api_key = "API_key"

dns_df = pd.read_csv(r"*path to file with DNS servers, you can find a public DNS servers file with .csv format*")
dns_list = set(dns_df["ip_address"].astype(str).tolist())

def is_public_dns(ip):
    return ip in dns_list

system_message = """
You are a Senior Security Engineer working in a SOC environment.
You analyze network alerts and determine if they are True Positive, Suspicious, False Positive, or Inconclusive.

You receive:
- the original network event
- VirusTotal enrichment
- a flag indicating if the destination IP is a known public DNS server

If the destination IP is a known public DNS server, consider the possibility of a False Positive due to normal DNS traffic.

Provide:
1. Classification (True Positive / Suspicious / False Positive / Inconclusive)
2. Confidence (Low / Medium / High)
3. Urgency (Low / Medium / High / Critical)
4. Does behavior match VirusTotal reports?
5. Does traffic look like beaconing?
6. What type of traffic is observed?
7. Next investigation steps
8. Recommendations
"""

def get_ai_response(user_message_ai, system_message):
    client = OpenAI(api_key=openai_api_key)

    completion = client.chat.completions.create(
        model="gpt-5-mini",
        messages=[
            {"role": "system", "content": system_message},
            {"role": "user", "content": user_message_ai}
        ]
    )

    return json.loads(completion.to_json())['choices'][0]['message']['content']

def build_ai_prompt(original_event, vt_data):
    dns_flag = "YES" if is_public_dns(original_event["dst_ip"]) else "NO"

    return f"""
=== ORIGINAL EVENT ===
{json.dumps(original_event, indent=2)}

=== VIRUSTOTAL ENRICHMENT ===
{json.dumps(vt_data, indent=2)}

=== PUBLIC DNS CHECK ===
Destination IP is a known public DNS server: {dns_flag}

Please analyze this event according to the system rules.
"""

def process_alert(original_event):
    vt_data = vt_lookup(original_event["dst_ip"])
    user_message_ai = build_ai_prompt(original_event, vt_data)
    ai_result = get_ai_response(user_message_ai, system_message)
    return ai_result

fake_event = {
    "client": "ClientA",
    "timestamp": "2025-01-01T12:00:00Z",
    "src_ip": "10.0.0.5",
    "dst_ip": "8.8.8.8",  # Google DNS
    "src_port": 54321,
    "dst_port": 53,
    "protocol": "UDP"
}

result = process_alert(fake_event)
print(result)