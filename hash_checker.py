import re, requests, json, base64, urllib.parse, urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Jira Config ---
jira_host = 'jira url'
jira_http = 'https'
jira_url = jira_http + "://" + jira_host
jira_api_search = '/rest/api/2/search?expand=renderedFields&jql='
jira_create_comment = '/rest/api/2/issue/{}/comment'
jira_user = 'user'
jira_pass = 'pass'

from openai import OpenAI

openai_api_key = "API KEY"

def get_ai_response(user_message, system_message):
    client = OpenAI(api_key=openai_api_key)

    completion = client.chat.completions.create(
        model="gpt-5-mini",
        messages=[
            {"role": "system", "content": system_message},
            {"role": "user", "content": user_message}
        ]
    )

    return json.loads(completion.to_json())["choices"][0]["message"]["content"]

system_message_hash = """
You are a Senior SOC Analyst. You analyze file hashes and VirusTotal results.
Your job is to produce a clean, professional, human-readable summary for Jira.

Your output must include:
- File name (if available)
- File type
- Whether the hash is malicious, suspicious, or clean
- How many engines flagged it
- Sandbox behavior summary
- Related IPs, domains, URLs
- A short risk assessment
- Recommended next steps
- Final verdict

Keep the tone concise and professional.

IMPORTANT: Generate the final answer in English.
"""
def extract_text_from_adf(node):
    if isinstance(node, dict):
        if node.get("type") == "text":
            return node.get("text", "")
        return " ".join(extract_text_from_adf(v) for v in node.values())
    if isinstance(node, list):
        return " ".join(extract_text_from_adf(i) for i in node)
    return ""

from bs4 import BeautifulSoup

def strip_html(html_text):
    if not html_text:
        return ""
    return BeautifulSoup(html_text, "html.parser").get_text()

def generate_headers():
    credentials = jira_user + ":" + jira_pass
    encoded_credentials = base64.encodebytes(str.encode(credentials)).decode().replace('\n','')
    headers = {
        'Authorization': 'Basic {}'.format(encoded_credentials),
        'Content-Type': 'application/json',
        'X-Atlassian-Token': 'no-check'
    }
    return headers

def jql_query(query_clear):
    query_encoded = urllib.parse.quote(query_clear)
    request_url = jira_url + jira_api_search + query_encoded
    response = requests.get(request_url, headers=generate_headers(), verify=False)
    return response.status_code, response.json()

def add_comment(issue_key, comment):
    data = {"body": comment}
    request_url = jira_url + jira_create_comment.format(issue_key)
    response = requests.post(request_url, headers=generate_headers(), data=json.dumps(data), verify=False)
    print(f"Comentariu adăugat la {issue_key}: {response.status_code}")

# --- Hash functions ---
HASH_REGEX = r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b"

def extract_hashes(ticket_description):
   
    return re.findall(HASH_REGEX, ticket_description or "")

def check_hash_virustotal(hash_value, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()

        attributes = data["data"]["attributes"]

        stats = attributes.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        # File name
        names = attributes.get("names", [])
        file_name = names[0] if names else "Necunoscut"

        # File type
        file_type = attributes.get("type_description", "Necunoscut")

        # Sandbox behaviors
        sandbox = attributes.get("sandbox_verdicts", {})

        # Relations (IPs, domains, URLs)
        relations = attributes.get("relationships", {})

        return True, {
            "malicious": malicious,
            "suspicious": suspicious,
            "file_name": file_name,
            "file_type": file_type,
            "sandbox": sandbox,
            "relations": relations
        }

    elif response.status_code == 404:
        return False, f"Hash {hash_value} does not exist in VirusTotal database."

    else:
        return False, f"Eroare VirusTotal: {response.status_code} - {response.text}"

def build_investigation_comment(issue_key, hash_value, vt_data, status_text):
    user_message = f"""
Analyzed hash: {hash_value}

VirusTotal extracted data:
- File name: {vt_data.get('file_name')}
- File type: {vt_data.get('file_type')}
- Malicious engines: {vt_data.get('malicious')}
- Suspicious engines: {vt_data.get('suspicious')}
- Sandbox verdicts: {json.dumps(vt_data.get('sandbox'), indent=2)}
- Relations (IPs, domains, URLs): {json.dumps(vt_data.get('relations'), indent=2)}

  Ticket status analysis:
  {status_text}
Please generate a professional SOC-style analysis based on the data above.
The final answer MUST be written in English.
IMPORTANT: Evaluate status flags on a per‑hash basis. Each file hash represents a separate artifact with its own status.
If one hash shows ‘still present’ and another hash shows ‘deleted’, treat these as two independent file states, not as conflicting information.
Generate separate conclusions and actions for each hash. 
Ignore duplicate hashes. Perform the analysis only once per unique hash, even if the same value appears multiple times in the input.
"""

    ai_text = get_ai_response(user_message, system_message_hash)
    return ai_text

# --- Main ---
if __name__ == "__main__":
    api_key = "VT API KEY"

    jql_automate_new_alert = (
        JQL QUERY
    )

    resp, issues = jql_query(jql_automate_new_alert)

    if resp == 200:
        for issue in issues.get("issues", []):
            issue_key = issue["key"]
            description_html = issue.get("renderedFields", {}).get("description", "") 
            description = strip_html(description_html).lower()
            status_deleted = "deleted" in description 
            status_blocked = "blocked" in description 
            status_present = "still present" in description
            status_text = f""" 
            Status flags detected:
            - deleted: {status_deleted}
            - blocked: {status_blocked}
            - still present: {status_present}
            """

            print(f"{issue_key} descriere: {description}")

            hash_list = extract_hashes(description)

            if hash_list:
                 for hash_value in list(set(hash_list)): 
                     exists, vt_data = check_hash_virustotal(hash_value, api_key)
                     if exists:
                        comment = build_investigation_comment(issue_key, hash_value, vt_data, status_text)
                        add_comment(issue_key, comment)
                     else:
                        print(f"{issue_key}: Hash {hash_value} does not exist in VirusTotal database.")
            else:
                 print(f"{issue_key}: There is no hash found in the description.")

    else:
        print("Jira error:", resp)