import feedparser
import requests
import hashlib
import json
import os
from dateutil import parser
from datetime import timezone, timedelta

# ----------------- Configuration -----------------
RSS_CONTENT = """<?xml version="1.0" encoding="UTF-8"?>
                <rss version="2.0">
                <channel>
                    <title>AWS Service Health - Invocation delays and elevated error rates for Lambda in the US-WEST-2 Region</title>
                    <link>https://status.aws.amazon.com/rss/Lambda-us-west-2.rss</link>
                    <description>Updates on the health of AWS Lambda in US West (Oregon)</description>
                    <language>en-us</language>
                    <pubDate>Thu, 06 Nov 2025 09:00:00 CST</pubDate>
                    <lastBuildDate>Thu, 06 Nov 2025 10:30:00 CST</lastBuildDate>
                    <item>
                    <title>Service Resolved: Invocation delays and elevated error rates for Lambda in the US-WEST-2 Region</title>
                    <link>https://status.aws.amazon.com/#Lambda-us-west-2</link>
                    <description>We are investigating increased invocation latency and elevated error rates affecting AWS Lambda in the US-WEST-2 Region. Mitigation efforts are underway.</description>
                    <pubDate>Thu, 06 Nov 2025 09:45:00 CST</pubDate>
                    <guid>https://status.aws.amazon.com/#Lambda-us-west-2-20251106094500</guid>
                    </item>
                </channel>
                </rss>"""

TOKEN_URL = "https://preprod.ustsmartops.ai/paas/itops/keycloak/auth/realms/cloudopsbcbsa/protocol/openid-connect/token"
ALERT_API_URL = "https://preprod.ustsmartops.ai/paas/itops/alertmapping/api/invokerealtime"
CORRELATION_FILE = "correlation_ids.json"

USERNAME = os.getenv("USERNAME")
PASSWORD = os.getenv("PASSWORD")
CLIENT_ID = "smartops-frontend"

# ----------------- Load Correlation Map -----------------
if os.path.exists(CORRELATION_FILE):
    with open(CORRELATION_FILE, "r") as f:
        correlation_map = json.load(f)
else:
    correlation_map = {}

# ----------------- Parse RSS Feed -----------------
feed = feedparser.parse(RSS_CONTENT)
print(f"Feed Title: {feed.feed.title}\n")

token = None
token_invoked = False

for entry in feed.entries:
    print(f"Title: {entry.title}")
    print(f"Published: {entry.published}")
    print(f"Link: {entry.link}")
    print(f"Summary: {entry.summary}\n")
    
   # Convert pubDate to datetime with microseconds
    published_dt = parser.parse(entry.published)
    cdt_offset = timezone(timedelta(hours=-5))
    published_cdt = published_dt.astimezone(cdt_offset)
    alert_time = published_cdt.strftime("%Y-%m-%d %H:%M:%S.%f")
    print(alert_time)

    # Determine severity
    severity = "Critical" if "Resolved" not in entry.title else "Ok"

    # Generate issue key and correlation ID
    issue_key = hashlib.md5(entry.title.encode()).hexdigest()
    if issue_key in correlation_map:
        correlation_id = correlation_map[issue_key]
    else:
        correlation_id = hashlib.md5((entry.title + alert_time).encode()).hexdigest()
        correlation_map[issue_key] = correlation_id

    # Save updated correlation map
    with open(CORRELATION_FILE, "w") as f:
        json.dump(correlation_map, f)

    # Token API (once)
    if not token_invoked:
        payload = {
            'username': USERNAME,
            'password': PASSWORD,
            'client_id': CLIENT_ID,
            'grant_type': 'password'
        }
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}

        response = requests.post(TOKEN_URL, data=payload, headers=headers, verify=False)
        if response.status_code == 200:
            token = response.json().get("access_token")
            print("Access Token:", token)
            token_invoked = True
        else:
            print("Failed to retrieve token:", response.status_code, response.text)
            continue

    
    # Prepare alert payload
    affected_service = feed.feed.title
    alert_body = {
        "organizationId": "20",
        "projectId": "151",
        "correlationId": correlation_id,
        "senseParams": {
            "nodeName": entry.title.split(":")[1].strip(),
            "alertMetric": "ServiceHealth",
            "alertTime": alert_time,
            "objectName": entry.summary,
            "objectStatus": "Service Down",
            "severity": severity,
            "requestReceivedTime": alert_time,
            "resourceType": "Cloud",
            "ipAddress": "",
            "alertDetailsURL": "https://health.aws.amazon.com/health/status",
            "alertMessage": entry.title,
            "alertName": affected_service + " - " + entry.title,
            "objectType": "AWS Service Status",
            "source": "AWS",
            "timezone": "UTC",
            "dateFormat": "%Y-%m-%d %H:%M:%S.%f"
        }
    }

    # Send alert
    alert_headers = {
        "Organization-name": "cloudopsbcbsa",
        "ORGANIZATION-KEY": "20",
        "User": USERNAME,
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    alert_response = requests.post(ALERT_API_URL, json=alert_body, headers=alert_headers, verify=False)
    print("Alert Response:", alert_response.status_code, alert_response.text)
