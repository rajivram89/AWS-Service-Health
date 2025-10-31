import feedparser
import requests
from io import BytesIO
import os

# Static RSS XML content
rss_content = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>AWS Service Health - US East (N. Virginia) - Amazon S3</title>
    <link>https://status.aws.amazon.com/rss/s3-us-east-1.rss</link>
    <description>Updates on the health of Amazon S3 in US East (N. Virginia)</description>
    <language>en-us</language>
    <pubDate>Thu, 30 Oct 2025 12:00:00 CDT</pubDate>
    <lastBuildDate>Thu, 30 Oct 2025 12:30:00 CDT</lastBuildDate>
    <item>
      <title>Service Issue: Amazon S3 - Increased Error Rates (US East)</title>
      <link>https://status.aws.amazon.com/#s3_us-east-1_20251030_1</link>
      <description>We are investigating increased error rates and latencies for Amazon S3 in the US East (N. Virginia) region. We are working to resolve the issue and will provide updates as they become available.</description>
      <pubDate>Thu, 30 Oct 2025 12:15:00 CDT</pubDate>
      <guid>https://status.aws.amazon.com/#s3_us-east-1_20251030_1</guid>
    </item>
  </channel>
</rss>"""

# Parse the RSS feed
feed = feedparser.parse(rss_content)

# Print feed title and entries
print(f"Feed Title: {feed.feed.title}\n")

token_invoked = False

for entry in feed.entries:
    print(f"Title: {entry.title}")
    print(f"Published: {entry.published}")
    print(f"Link: {entry.link}")
    print(f"Summary: {entry.summary}\n")

    # If title exists, invoke token API once
    if entry.title and not token_invoked:
        token_url = "https://preprod.ustsmartops.ai/paas/itops/keycloak/auth/realms/cloudopsbcbsa/protocol/openid-connect/token"
        payload = {
            'username': os.getenv("USERNAME"),
            'password': os.getenv("PASSWORD"),
            'client_id': 'smartops-frontend',
            'grant_type': 'password'
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        response = requests.post(token_url, data=payload, headers=headers, verify=False)  # verify=False for SSL issues

        if response.status_code == 200:
            token = response.json().get("access_token")
            print("Access Token:", token)
        else:
            print("Failed to retrieve token:", response.status_code, response.text)

        token_invoked = True




