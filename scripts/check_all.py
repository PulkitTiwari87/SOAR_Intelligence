import urllib.request
import urllib.error
import ssl

context = ssl._create_unverified_context()

endpoints = {
    "Wazuh Manager API (55000)": "https://localhost:55000",
    "Wazuh Dashboard (443)": "https://localhost",
    "TheHive (9000)": "http://localhost:9000",
    "Cortex (9001)": "http://localhost:9001",
    "MISP (8080)": "http://localhost:8080",
    "Elasticsearch (9201)": "http://localhost:9201"
}

print("Running Connectivity Check...\n")
for name, url in endpoints.items():
    try:
        req = urllib.request.Request(url, method="GET")
        response = urllib.request.urlopen(req, context=context, timeout=5)
        print(f"✅ {name}: ONLINE (HTTP {response.status})")
    except urllib.error.HTTPError as e:
        # 4xx or 5xx codes still mean the service is reachable
        print(f"✅ {name}: ONLINE (HTTP {e.code})")
    except Exception as e:
        print(f"❌ {name}: OFFLINE/ERROR ({e})")
