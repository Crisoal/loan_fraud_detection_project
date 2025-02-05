import requests

def get_fingerprint(api_key, device_info):
    url = "https://api.fpjs.io/v2/identify"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(url, json=device_info, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return None

# Usage
device_info = {
    "ip": "127.0.0.1",
    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.3",
    "acceptLanguage": "en-US,en;q=0.9",
    "timezone": "America/New_York"
}

result = get_fingerprint("bxzstxvClPmKDkucQSSW", device_info)
print(result)