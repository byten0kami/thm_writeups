---
tags:
  - thm
  - med
  - linux-forensics
  - steganography
  - git
  - openssl
Scenario: Hunting for password fragments hidden in Linux artifacts (Env vars, Git logs, file tails) to decrypt a GPG vault.
Link: https://tryhackme.com/adventofcyber25/sidequest
---
## Quick Reference (TL;DR)

### Linux Hideouts (The "Fragments")
1.  **Environment Variables:** Secrets can persist in `.pam_environment`.
    * *Check:* `cat ~/.pam_environment` or `env`.
2.  **Git History:** Secrets deleted from files often remain in the commit log.
    * *Check:* `git log -p` (shows the patch/diff of changes).
3.  **File Tails:** Simple steganography often appends text to the end of binary files (images).
    * *Check:* `strings image.jpg | tail -n 5` or simply `tail image.jpg`.

### Key Commands
```bash
# 1. OpenSSL Decryption (AES-256-CBC)
# -pbkdf2 is crucial for newer OpenSSL versions
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -salt -base64 -in encrypted.txt -out decrypted.txt -pass pass:'PASSWORD'

# 2. View Remote Images (No Download)
# Option A: Python Server
python3 -m http.server 8000
# Option B: Base64 (Paste output into browser address bar as 'data:image/png;base64,...')
base64 image.png -w 0
```

---

## Detailed Walkthrough

So after finishing day one, there was an option to search for a key which unlocks a Side Quest:
>For those who consider themselves intermediate and want another challenge, check McSkidy's hidden note in `/home/mcskidy/Documents/` to get access to the key for **Side Quest 1**! Accessible through our [Side Quest Hub](https://tryhackme.com/adventofcyber25/sidequest)!

Of course I jumped right into it.
Following the instruction, we find a note from McSkidy:
```bash
cd /home/mcskidy/Documents/
ls -la
cat read-me-please.txt
#also, "sudo su" here allows to jump between home folders easier
```
![[Screenshot 2025-12-08 at 22.19.56.png|600]]

Encrypted message is located at `/home/eddi_knapp/Documents/`.
Also we got the credentials to another account:
`eddi_knapp:S0mething1Sc0ming`

To open the vault, we need to combine a key from 3 fragments.

Moving to eddi_knapp's folder, we see a few files and folders. Some of them are curious, like `fix_passfrag_backups_20251111162432`, `.pam_environment`, `secret`,`secret_git
![[Screenshot 2025-12-08 at 22.23.37.png|600]]

**First clue:**
*I ride with your session, not with your chest of files.*
*Open the little bag your shell carries when you arrive.*

The first riddle strongly suggested **session-based data**, not static files and **Environment Variables**, which persist during a user's session. While standard enumeration tools (`env`) came up empty, manual inspection of the home directory revealed a hidden configuration file `.pam_environment`. This non-standard file contained the first password fragment saved as variable:
``` bash
root@tbfc-web01:/home/eddi_knapp$ cat .pam_environment
PASSFRAG1="3ast3r"
```

**Second clue:**
*The tree shows today; the rings remember yesterday. 
Read the ledger’s older pages.*

The phrase "Tree shows today" hinted at a standard file structure, but "Rings remember yesterday" suggested looking below the surface. I recognized this as a reference to **Git**, where the "ledger's older pages" represent the commit log. The goal was to look back in time at changes that had been effectively "erased" from the current working tree.

Upon entering the hidden `.secret_git` directory, git refused to run due to ownership permissions (running as root in a user folder). I resolved this by switching to the user context (`su eddi_knapp` with the password found earlier) to inspect the logs properly:
![[Screenshot 2025-12-08 at 22.50.39.png|600]]

Some private note, let's check it! 
![[Screenshot 2025-12-08 at 22.51.30.png|600]]

Fragment 2 found!

**Third clue:**
*When pixels sleep, their tails sometimes whisper plain words.
Listen to the tail.*

"Pixels" clearly pointed to the `Pictures` directory. The phrase "tails sometimes whisper plain words" was a specific hint about **file appending steganography**—where text is hidden at the very end of a file. I realized I needed to read the "tail" of the image binaries to find the plaintext message.

After scanning `Pictures` folder, file `.easter_egg` got my attention:
![[Screenshot 2025-12-08 at 22.53.45.png|600]]
Third part done!
Complete passphrase is `3ast3r-1s-c0M1nG`,  let's use it!

As per the instruction,  going to `/home/eddi_knapp/Documents` to find a gpg vault `mcskidy_note.txt.gpg`.
Decrypting it with the key we got another note:
![[Screenshot 2025-12-08 at 22.59.11.png|600]]

To decode the message, I needed to pass a block of Base64 text to OpenSSL. Instead of pasting it directly (which can cause formatting errors), I used a **Heredoc** (`<< EOF`) to cleanly write the multi-line string into a temporary file before processing.
```bash
cat > /home/socmas/2025/wishlist.txt << EOF
Hardware security keys (YubiKey or similar)
Commercial password manager subscriptions (team seats)
Endpoint detection & response (EDR) licenses
Secure remote access appliances (jump boxes)
Cloud workload scanning credits (container/image scanning)
Threat intelligence feed subscription
Secure code review / SAST tool access
Dedicated secure test lab VM pool
Incident response runbook templates and playbooks
Electronic safe drive with encrypted backups
EOF
```

Proceeding to the website mentioned earlier in the task:
`10.80.145.63`
![[Screenshot 2025-12-08 at 23.06.45.png|600]]

Let's follow McSkidy's instructions, and put this code to a file
```bash
cat << EOF > /tmp/website_output.txt
U2FsdGVkX1/7xkS74RBSFMhpR9Pv0PZrzOVsIzd38sUGzGsDJOB9FbybAWod5HMsa+WIr5HDprvK6aFNYuOGoZ60qI7axX5Qnn1E6D+BPknRgktrZTbMqfJ7wnwCExyU8ek1RxohYBehaDyUWxSNAkARJtjVJEAOA1kEOUOah11iaPGKxrKRV0kVQKpEVnuZMbf0gv1ih421QvmGucErFhnuX+xv63drOTkYy15s9BVCUfKmjMLniusI0tqs236zv4LGbgrcOfgir+P+gWHc2TVW4CYszVXlAZUg07JlLLx1jkF85TIMjQ3B91MQS+btaH2WGWFyakmqYltz6jB5DOSCA6AMQYsqLlx53ORLxy3FfJhZTl9iwlrgEZjJZjDoXBBMdlMCOjKUZfTbt3pnlHWEaGJD7NoTgywFsIw5cz7hkmAMxAIkNn/5hGd/S7mwVp9h6GmBUYDsgHWpRxvnjh0s5kVD8TYjLzVnvaNFS4FXrQCiVIcp1ETqicXRjE4T0MYdnFD8h7og3ZlAFixM3nYpUYgKnqi2o2zJg7fEZ8c=
EOF
```

Using offered commands ti use OpenSSL to decrypt the ciphertext with the:
```bash
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -salt -base64 -in /tmp/website_output.txt -out /tmp/decoded_message.txt -pass pass:'91J6X7R4FQ9TQPM9JX2Q9X2Z'

cat /tmp/decoded_message.txt
```

Finding next instruction:
![[Screenshot 2025-12-08 at 23.11.37.png|600]]

Using the key `THM{w3lcome_2_A0c_2025}` to decrypt `/home/eddi_knapp/.secret/dir`

Force decrypt with password:
```bash
gpg --batch --passphrase 'THM{w3lcome_2_A0c_2025}' -d dir.tar.gz.gpg > dir.tar.gz
```
And unzip the .gz
```bash
tar -xzvf dir.tar.gz
```

Inside the unzipped `dir` we see a file `sq1.png`.
Let's try to find something about it.
Checking tail gives nothing:
```bash
strings sq1.png | tail -n 10
```

Using `cacaview` gives us an idea of the image - it's clearly an egg.
```bash
cacaview sq1.png
```

To view the final image, I hosted a python web server.
```bash
python3 -m http.server 8888
```
*Alternatively, I could have run `base64 sq1.png` and pasted the raw text directly into a browser address bar (`data:image/png;base64,...`) to view it without downloading files.*

Open the url http://10.80.145.63:8888/sq1.png in browser and here it is:
![[Pasted image 20251208233618.png|300]]
Key: `now_you_see_me`
SQ2 key: THM{HEADER_FLAG}