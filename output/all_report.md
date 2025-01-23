# Vulnerability Analysis Report - SOURCES
Generated: 2025-01-23 18:53:47
Total Vulnerabilities Analyzed: 40

## Vulnerabilities by Technology

### Paxton Net2

- [Access Control in Paxton Net2 software](https://seclists.org/fulldisclosure/2024/Dec/0) ((Dec 02)) [Full Disclosure]
    - Unspecified access control vulnerability.

### Microsoft PlayReady (Warbird/PMP)

- [Microsoft Warbird and PMP security research - technical doc](https://seclists.org/fulldisclosure/2024/Dec/1) (Security Explorations (Dec 03)) [Full Disclosure]
    - Compromise of PlayReady due to wrong assumptions about code obfuscation, crypto, and OS kernel integration leading to content key sniffer operation.

### Image Access Scan2Net

- [SEC Consult SA-20241204-0 :: Multiple Critical Vulnerabilities in Image Access Scan2Net (14 CVE)](https://seclists.org/fulldisclosure/2024/Dec/2) ((Dec 04)) [Full Disclosure]
    - Multiple critical vulnerabilities in firmware <=7.40, <=7.42, <7.42B, including CVE-2024-28138, CVE-2024-28139, CVE-2024-28140, CVE-2024-28141, CVE-2024-28142, CVE-2024-28143, CVE-2024-28144, CVE-2024-28145, CVE-2024-28146, CVE-2024-47946, CVE-2024-47947, CVE-2024-36498, CVE-2024-36494, CVE-2024-50584.

### ORing IAP-420

- [St. Poelten UAS | Multiple Vulnerabilities in ORing IAP](https://seclists.org/fulldisclosure/2024/Dec/3) ((Dec 12)) [Full Disclosure]
    - Multiple vulnerabilities in version 2.01e, including CVE-2024-55544, CVE-2024-55545, CVE-2024-55546, CVE-2024-55547, CVE-2024-55548.

### Numerix License Server Administration System Login

- [SEC Consult SA-20241211-0 :: Reflected Cross-Site Scripting in Numerix License Server Administration System Login](https://seclists.org/fulldisclosure/2024/Dec/4) ((Dec 12)) [Full Disclosure]
    - Reflected Cross-Site Scripting (XSS) vulnerability (CVE-2024-50585) allows arbitrary JavaScript execution via malicious links.

### RansomLordNG

- [RansomLordNG - anti-ransomware exploit tool](https://seclists.org/fulldisclosure/2024/Dec/14) (malvuln (Dec 16)) [Full Disclosure]
    - Anti-ransomware tool that dumps process memory of targeted malware prior to termination. Leverages code execution vulnerabilities.

### GFI Kerio Control

- [[KIS-2024-07] GFI Kerio Control <= 9.4.5 Multiple HTTP Response Splitting Vulnerabilities](https://seclists.org/fulldisclosure/2024/Dec/15) (Egidio Romano (Dec 16)) [Full Disclosure]
    - Multiple HTTP Response Splitting vulnerabilities in versions <= 9.4.5 via the 'dest' GET parameter. May lead to Reflected XSS and RCE.

### Broadcom CA Client Automation (CA DSM)

- [[SYSS-2024-085]: Broadcom CA Client Automation - Improper Privilege Management (CWE-269)](https://seclists.org/fulldisclosure/2024/Dec/16) ((Dec 18)) [Full Disclosure]
    - Improper Privilege Management (CWE-269) allows low-privileged users to extract cryptographic keys used to encrypt sensitive configuration data (CVE-2024-38499).

### blogenginev3.3.8

- [Stored XSS with Filter Bypass - blogenginev3.3.8](https://seclists.org/fulldisclosure/2024/Dec/17) (Andrey Stoykov (Dec 18)) [Full Disclosure]
    - Stored Cross-Site Scripting (XSS) vulnerability with filter bypass allows arbitrary JavaScript execution.

### Ewon Flexy 205

- [CyberDanube Security Research 20241219-0 | Authenticated Remote Code Execution in Ewon Flexy 205](https://seclists.org/fulldisclosure/2024/Dec/18) ((Dec 21)) [Full Disclosure]
    - Authenticated Remote Code Execution vulnerability (CVE-2024-9154) allows gaining root access via Java applications.

### IBMi Navigator

- [IBMi Navigator / CVE-2024-51463 / Server Side Request Forgery	(SSRF)](https://seclists.org/fulldisclosure/2024/Dec/19) (hyp3rlinx (Dec 30)) [Full Disclosure]
    - Server Side Request Forgery (SSRF) vulnerability (CVE-2024-51463) allows sending unauthorized requests, potentially leading to network enumeration.

- [IBMi Navigator / CVE-2024-51464 / HTTP Security Token Bypass](https://seclists.org/fulldisclosure/2024/Dec/20) (hyp3rlinx (Dec 30)) [Full Disclosure]
    - HTTP Security Token Bypass vulnerability (CVE-2024-51464) allows attackers to modify existing tokens to bypass restrictions.

### CTFd

- [Multiple vulnerabilities in CTFd versions <= 3.7.4](https://seclists.org/fulldisclosure/2024/Dec/21) (Blazej Adamczyk (Dec 30)) [Full Disclosure]
    - Multiple vulnerabilities in versions <= 3.7.4, including CVE-2024-11716 allowing users to change bracket without admin privileges.

### Bruno IDE Desktop

- [CyberDanube Security Research 20250107-0 | Multiple Vulnerabilities in ABB AC500v3](https://seclists.org/fulldisclosure/2025/Jan/6) ((Jan 15)) [Full Disclosure]
    - Command Injection vulnerability in versions prior to 1.29.0 (CWE-78) via crafted URLs, leading to potential remote code execution.

### Asterisk

- [CVE-2024-48463](https://seclists.org/fulldisclosure/2025/Jan/7) ((Jan 15)) [Full Disclosure]
    - Path traversal vulnerability via AMI ListCategories allows access to outside files (GHSA-33x6-fj46-6rfh).

### Fedora Repository

- [CVE-2025-23012](https://nvd.nist.gov/vuln/detail/CVE-2025-23012) (January 23, 2025) [NIST]
    - CVE-2025-23012: Includes service account with default credentials, allowing local file reads.

- [CVE-2025-23011](https://nvd.nist.gov/vuln/detail/CVE-2025-23011) (January 23, 2025) [NIST]
    - CVE-2025-23011: Path traversal via Zip Slip allows arbitrary JSP file extraction.

### Directus

- [CVE-2025-24353](https://nvd.nist.gov/vuln/detail/CVE-2025-24353) (January 23, 2025) [NIST]
    - CVE-2025-24353: User can specify arbitrary role when sharing an item to see otherwise invisible fields.

### Himmelblau

- [CVE-2025-24034](https://nvd.nist.gov/vuln/detail/CVE-2025-24034) (January 23, 2025) [NIST]
    - CVE-2025-24034: Credentials leakage in debug logs (user access tokens and Kerberos TGTs).

### @fastify/multipart

- [CVE-2025-24033](https://nvd.nist.gov/vuln/detail/CVE-2025-24033) (January 23, 2025) [NIST]
    - CVE-2025-24033: `saveRequestFiles` function does not delete uploaded temporary files when user cancels the request.

### IBM Tivoli Application Dependency Discovery Manager

- [CVE-2025-23227](https://nvd.nist.gov/vuln/detail/CVE-2025-23227) (January 23, 2025) [NIST]
    - CVE-2025-23227: Stored cross-site scripting vulnerability.

### RestrictedPython

- [CVE-2025-22153](https://nvd.nist.gov/vuln/detail/CVE-2025-22153) (January 23, 2025) [NIST]
    - CVE-2025-22153: Type confusion bug allows bypass when using try/except* clauses.

### Unspecified Product

- [CVE-2024-55930](https://nvd.nist.gov/vuln/detail/CVE-2024-55930) (January 23, 2025) [NIST]
    - CVE-2024-55930: Weak default folder permissions.

- [CVE-2024-55929](https://nvd.nist.gov/vuln/detail/CVE-2024-55929) (January 23, 2025) [NIST]
    - CVE-2024-55929: Mail spoofing.

- [CVE-2024-55928](https://nvd.nist.gov/vuln/detail/CVE-2024-55928) (January 23, 2025) [NIST]
    - CVE-2024-55928: Clear text secrets returned & Remote system secrets in clear text.

- [CVE-2024-55927](https://nvd.nist.gov/vuln/detail/CVE-2024-55927) (January 23, 2025) [NIST]
    - CVE-2024-55927: Flawed token generation implementation & Hard-coded key implementation.

- [CVE-2024-55926](https://nvd.nist.gov/vuln/detail/CVE-2024-55926) (January 23, 2025) [NIST]
    - CVE-2024-55926: Arbitrary file upload, deletion and read through header manipulation.

- [CVE-2024-52329](https://nvd.nist.gov/vuln/detail/CVE-2024-52329) (January 23, 2025) [NIST]
    - CVE-2024-55925: API Security bypass through header manipulation.

### IBM Security Verify Bridge

- [CVE-2024-45672](https://nvd.nist.gov/vuln/detail/CVE-2024-45672) (January 23, 2025) [NIST]
    - CVE-2024-45672: Local privileged user can overwrite files due to excessive privileges granted to the agent, causing denial of service.

### Open Virtual Network (OVN)

- [CVE-2025-0650](https://nvd.nist.gov/vuln/detail/CVE-2025-0650) (January 23, 2025) [NIST]
    - CVE-2025-0650: UDP packets may bypass egress ACLs, leading to unauthorized access.

### ECOVACS Robot Lawn Mowers and Vacuums

- [CVE-2024-55925](https://nvd.nist.gov/vuln/detail/CVE-2024-55925) (January 23, 2025) [NIST]
    - CVE-2024-52331: Deterministic symmetric key to decrypt firmware updates allows malicious firmware creation.

- [CVE-2024-52331](https://nvd.nist.gov/vuln/detail/CVE-2024-52331) (January 23, 2025) [NIST]
    - CVE-2024-52330: Improper TLS certificate validation allows reading/modifying TLS traffic and firmware updates.

- [CVE-2024-52330](https://nvd.nist.gov/vuln/detail/CVE-2024-52330) (January 23, 2025) [NIST]
    - CVE-2024-52328: Audio files insecurely stored, allowing modification/deletion of camera-on warnings.

- [CVE-2024-52328](https://nvd.nist.gov/vuln/detail/CVE-2024-52328) (January 23, 2025) [NIST]
    - CVE-2024-52327: Cloud service allows bypassing PIN entry to access live video feed.

### ECOVACS HOME Mobile App Plugins

- [CVE-2024-52329](https://nvd.nist.gov/vuln/detail/CVE-2024-52329) (January 23, 2025) [NIST]
    - CVE-2024-52329: Improper TLS certificate validation allows reading/modifying TLS traffic and obtaining authentication tokens.

### ECOVACS Robot Lawn Mowers and Vacuums

- [Access Control in Paxton Net2 software](https://seclists.org/fulldisclosure/2024/Dec/0) ((Dec 02)) [Full Disclosure]
    - Stores anti-theft PIN in cleartext on the device filesystem.

- [Microsoft Warbird and PMP security research - technical doc](https://seclists.org/fulldisclosure/2024/Dec/1) (Security Explorations (Dec 03)) [Full Disclosure]
    - Uses a shared, static secret key to encrypt BLE GATT messages.

- [SEC Consult SA-20241204-0 :: Multiple Critical Vulnerabilities in Image Access Scan2Net (14 CVE)](https://seclists.org/fulldisclosure/2024/Dec/2) ((Dec 04)) [Full Disclosure]
    - Uses a deterministic root password generated based on model and serial number.

### basteln3rk Save & Import Image from URL

- [St. Poelten UAS | Multiple Vulnerabilities in ORing IAP](https://seclists.org/fulldisclosure/2024/Dec/3) ((Dec 12)) [Full Disclosure]
    - Reflected Cross-Site Scripting (XSS) vulnerability.

### wp-flickr-press

- [SEC Consult SA-20241211-0 :: Reflected Cross-Site Scripting in Numerix License Server Administration System Login](https://seclists.org/fulldisclosure/2024/Dec/4) ((Dec 12)) [Full Disclosure]
    - Reflected Cross-Site Scripting (XSS) vulnerability.


## Security Trends Analysis

### Increase in vulnerabilities related to TLS certificate validation
**Impact**: Man-in-the-middle attacks, data breaches, and compromised firmware updates

### Continued prevalence of Cross-Site Scripting (XSS) and Command Injection vulnerabilities
**Impact**: Remote code execution, data theft, and defacement of web applications

### Insecure Storage of Secrets and Credentials
**Impact**: Exposed sensitive information leading to unauthorized access

### Rise in API Security bypasses
**Impact**: Unauthorized access to data and functionality, potentially leading to data breaches and service disruptions

### Vulnerabilities in IoT devices related to weak security practices.
**Impact**: Compromise of devices, data theft, and potential for botnet recruitment.

### Increase in Cross-Site Scripting (XSS) vulnerabilities in web applications.
**Impact**: Allows attackers to inject malicious scripts into websites, potentially stealing user data or performing unauthorized actions.

