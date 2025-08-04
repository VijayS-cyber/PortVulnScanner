# PortVulnScanner
A comprehensive toolkit and knowledge base focused on the security risks, usage, and monitoring of critical network ports, including 135 (RPC), 139 (NetBIOS/SMB), 445 (SMB over TCP), and 903 (VMware Remote Console).

nmap tcp synscan
C:\Users\sunil>nmap -sS 192.168.31.19
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-04 18:59 India Standard Time
Nmap scan report for SunilVijay.lan (192.168.31.19)
Host is up (0.00029s latency).
Not shown: 996 closed tcp ports (reset)
PORT    STATE SERVICE
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
903/tcp open  iss-console-mgr

Nmap done: 1 IP address (1 host up) scanned in 0.80 seconds

These ports play essential roles in Windows and virtualization environments but also represent significant attack surfaces frequently targeted by malware, ransomware, and threat actors for remote code execution, data breaches, and lateral movement within networks.


Here are the common services running on each of the specified ports:

Port 135 – Windows Remote Procedure Call (RPC) Endpoint Mapper

Used primarily by the Windows RPC Endpoint Mapper service.

Enables remote procedure calls and is crucial for communication in Windows environments.

Associated with Active Directory, Windows Management Instrumentation (WMI), DCOM applications, and other remote management services.


Port 139 – NetBIOS Session Service (SMB over NetBIOS)

Provides session services for the Server Message Block (SMB) protocol over NetBIOS, typically used for file and printer sharing in Windows networks.

Facilitates NetBIOS name resolution, network browsing, and legacy SMB applications.

Supports Windows file/print sharing, remote administration, and various older network applications.


Port 445 – Server Message Block (SMB) over TCP

Dedicated to SMB protocol for file, directory, and printer sharing using TCP.

Used by Active Directory and for direct file sharing between computers without needing NetBIOS.

Vital for Windows inter-process communication and resource access.


Port 903 – VMware Remote Console (VMRC) / Java Application Monitoring

Commonly used for VMware Remote Console (VMRC) to provide direct console access and management for virtual machines, allowing low-level administrative control.

Also sometimes used for remote monitoring and management of distributed Java applications.

In VMware setups, the VMRC client connects to ESXi/vCenter hosts through this port.



Here are the potential security risks associated with each port:

Port 135 (RPC Endpoint Mapper)

Remote Code Execution (RCE): Attackers can exploit vulnerabilities to remotely execute arbitrary code or commands, often leading to full system compromise.

Worms and Malware: Well-known malware such as the Blaster and Sasser worms specifically targeted this port.

Unauthorized Access: Open port 135 can be exploited to gain access to sensitive data and internal Windows services.

DDoS Attacks and Amplification: It is susceptible to Distributed Denial of Service (DDoS) attacks if exposed to the internet.

Lateral Movement: Attackers use it for lateral movement within networks via tools like PsExec and DCE/RPC.


Port 139 (NetBIOS Session Service, SMB)

Ransomware and Worms: Ransomware such as WannaCry and other worms can propagate through open 139.

Remote Access Trojans: Attackers may exploit the port to run remote access Trojans (RATs).

Man-in-the-Middle Attacks: NetBIOS traffic is typically unencrypted, allowing data and credentials to be intercepted.

Unauthorized Data Access: Hackers can exploit 139 to access file and print shares without proper authorization.

DDoS Attacks: Can be used for DDoS or reflection attacks if not properly secured.


Port 445 (SMB over TCP)

Ransomware (e.g., WannaCry, NotPetya): Attackers exploited SMB vulnerabilities to spread ransomware globally.

Remote Code Execution: Exploits such as EternalBlue allow attackers to run code on vulnerable systems.

Credential Theft and Lateral Movement: Attackers capture NTLM hashes or relay authentication to move within the network.

Botnet and Malware: Open 445 is routinely scanned for entry points to deploy malware and for lateral propagation.

Data Breach and Denial of Service: Can expose systems to major data breaches or DoS attacks—should never be open to the public internet.


Port 903 (VMware Remote Console/Java Management)

Unauthorized Remote Console Access: Exposing 903 may allow attackers to access the VMware Remote Console or control virtual machines if authentication is weak.

Remote Code Execution: If protocols or applications using this port have vulnerabilities, attackers could exploit them for remote access or code execution.

Information Disclosure: Unprotected use could allow monitoring or interception of remote management traffic, revealing sensitive data.

Brute Force and Reconnaissance: Like any open management port, it can be targeted for brute-force or reconnaissance attacks.


Security Recommendations

Restrict access to these ports using firewall rules; never expose them to the public internet if not required.

Regularly patch and update all systems using these ports.

Disable unused services and block unused ports.

Enable intrusion detection and multi-factor authentication for remote access.

Limit network access to trusted hosts only and monitor for unusual activity.

Misconfigured or exposed, these ports can be significant vulnerabilities and are frequently targeted by attackers for initial entry or lateral movement within networks.
