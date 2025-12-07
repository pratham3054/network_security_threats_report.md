Network Security Threats — Research Report

Author: Pratham Lad
Date: 2025-12-07
Objective: Provide a comprehensive overview of common network security threats (DoS/DDoS, Man-in-the-Middle, spoofing), explain how they work, show real-world examples, and recommend mitigations and best practices.

Executive Summary

Networks are subject to many threats that can impact confidentiality, integrity, and availability. This report focuses on three high-impact classes — Denial of Service (DoS/DDoS), Man-in-the-Middle (MITM), and spoofing — and also covers closely related network threats (ARP/DNS poisoning, packet sniffing, replay attacks, ransomware delivery over networks). For each threat we describe attack mechanics, impact, detection, mitigation, and present real-world examples. The report ends with a prioritized checklist for defenders.

Table of Contents

DoS and DDoS Attacks

Man-in-the-Middle (MITM) Attacks

Spoofing (IP, ARP, DNS)

Related Network Threats (Sniffing, Replay, Ransomware over network)

Detection & Monitoring Best Practices

Mitigations — Technical and Administrative Controls

Case Studies (short)

Actionable Checklist & Recommendations

References & Further Reading

1. Denial of Service (DoS) and Distributed Denial of Service (DDoS)
What it is

A DoS attack attempts to make a networked service unavailable to legitimate users by overwhelming resources (CPU, memory, bandwidth, application threads). A DDoS uses many distributed systems (botnets) to scale attack volume.

How it works (common vectors)

Volumetric attacks: Flood the target with excessive traffic (UDP floods, amplification e.g., DNS/SMB/NTP reflection).

Protocol attacks: Consume server or firewall resources (SYN flood, fragmentation attacks).

Application layer attacks: Target specific application endpoints (HTTP GET/POST floods, slowloris) to exhaust application threads.

Impact

Service downtime and business disruption.

Revenue loss, SLA violations, reputational damage.

Collateral damage to upstream infrastructure (ISP congestion).

Detection

Sudden spikes in traffic or flows from many sources.

Increased error rates (503), high CPU/connection usage, abnormal packet sizes or protocols.

Netflow/sFlow anomalies.

Mitigation

Preventive: Overprovision bandwidth, redundant infrastructure, geo/load balancing, anycast.

Reactive: DDoS scrubbing services (Cloudflare, Akamai, AWS Shield), rate limiting, blackholing/sinkholing, WAF rules for application attacks.

Long-term: Use CDN and scalable cloud services, implement network-level filtering at edge, maintain incident playbooks.

Real-world example

GitHub DDoS (2018): Massive memcached amplification DDoS peaked at 1.35 Tbps; mitigated using scrubbing and edge filtering.

2. Man-in-the-Middle (MITM) Attacks
What it is

An attacker intercepts and potentially alters communication between two parties without their knowledge, compromising confidentiality and integrity.

How it works (common techniques)

ARP spoofing/poisoning: Attacker tricks hosts in a LAN into sending traffic through the attacker’s machine.

DNS spoofing / cache poisoning: Redirects domain requests to malicious IPs.

Rogue Wi-Fi / Evil Twin: Attacker provides a malicious wireless AP to intercept traffic.

TLS stripping / downgrades: Forcing unencrypted connections or presenting fake certificates to intercept content.

Impact

Credential theft, session hijacking, data exfiltration, content tampering, malware injection.

Detection

Unexpected certificate changes/warnings, duplicate IP/MAC detection, sudden change in DNS resolution, alerts from IDS/IPS for ARP anomalies.

Mitigation

Encrypt everything: Enforce TLS (HTTPS everywhere), HSTS, certificate pinning where feasible.

Network hygiene: Use dynamic ARP inspection, DHCP snooping, and switch port security in enterprise networks.

Authentication & verification: Multi-factor authentication, DNSSEC for DNS integrity, use secure DNS (DoT/DoH) where appropriate.

User awareness: Avoid untrusted Wi-Fi; check certificate warnings.

Real-world example

NSA and others (historical): State-level actors exploited MITM techniques and BGP/DNS manipulation to intercept traffic.

3. Spoofing (IP, ARP, DNS)
What it is

Spoofing is the fabrication of identity information (IP address, MAC/ARP entries, DNS records) to impersonate another host or service.

How it works

IP spoofing: Crafting packets with a forged source IP (used in reflection/amplification DDoS and to bypass IP-based ACLs).

ARP spoofing: Poisoning ARP tables to associate the attacker’s MAC with another host’s IP.

DNS spoofing: Altering DNS responses or caches to resolve domains to attacker-controlled IPs.

Impact

Traffic redirection, unauthorized access, man-in-the-middle, amplification in DDoS.

Detection

IP/MAC mismatches, multiple hosts claiming same IP, unusual DNS answers, monitoring for asymmetric routing.

Mitigation

Ingress/egress filtering (BCP38): Block spoofed source addresses at network edge.

ARP defenses: Use static ARP entries for critical hosts, dynamic ARP inspection (on managed switches).

DNS security: DNSSEC, monitor DNS changes, restrict zone transfers, use secure DNS resolvers.

4. Related Network Threats
Packet sniffing (eavesdropping)

How: Capture packets on a network segment (promiscuous mode, compromised switch/span port).

Impact: Cleartext credentials and private data leakage.

Mitigation: Use link encryption (TLS), secure management interfaces, avoid plaintext protocols (use SSH not Telnet).

Replay attacks

How: Attacker captures valid traffic and replays it to gain unauthorized actions.

Mitigation: Use session tokens with nonces/timestamps, TLS, and replay protection at protocol level.

Ransomware distribution via network

How: Lateral movement using exposed SMB, weak RDP, or credential reuse.

Mitigation: Network segmentation, patching, MFA, EDR/antivirus, restrict SMB exposure.

5. Detection & Monitoring Best Practices

Network visibility: NetFlow/IPFIX, sFlow, packet capture on demand.

Centralized logs: Syslog, SIEM to correlate network and host events.

Anomaly detection: Baseline normal behavior, use ML/behavioral analytics for abnormal flows.

Honeypots & deception: Detect reconnaissance and early compromise.

IDS/IPS: Signature and anomaly-based detection (Suricata, Snort).

6. Mitigations — Technical and Administrative Controls
Network Controls

Firewall rules and ACLs (least privilege).

Edge filtering and DDoS mitigation services.

Network segmentation and VLANs.

Enforce strong cryptography (TLS 1.2+/cipher suites).

Secure DNS (DNSSEC) and secure DHCP.

Host & Application Controls

Patch management; reduce attack surface.

Use authenticated encryption, HSTS, CSP for web apps.

Secure authentication (MFA, password policies, rotate keys).

Operational & Policy Controls

Incident response plan covering DDoS/MITM scenarios.

Regular vulnerability scanning and penetration testing.

Employee training for phishing and social engineering.

Backup and recovery processes, offline backups for ransomware resilience.

7. Case Studies (short)
Case: Mirai Botnet (2016)

What happened: IoT devices with default credentials were co-opted into a botnet and used for massive DDoS attacks (Dyn outage impacted major websites).

Lesson: Device hardening, change default credentials, and IoT network segmentation.

Case: BGP Hijacking incidents

What happened: Misconfiguration or malicious announcements redirected traffic through unauthorized ASes.

Lesson: Route origin validation (RPKI) and monitoring for BGP anomalies.

8. Actionable Checklist & Prioritization

Immediate (within days)

Block public exposure of management ports (SSH, RDP, SMB).

Enforce strong passwords and MFA for remote access.

Enable TLS for web services and HSTS.

Short-term (weeks)

Deploy network monitoring (NetFlow) and basic IDS.

Configure UFW/firewall rules, disable insecure services.

Patch critical systems (OS, web server, DB).

Long-term (months)

Onboard DDoS scrubbing/edge CDNs for high-value services.

Implement segmentation, RPKI for routing security, DNSSEC where feasible.

Conduct regular tabletop exercises and red-team tests.

9. References & Further Reading

OWASP — Top 10 and network security guidance.

RFC 2827 / BCP38 — Network ingress filtering.

CERT/US and vendor advisories for DDoS incidents.

Project references: Suricata, Snort, Zeek (for network monitoring).
