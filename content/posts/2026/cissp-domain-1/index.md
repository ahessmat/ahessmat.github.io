---
title: "Studying for the CISSP: Domain 1"
draft: true
date: 2026-05-25
summary: "My notes on studying for the CISSP, domain 1"
tags: [exam,certification,resources]     # TAG names should always be lowercase
---

## Introduction

ISC2's flagship certification, the Certified Information Systems Security Professional (CISSP) is arguably the [most oft-requested certification across all job roles in cybersecurity]({{< relref "/posts/2023/what-certifications-should-you-get" >}}). It's a bear of an exam to study for, spanning an enormous breadth of testable material and being administered as an adaptive exam (meaning the exam's algorithms identify which areas you struggle in most and serves you questions in those areas more often than your stronger ones).

While I've met [the exam's years-of-experience prerequisite](https://www.isc2.org/certifications/cissp/cissp-experience-requirements) for several years now, studying for this exam has always felt like a chore to me; each time I've cracked open the book to study, I've been put to sleep (sometimes literally) from how dry and abstract the material has struck me as being. However, I want to turn over a new leaf; I want this cert - for as much as I might point to the myriad of other credentials I have, I recognize attaining this certification can only benefit my employability under conditions where [finding work can be extraordinarily challenging]({{< relref "/posts/2025/where-are-all-the-cybersecurity-jobs" >}}).

To that end, I'm going to catalog my lessons learned from the [Destination CISSP](https://www.amazon.com/Destination-CISSP-Concise-Rob-Witcher/dp/B0D37YPGPZ) (DCISSP) study materials. As stated above, these posts are largely going to be self-serving, since I'm trying to use the act of blogging to reinforce committing the lessons-learned to memory. That said, I'll highlight nuances and actions where appropriate during this series that I found helpful.

So, without further ado...

## Study log

* `26 May 2026`: 75% on DCISSP Domain 1 practice questions
  * Was thrown by the number of blockchain-related questions.
  * Got a competing definition of compensating controls
  * Didn't think through the ALE calculation correctly

* `26 May 2026` 70% on DCISSP Domain 2 Practice Quiz
  * Mistook the advantage of using AI/ML as favoring automation (vs. accuracy) when applied to destruction.
  * DCISSP didn't cover data `tokenization`: It replaces sensitive data with unique tokens that preserve data format and relationships, allowing for accurate testing while safeguarding the original information.
  * It isn't explicitly stated, but data `destruction` would be the most challenging of the data life cycle steps to securely perform in diverse international jurisdictions. Implicitly, this makes sense owing to different technological infrastructures and data destruction resource availability.
  * I got a question concerning which algoritm is best for data in-transit, which ultimately was AES. While I should know better given my experience, I do note that cryptography isn't covered until Domain 3.

* `29 May 2026` 75% on DCISSP Domain 3 Practice Quiz
  * Messed up on 2 lighting-related questions
  * Need to lookup what `Service Workers` are.
  * Need to lookup what Over-the-Air (OTA) updates involve

* `29 May 2026` 80% on DCISSP Overall Practice Quiz

* `29 May 2026` 76% Domain 1 Official Practice
  * Hadn't heard of `the prudent man rule`. It requires senior executives to take personal responsibility for ensuring the due care that ordinary, prudent individuals would exercise in the same situation.
  * Canon IV of CISSP allows any certified or licensed professional to bring ethics charges agains other CISSP holders.
  * The `Gramm-Leach-Bliley Act (GLBA)` contains laws specifically to financial institutions. By contrast, the `Sarbanes Oxley (SOX)` Act regulates the financial reporting activities of publicly traded companies.
  * The `Federal Information Security Management Act (FISMA)` specifically applies to government contracts. `GISRA` predates FISMA and was effectively replaced by the latter.
  * The `Economic Espionage Act` imposes fines/jail sentences on anyone found guilty of stealing trade secrets from a US corporation.
  * It's important to distinguish a `business continuity plan` apart from a `disaster recovery plan`. The former keeps operations going during a disruption, the latter is a subset of the BCP for restoring services after an event.
  * A `security controls assessment (SCA)` often refers to a formal US gov't process, typically paired with a `Security Test and Evaluation (ST&E)`.
  * The `Code of Federal Regulations (CFR)` contains the text of all admin law promulgated by federal agencies.
  * The `Risk Maturity Model (RMM)` is specifically designed for the purpose of assessing enterprise risk management programs.
  * The `Children's Online PRivacy Protection Act (COPPA)` requires websites obtain avdvance parental consent for children under the age of 13.

* `1 June 2026` 68% Domain 2 Official Practice
  * `Business Owners` are a data management role; they balance security controls against business reqs.
  * `Adminitrators` are a data management role; they grant permissions to access/handle data.
  * `Data Processors` are typiucally third parties that process data.
  * A `data retention policy` helps reduce liabilities by ensuring uneeded data isn't retained.
  * `Clearing` describes preparing media for reuse (writing over all addressable locations for same security level of use).
  * `Erasing` describes deleting files (but may not get all data).
  * `Purging` describes intensive clearing for reuse in lower-security areas.
  * `Sanitization` describes a series of processes that removes data while ensuring its unrecoverable.
  * `DLP` detects for data in-transit, not data at-rest (that would need a sensitive data scanning tool).
  * Industry security ratings from highest-to-lowest: `Proprietary`/`Confidential`, `Private` (e.g. PHI), `Sensitive` (internal), `Public` (who cares)
  * `Scoping`: selecting control appropriate for your system.
  * `Tailoring`: matches org's mission to controls from a baseline.
  * `Baselining`: configuring a system to match a baseline (or building the baseline)
  * `EOS`: ending support, ready for secure disposal, destruction, or resale. Comes after EOL.
  * `EOL`: no longer made/supported, including via patches, upgrades, or org mx.
  * Downgrading a secure system for reuse is risky and expensive; it's hard to assure that no remnant data exists.
  * The best method for sanitizing SSDs is physical destruction.

* `1 June 2026` 72% Domain 3 Official Practice
  * `Brewer-Nash`: model allows access controls to change dynamically based upon user's actions (Chinese Firewall). Blocks lower-classified objects from accessing higher-classified objects (CONFIDENTIALITY)
  * `Biba`: model focuses only on protecting integrity (INTEGRITY), emphasizes external threats and assumes internal threats are addressed programmatically. 
  * `Clark-Wilson`: model uses security labels to grant access to objects via transformation procedures and a restricted interface model.
  * `Graham-Denning`: model focuses on secure creation/deletion of subjects and objects using 8 primary protection rules.
  * Fires may be detected at the incipient stage (pre-smoke).
  * In an `m` of `n` control system, at least m of n possible escrow agents must collaborate to retrieve an encryption key from the escrow database.
  * The `Simple Integrity Property`: an individual may not read file classified at a lower security level than their own.
  * The `*-Security Property`: individual maybit write to a file at a lower classification than their own.
  * The `*-Integrity Property`: subject cannot modify an object at a higher integrity level than their own.
  * A preaction fire suppression system activates in 2 steps. The pipes fill with water once the early sigs of fire are detected. The system does not dispense water until heat sensors on sprinkler heads trigger.
  * The `Encapsulating Security Payload (ESP)` protocol provides confidentiality/integrity for packet contents.
  * `Kerckhoff's principle`: cryptographic system should be secure even if everything about the system (except key) is public knowledge.
  * `System High Mode`: user must have a valid security clearance for all infor on system, access aproval for all info processed by the system, and a valid need to know for some (but not all) info processed by the system.
  * `Transposition`: every plaintext character is shifted, but retained (i.e. a word's letters get shuffled but not replaced/substituted)
  * `2DES` is vulnerable to `Meet-in-the-Middle`.
  * Data center humidity should be maintained between 40-60 percent
  * `Fault Injection Attack`: attacker attempts to comproimise integrity of a cryptographic device by causing some type of external fault.

* `2 June 2026` 55% Domain 4 Official Practice
  * `BitTorrent`: peer-to-peer CDN - usually used for distribute files
  * `Lightweight Extensible Auth Protocol (LEAP)`: Cisco protocol that fixes TKIP, but is vulnerable.
  * `PEAP`: provides encryption for EAP methods and can provide auth. Does not implement CCMP.
  * `802.11ac`: directly connects 2 clients in an `ad hoc` mode. `Infrastructure` mode connects endpoints to a central network. `wired extension` mode uses a wireless AP to link clients to a wired network.
  * `Collision domain`: set of systems that could cause a collision if transmitted simultaneously.
  * Need to review the 802.* protocols
  * Need to review protocols/artifacts of OSI layers
  * Need to review physical cable length speeds
  * `Challenge Handshake Auth Protocol (CHAP)`: used by PPP servers to auth remote clients encrypting username + pass.
  * `Session Initialization Protocol (SIP)` can be secured.
  * `X-tier firewall`: the depth/number of zones protected by the firewall
  * `Distance-Vector Protocol`: use metrics like directions + distance in hops to remote networks. By contrast, `link-state protocol` considers the shortest distance.
  * `FCoE`: Fibre Channel over Ethernet, a storage protocol
  * `SD-WAN`: Software-defined WAN.
  * `LiFi`: uses light to transmit data at high speeds.
  * `Zigbee`: low-poer wireless protocol.Uses AES.
  * `WPA3`: an upgrade over WPA2; SAE mode allows for secure auth between clients and network without enterprise user accounts.
  * SMS messages are not encrypted.
  * `iSCI`: converged protocol that allows location-independent file services over traditional network.
  * `Multi-layer protocols`: they conceal covert channels, filters can be bypassed, and logical boundaries put in place by network segments can be bypassed under some circumstances. They allow encryption at various layers.
  * `Converged protocols`: combine specialized protocols with standard protocols like TCP/IP.
  * `IPsec`: provides encrption, access control, nonrepudiation, and message auth.
  * `Port security`: prevents unrecognized/unpermitted systems from connecting to a network port based on MAC address.
  * Common VPN protocols: PPTP, L2F, L2TP, TLS, and IPsec.
  * `VXLAN`: encapsulation protocol that carries VLAN across routable networks, making 2 network locations appear to be in the same segment.
  * Pre-admit, client-based NAC?

|802.* standard|Data rates|Frequencies|Notes|
|-|-|-|-|
|802.11|2Mbps|2.4||
|802.11a|54Mbps|5||
|802.11b|11Mbps|2.4||
|802.11g|54Mbps|2.4||
|802.11n|600Mbps|2.4 or 5||
|802.11ac|3.5Gbps|5|Supports direct connection between 2 hosts in `ad hoc` mode|
|802.11ax|9.6Gbps|1-7.125Gbps||
|802.11be|40Gbps|1-7.25||

*"Please Do Not Throw Sausage Pizza Away"*

|Layer|Container|Devices & Protocols|TCP/IP|
|-|-|-|-|
|Application|Protocol data unit|Application Firewall, HTTP, DNS, SSH, SNMP, FTP|Application|
|Presentation|Protocol data unit|XML, JPEG, ANSI||
|Session|Proocol data unit|Circuit Proxy Firewalls||
|Transport|Segment / Datagram|TCP/UDP, iSCSI|Transport|
|Network|Packet|Routers, Packet Filtering Firewalls, IP addresses, ICMP, NAT|Internet|
|Data Link|Frame|Switches, bridges, MAC addresses, L2TP, PPTP|Link|
|Physical|Bits|Hubs, NICs, Network media||