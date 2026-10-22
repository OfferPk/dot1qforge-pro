# Dot1qForge Pro \- User Guide & Operations Manual

> **Step-by-step operational manual for enterprise network administrators, penetration testers, and NetDevOps engineers deploying Zero-Trust IEEE 802.1Q and IEEE 802.1ad (QinQ) trunking.**

---

## 1\. Quickstart: Web Application Studio

The **Dot1qForge Pro Web Studio** is completely self-contained with zero external dependencies. Open `source-code/index.html` directly in any web browser:

\# Optional local web server

cd product\_127/source-code

python3 \-m http.server 8080

\# Open http\://localhost:8080 in your browser

### Studio Interface Overview:

1. **Industry Presets**:  
   - **Enterprise Hardened Zero-Trust Trunk (Grade A+)**: Configured with dedicated quarantine Native VLAN 999, global native tagging enabled, DTP disabled (`nonegotiate`), strict pruning, and 9216 Jumbo MTU.  
   - **Carrier QinQ Metro-Ethernet Hand-off (Grade A+)**: Configured for telecommunications service providers using 802.1ad Provider Bridging (S-TAG 500, C-TAG 100\) with 802.1p CoS 5 (Voice).  
   - **Vulnerable Default VLAN 1 DTP Hopping (Grade F)**: Replicates legacy switch configurations vulnerable to CVE-2001-1413 double-tagging hopping and DTP switch spoofing.  
2. **VLAN Tagging & Trunk Parameters**: Toggle between Single-Tagged 802.1Q and Double-Tagged 802.1ad QinQ, configure Outer/Inner VLAN IDs, 802.1p PCP CoS priority, and Interface MTU.  
3. **Native VLAN Hopping Simulator**: Simulates double-tagging attacks in real-time, verifying whether outer tags are stripped and whether frames can break out into restricted target VLANs.  
4. **DTP Switch Spoofing Simulator**: Evaluates dynamic negotiation modes (`nonegotiate`, `dynamic_desirable`, `dynamic_auto`) to detect unauthorized trunk formation risks.  
5. **10-Point Zero-Trust Scorecard**: Real-time evaluation against CIS benchmarks and NIST guidelines (0–100%, Grades A+ to F).  
6. **Wireshark Hex Dissector**: Monospace byte-aligned hex dump with 1-click clipboard copy and binary `.pcap` capture file export.  
7. **Multi-Platform Synthesizer**: Instant configuration generation for Cisco IOS-XE, Cisco Nexus NX-OS, Arista EOS, Juniper Junos, and Linux iproute2.

---

## 2\. DevSecOps Python CLI Tool Operations

The standalone Python CLI tool (`build/dot1qforge-cli.py`) operates in Linux, macOS, and Windows environments without installing external packages:

### 2.1 Packet Dissection & Wireshark Hex Dump

./build/dot1qforge-cli.py \--dissect

### 2.2 Simulating Native VLAN Double-Tagging Hopping (CVE-2001-1413)

\# Check hardened preset (Protected)

./build/dot1qforge-cli.py \--preset build/presets/enterprise-hardened-trunk.json \--hopping

\# Check vulnerable preset (Exploitable)

./build/dot1qforge-cli.py \--preset build/presets/vulnerable-vlan1-dtp-hopping.json \--hopping

### 2.3 Simulating DTP Switch Spoofing

./build/dot1qforge-cli.py \--preset build/presets/vulnerable-vlan1-dtp-hopping.json \--dtp

### 2.4 Baby Giant & Jumbo MTU Sizing Analysis

./build/dot1qforge-cli.py \--preset build/presets/carrier-qinq-metro-ethernet.json \--mtu

### 2.5 Running 10-Point Zero-Trust Layer 2 Trunking Audits

\# Audit Enterprise Hardened Trunk preset

./build/dot1qforge-cli.py \--preset build/presets/enterprise-hardened-trunk.json \--audit

\# Audit Vulnerable Default VLAN 1 preset

./build/dot1qforge-cli.py \--preset build/presets/vulnerable-vlan1-dtp-hopping.json \--audit

### 2.6 Generating Binary PCAP Capture Files

Generate standard `.pcap` files for testing packet decoders or validating with Wireshark:

./build/dot1qforge-cli.py \--preset build/presets/enterprise-hardened-trunk.json \--pcap trunk-frame.pcap

\# Inspect with tcpdump or Wireshark

tcpdump \-e \-n \-r trunk-frame.pcap

### 2.7 Automated CI/CD Pipeline Gating (`--strict`)

Integrate Dot1qForge Pro into CI/CD pipelines to validate infrastructure-as-code repository commits:

\- name: Audit Layer 2 Trunking & VLAN Hopping Defense

  run: |

    python3 build/dot1qforge-cli.py \\

      \--preset build/presets/switch-trunk-config.json \\

      \--strict

*Exit Code 0: Audit Score \$\\ge 80\$ (Grade A/A+) and zero critical VLAN hopping or DTP vulnerabilities. Pipeline proceeds.* *Exit Code 1: Audit Score \$\< 80\$ (Grade B/C/F) or critical flaw detected. Pipeline halts.*

---

## 3\. Production Configuration Examples

### 3.1 Cisco Catalyst 9300 Hardened Zero-Trust Trunk Configuration

vlan dot1q tag native

vtp mode transparent

\!

vlan 999

 name UNUSED\_NATIVE\_QUARANTINE\_VLAN

 shutdown

\!

interface TenGigabitEthernet1/0/48

 description CORE-DISTRIBUTION-TRUNK

 switchport mode trunk

 switchport trunk native vlan 999

 switchport trunk allowed vlan 10,20,100,200

 switchport nonegotiate

 storm-control broadcast level 5.0

 mtu 9216

 no shutdown

---

## 4\. Troubleshooting Layer 2 Trunking Failures

1. **Traffic Bypasses Firewall via Native VLAN Hopping**:  
   - *Cause*: Trunk native VLAN is set to VLAN 1, untagged native frames are enabled, and user access ports share VLAN 1\.  
   - *Resolution*: Configure `switchport trunk native vlan 999` and `vlan dot1q tag native`.  
2. **Unauthorized Switch Forms Trunk on Access Port**:  
   - *Cause*: Switchport in `dynamic desirable` or `dynamic auto`. Attacker plugged in laptop running Yersinia and sent DTP frames.  
   - *Resolution*: Apply `switchport mode access` and `switchport nonegotiate`.  
3. **Double-Tagged QinQ Frames Dropped Across Metro-Ethernet**:  
   - *Cause*: Interface MTU is set to default 1500 bytes. Adding 8-byte S-TAG \+ C-TAG expands 1500-byte payload to 1526 bytes, causing drops.  
   - *Resolution*: Increase switch interface MTU to \$\\ge 1550\$ bytes or 9216 bytes.  
4. **VLAN 1 Broadcast Storms Overwhelming Switch CPU**:  
   - *Cause*: Trunk allowed list set to default `1-4094`. Inactive VLAN broadcasts flood all trunk links.  
   - *Resolution*: Restrict trunks to active subnets: `switchport trunk allowed vlan <list>`.