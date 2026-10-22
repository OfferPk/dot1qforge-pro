

DOT1Q

# **Dot1qForge Pro**

IEEE 802.1Q & IEEE 802.1ad (QinQ) VLAN Trunking, Hopping Defense & DTP Studio  
IEEE 802.1Q IEEE 802.1ad QINQ DTP DEFENSE 802.1p CoS  
Enterprise Hardened Zero-Trust Trunk (Grade A+) Carrier QinQ Metro-Ethernet Hand-off (Grade A+) Vulnerable Default VLAN 1 DTP Hopping (Grade F)

VLAN Tagging & Trunk Parameters FRAME: 64B

VLAN Tagging Architecture IEEE 802.1Q Single-Tagged (C-TAG) IEEE 802.1ad QinQ Double-Tagged (S-TAG \+ C-TAG)  
Outer / Primary VLAN ID  
Inner Customer VLAN ID (C-TAG)  
802.1p Priority Code Point (PCP) 0 \- Best Effort (BE) 1 \- Background (BK) 2 \- Excellent Effort (EE) 3 \- Critical Applications (CA) 4 \- Video (\<100ms) 5 \- Voice (\<10ms / EF) 6 \- Internetwork Control (IC) 7 \- Network Control (NC)  
Trunk Native VLAN ID  
Interface MTU (Bytes)

Native VLAN Double-Tagging Hopping Simulator PROTECTED

PROTECTED: Dedicated Quarantine Native VLAN  
Trunk Native VLAN is set to 999\. User ports isolated from trunk native domain.

Attacker Edge Access VLAN  
Global Native Tagging ("tag native") Enabled (vlan dot1q tag native) Disabled (Untagged Native Frames)

Dynamic Trunking Protocol (DTP) Simulator NONEGOTIATE

PROTECTED: DTP Disabled ("switchport nonegotiate")  
Port rejects all dynamic trunk negotiation attempts. Switch spoofing neutralized.

Port DTP Negotiation Mode switchport nonegotiate (DTP Disabled) switchport mode trunk (DTP Active Heartbeats) switchport mode dynamic desirable (VULNERABLE) switchport mode dynamic auto (VULNERABLE)

10-Point Zero-Trust Layer 2 Trunking Scorecard PASSING

A+

**100 / 100 Points Zero-Trust Hardened**  
All 10 Native VLAN isolation, DTP mitigation, QinQ MTU, and storm control policies satisfied.

IEEE 802.1Q / 802.1ad Tagged Frame & Hex Dissector  
Copy Hex Download PCAP  
0000 00 50 56 a1 b2 c3 00 1a 2b 3c 4d 5e 81 00 00 64 |.PV......\<M^...d|

Multi-Platform Production Synthesizer Copy Config  
Cisco IOS-XE Cisco Nexus NX-OS Arista EOS Juniper Junos Linux iproute2  
\! Generating configuration...