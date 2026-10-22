/**
 * Dot1qForge Pro - Multi-Platform Layer 2 Trunking & QinQ Configuration Synthesizer
 * 
 * Synthesizes production-hardened configurations for Cisco IOS-XE,
 * Cisco Nexus NX-OS, Arista EOS, Juniper Junos, and Linux (iproute2/systemd-networkd).
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.Dot1qConfigSynthesizer = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  function synthesizeCiscoIosXe(params) {
    const nativeVlan = params.trunkNativeVlan || 999;
    const allowed = params.allowedVlans || '10,20,100,200';
    const mtu = params.interfaceMtu || 9216;
    const isQinQ = Boolean(params.isQinQ);
    const sVlan = params.outerVlan || 500;

    if (isQinQ) {
      return `! ==============================================================================
! Cisco Catalyst / IOS-XE IEEE 802.1ad QinQ Provider Port Configuration
! ==============================================================================
! 1. Global Jumbo MTU Support for Double-Tagging
system mtu ${mtu}
!
! 2. Customer-Facing 802.1Q Tunnel (QinQ Edge Port)
interface GigabitEthernet1/0/1
 description CUSTOMER-QINQ-EDGE-HANDOFF
 switchport mode dot1q-tunnel
 switchport access vlan ${sVlan}
 switchport nonegotiate
 l2protocol-tunnel cdp
 l2protocol-tunnel stp
 l2protocol-tunnel vtp
 l2protocol-tunnel lldp
 no cdp enable
 storm-control broadcast level 5.0
 storm-control multicast level 10.0
!
! 3. Service Provider Core Trunk Uplink
interface TenGigabitEthernet1/0/48
 description METRO-ETHERNET-CORE-TRUNK
 switchport mode trunk
 switchport trunk native vlan ${nativeVlan}
 switchport trunk allowed vlan ${sVlan}
 switchport nonegotiate
 mtu ${mtu}
`;
    }

    return `! ==============================================================================
! Cisco Catalyst / IOS-XE Production Zero-Trust VLAN Trunk Configuration
! Platform: Cisco Catalyst 9300 / 9500 running IOS-XE 17.x+
! Standards: IEEE 802.1Q | CIS Cisco IOS Benchmark | NIST SP 800-125B
! ==============================================================================

! 1. Global Security Hardening: Force Tagging of Native VLAN Frames
vlan dot1q tag native
!
! 2. VTP Hardening: Disable VTP Domain Propagation
vtp mode transparent
!
! 3. Create Dedicated Quarantine Native VLAN
vlan ${nativeVlan}
 name UNUSED_NATIVE_QUARANTINE_VLAN
 state active
 shutdown
!
! 4. Switch-to-Switch Core Trunk Interface
interface TenGigabitEthernet1/0/48
 description CORE-DISTRIBUTION-TRUNK-LINK
 switchport mode trunk
 switchport trunk native vlan ${nativeVlan}
 switchport trunk allowed vlan ${allowed}
 switchport nonegotiate
 storm-control broadcast level 5.0
 storm-control multicast level 10.0
 storm-control action trap
 mtu ${mtu}
 no shutdown
!
! 5. User-Facing Edge Access Ports (Zero-Trust Locked)
interface range GigabitEthernet1/0/1 - 24
 description USER-WORKSTATION-EDGE-PORT
 switchport mode access
 switchport access vlan 10
 switchport nonegotiate
 spanning-tree portfast
 spanning-tree bpduguard enable
 storm-control broadcast level 5.0
`;
  }

  function synthesizeCiscoNxos(params) {
    const nativeVlan = params.trunkNativeVlan || 999;
    const allowed = params.allowedVlans || '10,20,100,200';
    const mtu = params.interfaceMtu || 9216;

    return `! ==============================================================================
! Cisco Nexus NX-OS Data Center Spine-Leaf Trunk Configuration
! ==============================================================================
vlan dot1q tag native
!
vlan ${nativeVlan}
  name UNUSED_NATIVE_VLAN
  state active
!
interface Ethernet1/1
  description SPINE-UPLINK-TRUNK
  switchport
  switchport mode trunk
  switchport trunk native vlan ${nativeVlan}
  switchport trunk allowed vlan ${allowed}
  mtu ${mtu}
  no shutdown
!
interface Ethernet1/2-24
  description COMPUTE-NODE-ACCESS
  switchport
  switchport mode access
  switchport access vlan 10
  spanning-tree port type edge
  spanning-tree bpduguard enable
`;
  }

  function synthesizeArista(params) {
    const nativeVlan = params.trunkNativeVlan || 999;
    const allowed = params.allowedVlans || '10,20,100,200';
    const mtu = params.interfaceMtu || 9216;

    return `! ==============================================================================
! Arista EOS Production VLAN Trunking Configuration
! ==============================================================================
vlan dot1q tag native
!
vlan ${nativeVlan}
   name UNUSED_NATIVE_VLAN
!
interface Ethernet49/1
   description LEAF-SPINE-TRUNK
   switchport mode trunk
   switchport trunk native vlan ${nativeVlan}
   switchport trunk allowed vlan ${allowed}
   mtu ${mtu}
!
interface Ethernet1-24
   description HOST-ACCESS-PORTS
   switchport mode access
   switchport access vlan 10
   spanning-tree portfast
   spanning-tree bpduguard enable
`;
  }

  function synthesizeJunos(params) {
    const nativeVlan = params.trunkNativeVlan || 999;
    const allowed = (params.allowedVlans || '10,20,100,200').split(',');

    const vlanMembers = allowed.map(v => `vlan-${v.trim()}`).join(' ');

    return `# ==============================================================================
# Juniper Junos OS Enterprise Trunking Configuration
# ==============================================================================
set vlans native-quarantine vlan-id ${nativeVlan}

set interfaces ge-0/0/0 unit 0 family ethernet-switching interface-mode trunk
set interfaces ge-0/0/0 unit 0 family ethernet-switching vlan members [ ${vlanMembers} ]
set interfaces ge-0/0/0 native-vlan-id ${nativeVlan}

# Edge Access Port Hardening
set interfaces ge-0/0/1 unit 0 family ethernet-switching interface-mode access
set interfaces ge-0/0/1 unit 0 family ethernet-switching vlan members vlan-10
set protocols rstp interface ge-0/0/1 edge
set protocols rstp interface ge-0/0/1 bpdu-timeout-action block
`;
  }

  function synthesizeLinux(params) {
    const vlan = params.outerVlan || params.vlanId || 100;
    const innerVlan = params.innerVlan || 200;
    const isQinQ = Boolean(params.isQinQ);

    if (isQinQ) {
      return `# ==============================================================================
# Linux iproute2 IEEE 802.1ad (QinQ) Configuration
# ==============================================================================
# 1. Create Outer Service VLAN Tag (S-TAG 802.1ad)
ip link add link eth0 name eth0.${vlan} type vlan proto 802.1ad id ${vlan}

# 2. Stack Inner Customer VLAN Tag (C-TAG 802.1Q)
ip link add link eth0.${vlan} name eth0.${vlan}.${innerVlan} type vlan proto 802.1q id ${innerVlan}

# 3. Bring Up Virtual Interfaces
ip link set eth0 up
ip link set eth0.${vlan} up
ip link set eth0.${vlan}.${innerVlan} up

# 4. Assign IP Address to Double-Tagged Interface
ip addr add 192.168.${innerVlan}.10/24 dev eth0.${vlan}.${innerVlan}
`;
    }

    return `# ==============================================================================
# Linux iproute2 IEEE 802.1Q Standard VLAN Trunking
# ==============================================================================
# 1. Add 802.1Q Tagged Interface
ip link add link eth0 name eth0.${vlan} type vlan id ${vlan}

# 2. Configure MTU & Bring Up Interface
ip link set dev eth0 mtu 9216
ip link set dev eth0 up
ip link set dev eth0.${vlan} up

# 3. Assign IP Address
ip addr add 192.168.${vlan}.10/24 dev eth0.${vlan}
`;
  }

  return {
    synthesizeCiscoIosXe,
    synthesizeCiscoNxos,
    synthesizeArista,
    synthesizeJunos,
    synthesizeLinux
  };
}));
