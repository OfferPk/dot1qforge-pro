/**
 * Dot1qForge Pro - IEEE 802.1Q & IEEE 802.1ad (QinQ) Protocol Engine
 * 
 * Provides binary Ethernet frame encoding, 802.1Q single-tagging,
 * 802.1ad QinQ double-tagging, Native VLAN hopping attack simulation,
 * DTP switch-spoofing evaluation, MTU sizing, and binary PCAP generation.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.Dot1qProtocolEngine = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // Standard Tag Protocol Identifiers (TPID)
  const TPID = {
    DOT1Q: 0x8100,      // Standard 802.1Q Customer Tag (C-TAG)
    DOT1AD: 0x88A8,     // IEEE 802.1ad Provider Bridge Service Tag (S-TAG)
    DOT1Q_LEGACY: 0x9100 // Legacy Cisco / Foundry QinQ S-TAG
  };

  // Priority Code Point (PCP) to CoS Mapping (IEEE 802.1p)
  const PCP_COS_NAMES = {
    0: '0 - Best Effort (BE)',
    1: '1 - Background (BK)',
    2: '2 - Excellent Effort (EE)',
    3: '3 - Critical Applications (CA)',
    4: '4 - Video (<100ms latency)',
    5: '5 - Voice (<10ms latency / EF)',
    6: '6 - Internetwork Control (IC)',
    7: '7 - Network Control (NC)'
  };

  // Standard CRC32 Table for Ethernet FCS (IEEE 802.3)
  const CRC32_TABLE = new Uint32Array(256);
  (function initCrcTable() {
    for (let i = 0; i < 256; i++) {
      let c = i;
      for (let j = 0; j < 8; j++) {
        c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
      }
      CRC32_TABLE[i] = c >>> 0;
    }
  })();

  function calculateCrc32(bytes) {
    let crc = 0xFFFFFFFF;
    for (let i = 0; i < bytes.length; i++) {
      crc = (crc >>> 8) ^ CRC32_TABLE[(crc ^ bytes[i]) & 0xFF];
    }
    return (crc ^ 0xFFFFFFFF) >>> 0;
  }

  function parseMac(macStr) {
    if (!macStr || typeof macStr !== 'string') return [0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    const cleaned = macStr.replace(/[^0-9a-fA-F]/g, '');
    const bytes = [];
    for (let i = 0; i < 12; i += 2) {
      if (i < cleaned.length) {
        bytes.push(parseInt(cleaned.substr(i, 2), 16) || 0);
      } else {
        bytes.push(0);
      }
    }
    return bytes.slice(0, 6);
  }

  function formatMac(bytes) {
    return Array.from(bytes).slice(0, 6).map(b => b.toString(16).padStart(2, '0')).join(':');
  }

  function parseIpv4(ipStr) {
    if (!ipStr || typeof ipStr !== 'string') return [192, 168, 1, 10];
    const parts = ipStr.trim().split('.');
    if (parts.length !== 4) return [192, 168, 1, 10];
    return parts.map(p => Math.max(0, Math.min(255, parseInt(p, 10) || 0)));
  }

  /**
   * Encodes a 4-byte 802.1Q / 802.1ad Tag (TPID + TCI)
   */
  function encodeVlanTag(tpid, vlanId, pcp, dei) {
    tpid = tpid || TPID.DOT1Q;
    vlanId = Math.max(1, Math.min(4094, parseInt(vlanId, 10) || 1));
    pcp = Math.max(0, Math.min(7, parseInt(pcp, 10) || 0));
    dei = dei ? 1 : 0;

    const tci = ((pcp & 0x07) << 13) | ((dei & 0x01) << 12) | (vlanId & 0x0FFF);
    return [
      (tpid >> 8) & 0xff,
      tpid & 0xff,
      (tci >> 8) & 0xff,
      tci & 0xff
    ];
  }

  /**
   * Forges an IEEE 802.1Q Single-Tagged or 802.1ad Double-Tagged Ethernet Frame
   */
  function forgeEthernetFrame(params) {
    params = params || {};
    const isQinQ = Boolean(params.isQinQ);
    const dstMac = parseMac(params.dstMac || '00:50:56:a1:b2:c3');
    const srcMac = parseMac(params.srcMac || '00:1a:2b:3c:4d:5e');

    // Outer Tag (S-TAG for QinQ, or standard 802.1Q tag)
    const outerVlan = parseInt(params.outerVlan || params.vlanId, 10) || 100;
    const outerPcp = parseInt(params.outerPcp || params.pcp, 10) || 0;
    const outerDei = Boolean(params.outerDei || params.dei);
    const outerTpid = isQinQ ? (params.sTpid || TPID.DOT1AD) : TPID.DOT1Q;

    const outerTagBytes = encodeVlanTag(outerTpid, outerVlan, outerPcp, outerDei);

    // Inner Tag (C-TAG for QinQ)
    let innerTagBytes = [];
    if (isQinQ) {
      const innerVlan = parseInt(params.innerVlan, 10) || 200;
      const innerPcp = parseInt(params.innerPcp, 10) || 0;
      const innerDei = Boolean(params.innerDei);
      innerTagBytes = encodeVlanTag(TPID.DOT1Q, innerVlan, innerPcp, innerDei);
    }

    // EtherType IPv4 (0x0800)
    const ethertype = [0x08, 0x00];

    // Payload: IPv4 ICMP Echo Request (28 bytes)
    const ipSrc = parseIpv4(params.srcIp || '192.168.100.10');
    const ipDst = parseIpv4(params.dstIp || '192.168.100.1');
    const ipHeader = [
      0x45, 0x00, 0x00, 0x1c, // IPv4, 28 bytes total length
      0x1a, 0x2b, 0x00, 0x00, // ID, Flags (0)
      0x40, 0x01, 0x00, 0x00, // TTL 64, Protocol ICMP (1), Checksum
      ...ipSrc,
      ...ipDst
    ];

    // ICMP Echo Request: Type 8, Code 0, Checksum, ID, Seq
    const icmpBody = [0x08, 0x00, 0xf7, 0xfd, 0x00, 0x01, 0x00, 0x01];

    const frameWithoutFcs = dstMac.concat(srcMac)
      .concat(outerTagBytes)
      .concat(innerTagBytes)
      .concat(ethertype)
      .concat(ipHeader)
      .concat(icmpBody);

    // Pad to minimum Ethernet frame size (60 bytes before FCS)
    while (frameWithoutFcs.length < 60) {
      frameWithoutFcs.push(0x00);
    }

    // Compute 4-byte CRC32 Frame Check Sequence (FCS)
    const crc = calculateCrc32(new Uint8Array(frameWithoutFcs));
    const fcsBytes = [
      crc & 0xff,
      (crc >> 8) & 0xff,
      (crc >> 16) & 0xff,
      (crc >> 24) & 0xff
    ];

    const completeFrame = frameWithoutFcs.concat(fcsBytes);

    return {
      isQinQ,
      outerVlan,
      outerPcp,
      outerDei,
      outerTpid: '0x' + outerTpid.toString(16).toUpperCase(),
      innerVlan: isQinQ ? (parseInt(params.innerVlan, 10) || 200) : null,
      totalLength: completeFrame.length,
      wireLengthWithPreamble: completeFrame.length + 8, // 7B preamble + 1B SFD
      rawBytes: new Uint8Array(completeFrame)
    };
  }

  /**
   * Wireshark-Style Hex Dump Formatter
   */
  function formatHexDump(uint8Arr) {
    const lines = [];
    const len = uint8Arr.length;

    for (let i = 0; i < len; i += 16) {
      const chunk = uint8Arr.subarray(i, Math.min(i + 16, len));
      const offset = i.toString(16).padStart(4, '0');

      let hexPart1 = '';
      let hexPart2 = '';
      let asciiPart = '';

      for (let j = 0; j < 16; j++) {
        if (j < chunk.length) {
          const byte = chunk[j];
          const hex = byte.toString(16).padStart(2, '0');
          if (j < 8) hexPart1 += hex + ' ';
          else hexPart2 += hex + ' ';

          asciiPart += (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
        } else {
          if (j < 8) hexPart1 += '   ';
          else hexPart2 += '   ';
        }
      }

      const hexCombined = (hexPart1.trimEnd() + '  ' + hexPart2.trimEnd()).padEnd(48, ' ');
      lines.push(`${offset}   ${hexCombined}   |${asciiPart}|`);
    }

    return lines.join('\n');
  }

  /**
   * Native VLAN Double-Tagging Hopping Attack Simulator (CVE-2001-1413)
   */
  function simulateVlanHopping(params) {
    const userAccessVlan = parseInt(params.userAccessVlan, 10) || 1;
    const trunkNativeVlan = parseInt(params.trunkNativeVlan, 10) || 1;
    const targetVlan = parseInt(params.targetVlan, 10) || 100;
    const tagNativeEnabled = Boolean(params.tagNativeEnabled);
    const unusedNativeVlan = Boolean(params.unusedNativeVlan);

    // Condition 1: Attacker must be on the same VLAN as the Trunk Native VLAN
    const onNativeVlan = (userAccessVlan === trunkNativeVlan);

    // Condition 2: Trunk must transmit Native VLAN frames untagged
    const nativeUntagged = !tagNativeEnabled;

    if (onNativeVlan && nativeUntagged && !unusedNativeVlan) {
      return {
        vulnerable: true,
        riskLevel: 'CRITICAL',
        title: 'CRITICAL EXPLOIT: Native VLAN Double-Tagging Hopping Succeeded!',
        summary: `Attacker on Access VLAN ${userAccessVlan} crafts frame with Outer Tag=VLAN ${trunkNativeVlan} and Inner Tag=VLAN ${targetVlan}. Switch 1 strips Outer Tag over trunk. Switch 2 receives Inner Tag and delivers frame directly into restricted VLAN ${targetVlan}!`,
        remediation: '1. Change Trunk Native VLAN to an unused ID (e.g. VLAN 999).\n2. Enforce global native tagging: "vlan dot1q tag native".\n3. Never place end-users on Native VLAN.'
      };
    } else if (onNativeVlan && tagNativeEnabled) {
      return {
        vulnerable: false,
        riskLevel: 'PROTECTED',
        title: 'PROTECTED: Native VLAN Tagging Enforced ("vlan dot1q tag native")',
        summary: `Even though user is on Native VLAN ${userAccessVlan}, the trunk explicitly tags all native frames with TPID 0x8100. Switch 1 does not strip the outer tag; Switch 2 treats the frame as a legitimate dual-tagged packet and does not forward to VLAN ${targetVlan}.`,
        remediation: 'Compliant. Ensure all intermediate switches maintain native tag enforcement.'
      };
    } else if (unusedNativeVlan || !onNativeVlan) {
      return {
        vulnerable: false,
        riskLevel: 'PROTECTED',
        title: 'PROTECTED: Dedicated Unused Native VLAN (VLAN Isolation Active)',
        summary: `Access port is on VLAN ${userAccessVlan}, but Trunk Native VLAN is dedicated unused VLAN ${trunkNativeVlan}. The switch drops or encapsulates the outer tag with VLAN ${userAccessVlan}, rendering the double-tag payload harmless.`,
        remediation: 'Compliant. Dedicated non-default Native VLAN prevents hopping breakout.'
      };
    }

    return {
      vulnerable: false,
      riskLevel: 'SAFE',
      title: 'PROTECTED: Segmentation Enforced',
      summary: 'VLAN hopping parameters safely isolated.',
      remediation: 'None required.'
    };
  }

  /**
   * Dynamic Trunking Protocol (DTP) Switch Spoofing Simulator
   */
  function simulateDtpSpoofing(dtpMode) {
    const mode = (dtpMode || 'dynamic_desirable').toLowerCase();

    if (mode === 'dynamic_desirable' || mode === 'dynamic_auto') {
      return {
        vulnerable: true,
        riskLevel: 'CRITICAL',
        title: 'CRITICAL EXPLOIT: DTP Switch Spoofing Active',
        summary: `Port is in "${mode}" mode. An attacker transmitting DTP packets (via Yersinia or Scapy) will successfully negotiate an active 802.1Q trunk, gaining untethered access to all VLANs!`,
        remediation: 'Configure "switchport mode access" and explicitly disable DTP with "switchport nonegotiate".'
      };
    } else if (mode === 'trunk_negotiate') {
      return {
        vulnerable: true,
        riskLevel: 'WARN',
        title: 'WARNING: Trunk with Active DTP Heartbeats',
        summary: 'Port is a trunk but DTP frames are still broadcast every 30 seconds. Attacker cannot change port mode but learns VTP domain metadata.',
        remediation: 'Add "switchport nonegotiate" to static trunk interfaces.'
      };
    } else {
      return {
        vulnerable: false,
        riskLevel: 'PROTECTED',
        title: 'PROTECTED: DTP Disabled ("switchport nonegotiate")',
        summary: 'Port rejects all dynamic trunk negotiation attempts. Switch spoofing attacks are completely neutralized.',
        remediation: 'Compliant.'
      };
    }
  }

  /**
   * Baby Giant / Jumbo MTU Frame Sizing Calculator
   */
  function calculateMtuSizing(isQinQ, ipMtu) {
    ipMtu = parseInt(ipMtu, 10) || 1500;
    const l2HeaderLen = 14; // Dest MAC (6) + Src MAC (6) + EtherType (2)
    const fcsLen = 4;       // CRC32
    const vlanOverhead = isQinQ ? 8 : 4; // 8B for 802.1ad QinQ, 4B for 802.1Q

    const totalL2FrameSize = ipMtu + l2HeaderLen + vlanOverhead + fcsLen;
    const minSwitchMtu = ipMtu + vlanOverhead;

    return {
      ipMtu,
      isQinQ,
      vlanOverheadBytes: vlanOverhead,
      totalL2FrameSizeBytes: totalL2FrameSize,
      minSwitchPortMtuBytes: minSwitchMtu,
      isBabyGiant: (totalL2FrameSize > 1518 && totalL2FrameSize <= 1600),
      isJumbo: (totalL2FrameSize > 1600),
      recommendation: isQinQ
        ? `QinQ adds 8 bytes overhead. Switch ports MUST support at least ${minSwitchMtu} bytes (recommend standard Jumbo MTU 9216) to avoid dropping double-tagged frames.`
        : `802.1Q adds 4 bytes overhead. Switch ports MUST support at least ${minSwitchMtu} bytes.`
    };
  }

  /**
   * Generates a standard binary PCAP file containing the forged tagged Ethernet frame
   */
  function generatePcap(forgedFrame) {
    const rawPayload = forgedFrame.rawBytes;

    // PCAP Global Header (24 bytes)
    const pcapHeader = new ArrayBuffer(24);
    const pcapView = new DataView(pcapHeader);
    pcapView.setUint32(0, 0xa1b2c3d4, false); // Magic number
    pcapView.setUint16(4, 2, false);          // Major version 2
    pcapView.setUint16(6, 4, false);          // Minor version 4
    pcapView.setInt32(8, 0, false);           // GMT to local correction
    pcapView.setUint32(12, 0, false);         // Accuracy of timestamps
    pcapView.setUint32(16, 262144, false);    // Max length of captured packets
    pcapView.setUint32(20, 1, false);         // Data link type: Ethernet (1)

    // Packet Record Header (16 bytes)
    const recordHeader = new ArrayBuffer(16);
    const recordView = new DataView(recordHeader);
    const nowSec = Math.floor(Date.now() / 1000);
    recordView.setUint32(0, nowSec, false);
    recordView.setUint32(4, 0, false);
    recordView.setUint32(8, rawPayload.length, false);
    recordView.setUint32(12, rawPayload.length, false);

    const totalPcap = new Uint8Array(24 + 16 + rawPayload.length);
    totalPcap.set(new Uint8Array(pcapHeader), 0);
    totalPcap.set(new Uint8Array(recordHeader), 24);
    totalPcap.set(rawPayload, 40);

    return totalPcap;
  }

  return {
    TPID,
    PCP_COS_NAMES,
    encodeVlanTag,
    forgeEthernetFrame,
    formatHexDump,
    simulateVlanHopping,
    simulateDtpSpoofing,
    calculateMtuSizing,
    generatePcap
  };
}));
