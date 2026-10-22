/**
 * Dot1qForge Pro - 10-Point Zero-Trust Layer 2 Trunking & 802.1Q Security Auditor
 * 
 * Evaluates switch trunk configurations, Native VLAN assignments, DTP negotiation states,
 * and QinQ MTU headroom against NIST SP 800-125B, CIS Cisco IOS Benchmark, and NSA Hardening Guidelines.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.Dot1qSecurityAuditor = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const AUDIT_CONTROLS = [
    {
      id: 'DOT1Q-SEC-01',
      title: 'Dedicated Unused Native VLAN ID',
      maxPoints: 15,
      evaluate: function (cfg) {
        const nativeVlan = parseInt(cfg.trunkNativeVlan, 10) || 1;
        if (nativeVlan !== 1 && nativeVlan >= 900) {
          return {
            passed: true,
            score: 15,
            level: 'PASS',
            finding: `Dedicated unused Native VLAN ${nativeVlan} configured on trunk interfaces.`,
            remediation: 'Compliant. No user access ports or management services share the Native VLAN ID.'
          };
        } else if (nativeVlan !== 1) {
          return {
            passed: true,
            score: 10,
            level: 'PASS',
            finding: `Non-default Native VLAN ${nativeVlan} in use. Ensure this VLAN is completely unused for host data.`,
            remediation: 'Standardize on a dedicated quarantine/dummy VLAN ID such as 999.'
          };
        }
        return {
          passed: false,
          score: 0,
          level: 'FAIL',
          finding: 'CRITICAL HAZARD: Trunk Native VLAN is set to Default VLAN 1! Vulnerable to Native VLAN hopping attacks.',
          remediation: 'Configure "switchport trunk native vlan 999" and ensure VLAN 999 has no active access switchports.'
        };
      }
    },
    {
      id: 'DOT1Q-SEC-02',
      title: 'Global Native VLAN 802.1Q Tagging',
      maxPoints: 15,
      evaluate: function (cfg) {
        if (cfg.tagNativeEnabled) {
          return {
            passed: true,
            score: 15,
            level: 'PASS',
            finding: 'Global Native VLAN Tagging enabled ("vlan dot1q tag native"). All native frames carry an 802.1Q tag.',
            remediation: 'Compliant. Double-tagging Native VLAN hopping attacks are completely neutralized.'
          };
        }
        return {
          passed: false,
          score: 2,
          level: 'FAIL',
          finding: 'Native VLAN frames transmitted UNTAGGED over trunk. Attackers on the native VLAN can exploit double-tagging to jump VLANs.',
          remediation: 'Enable global native tagging with "vlan dot1q tag native" on all switches.'
        };
      }
    },
    {
      id: 'DOT1Q-SEC-03',
      title: 'Dynamic Trunking Protocol (DTP) Disablement',
      maxPoints: 12,
      evaluate: function (cfg) {
        const dtpMode = (cfg.dtpMode || 'dynamic_desirable').toLowerCase();
        if (dtpMode === 'nonegotiate' || cfg.dtpDisabled) {
          return {
            passed: true,
            score: 12,
            level: 'PASS',
            finding: 'DTP explicitly disabled ("switchport nonegotiate"). Dynamic trunking negotiation blocked.',
            remediation: 'Compliant. Rogue switches or attacking laptops running Yersinia cannot spoof trunk links.'
          };
        } else if (dtpMode === 'trunk_negotiate') {
          return {
            passed: false,
            score: 6,
            level: 'WARN',
            finding: 'Port statically set to trunk, but DTP frames are still broadcast every 30 seconds.',
            remediation: 'Add "switchport nonegotiate" to all static trunk interfaces.'
          };
        }
        return {
          passed: false,
          score: 0,
          level: 'FAIL',
          finding: 'CRITICAL: Port configured with DTP negotiation enabled ("dynamic auto" or "dynamic desirable").',
          remediation: 'Enforce static port mode and apply "switchport nonegotiate".'
        };
      }
    },
    {
      id: 'DOT1Q-SEC-04',
      title: 'Strict Trunk VLAN Pruning & Whitelisting',
      maxPoints: 10,
      evaluate: function (cfg) {
        if (cfg.trunkPruningExplicit && cfg.allowedVlans && cfg.allowedVlans !== 'all' && cfg.allowedVlans !== '1-4094') {
          return {
            passed: true,
            score: 10,
            level: 'PASS',
            finding: `Explicit VLAN pruning enforced ("switchport trunk allowed vlan ${cfg.allowedVlans}").`,
            remediation: 'Compliant. Broadcast, multicast, and unknown unicast frames for inactive VLANs are pruned from the trunk.'
          };
        }
        return {
          passed: false,
          score: 2,
          level: 'WARN',
          finding: 'Trunk allows all VLANs (1-4094). Unnecessary broadcast traffic floods core links and bloats switch CAM tables.',
          remediation: 'Explicitly whitelist required VLANs: "switchport trunk allowed vlan 10,20,100".'
        };
      }
    },
    {
      id: 'DOT1Q-SEC-05',
      title: 'Access Port Mode Hardening & PortFast',
      maxPoints: 10,
      evaluate: function (cfg) {
        if (cfg.accessPortHardened) {
          return {
            passed: true,
            score: 10,
            level: 'PASS',
            finding: 'Host edge ports strictly set to "switchport mode access" with Spanning Tree PortFast active.',
            remediation: 'Compliant. Prevents dynamic trunk formation on user-facing edge ports.'
          };
        }
        return {
          passed: false,
          score: 3,
          level: 'WARN',
          finding: 'Access ports default to dynamic negotiation without explicit access lockdown.',
          remediation: 'Apply "switchport mode access" and "spanning-tree portfast" on all access ports.'
        };
      }
    },
    {
      id: 'DOT1Q-SEC-06',
      title: 'IEEE 802.1ad QinQ S-TAG Alignment & MTU Headroom',
      maxPoints: 10,
      evaluate: function (cfg) {
        const isQinQ = Boolean(cfg.isQinQ);
        const mtu = parseInt(cfg.interfaceMtu, 10) || 1500;
        if (isQinQ && mtu >= 9216) {
          return {
            passed: true,
            score: 10,
            level: 'PASS',
            finding: `QinQ Provider Bridging active with Jumbo MTU (${mtu}B). 8-byte tag overhead fully accommodated.`,
            remediation: 'Compliant.'
          };
        } else if (isQinQ && mtu >= 1550) {
          return {
            passed: true,
            score: 8,
            level: 'PASS',
            finding: `QinQ active with Baby Giant MTU (${mtu}B). Sufficient for standard 1500B customer payloads.`,
            remediation: 'Recommend standardizing on 9216 Jumbo MTU for carrier transport.'
          };
        } else if (isQinQ) {
          return {
            passed: false,
            score: 0,
            level: 'FAIL',
            finding: `CRITICAL MTU DROPS: QinQ double-tagging enabled but interface MTU is only ${mtu} bytes! Double-tagged frames will be dropped.`,
            remediation: 'Increase interface MTU to at least 1550 bytes (or 9216 bytes).'
          };
        } else {
          // Standard single-tag 802.1Q
          return {
            passed: true,
            score: 10,
            level: 'PASS',
            finding: `Standard 802.1Q trunking with MTU ${mtu}B.`,
            remediation: 'Compliant.'
          };
        }
      }
    },
    {
      id: 'DOT1Q-SEC-07',
      title: 'VTP Domain & Mode Hardening (Transparent / Off)',
      maxPoints: 8,
      evaluate: function (cfg) {
        const vtpMode = (cfg.vtpMode || 'transparent').toLowerCase();
        if (vtpMode === 'transparent' || vtpMode === 'off') {
          return {
            passed: true,
            score: 8,
            level: 'PASS',
            finding: `VTP operating in "${vtpMode}" mode. Rogue switch revision numbers cannot overwrite campus VLAN databases.`,
            remediation: 'Compliant.'
          };
        }
        return {
          passed: false,
          score: 1,
          level: 'WARN',
          finding: `VTP in "${vtpMode}" mode: A rogue or newly inserted switch with a higher configuration revision number can wipe out all VLANs!`,
          remediation: 'Set "vtp mode transparent" or "vtp mode off" and configure a secure VTP password.'
        };
      }
    },
    {
      id: 'DOT1Q-SEC-08',
      title: 'Layer 2 Storm Control Rate-Limiting',
      maxPoints: 8,
      evaluate: function (cfg) {
        if (cfg.stormControlEnabled) {
          return {
            passed: true,
            score: 8,
            level: 'PASS',
            finding: 'Storm control active for Broadcast, Multicast, and Unknown Unicast (capped at 5-10% bandwidth).',
            remediation: 'Compliant. Prevents Layer 2 broadcast storms from saturating the switch backplane.'
          };
        }
        return {
          passed: false,
          score: 2,
          level: 'WARN',
          finding: 'Storm control disabled: Loops or rogue broadcast storms can saturate switch backplanes and freeze management consoles.',
          remediation: 'Configure "storm-control broadcast level 5.0" on all access and trunk ports.'
        };
      }
    },
    {
      id: 'DOT1Q-SEC-09',
      title: 'BPDU Guard & Root Guard on Edge Ports',
      maxPoints: 6,
      evaluate: function (cfg) {
        if (cfg.bpduGuardActive) {
          return {
            passed: true,
            score: 6,
            level: 'PASS',
            finding: 'Spanning Tree BPDU Guard active on edge ports. Injected BPDUs immediately place port into err-disabled state.',
            remediation: 'Compliant.'
          };
        }
        return {
          passed: false,
          score: 1,
          level: 'WARN',
          finding: 'BPDU Guard disabled: Rogue switches plugged into access ports can hijack the Spanning Tree root bridge role.',
          remediation: 'Enable "spanning-tree portfast bpduguard default" globally.'
        };
      }
    },
    {
      id: 'DOT1Q-SEC-10',
      title: 'DHCP Snooping & DAI Trunk Trust Boundary',
      maxPoints: 6,
      evaluate: function (cfg) {
        if (cfg.fhsTrustBoundaryEnforced) {
          return {
            passed: true,
            score: 6,
            level: 'PASS',
            finding: 'First-Hop Security trust boundary enforced: Trunks marked trusted for DHCP Snooping & DAI; access ports untrusted.',
            remediation: 'Compliant.'
          };
        }
        return {
          passed: false,
          score: 2,
          level: 'INFO',
          finding: 'Trunk trust boundaries not linked to DHCP Snooping / Dynamic ARP Inspection tables.',
          remediation: 'Ensure core uplinks carry "ip dhcp snooping trust" and "ip arp inspection trust".'
        };
      }
    }
  ];

  function auditConfiguration(cfg) {
    let totalScore = 0;
    const findings = [];

    AUDIT_CONTROLS.forEach(ctrl => {
      const res = ctrl.evaluate(cfg);
      totalScore += res.score;
      findings.push({
        id: ctrl.id,
        title: ctrl.title,
        maxPoints: ctrl.maxPoints,
        score: res.score,
        level: res.level,
        passed: res.passed,
        finding: res.finding,
        remediation: res.remediation
      });
    });

    let grade = 'F';
    if (totalScore >= 95) grade = 'A+';
    else if (totalScore >= 85) grade = 'A';
    else if (totalScore >= 75) grade = 'B';
    else if (totalScore >= 60) grade = 'C';
    else if (totalScore >= 50) grade = 'D';

    return {
      score: totalScore,
      maxScore: 100,
      grade: grade,
      passed: totalScore >= 80,
      findings: findings,
      evaluatedAt: new Date().toISOString()
    };
  }

  return {
    AUDIT_CONTROLS,
    auditConfiguration
  };
}));
