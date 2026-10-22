/**
 * Dot1qForge Pro - Web Studio Controller & Preset Manager
 */

(function () {
  'use strict';

  const PRESETS = {
    'enterprise-hardened': {
      tagMode: 'single',
      outerVlan: 100,
      innerVlan: 200,
      pcp: 0,
      dei: false,
      trunkNativeVlan: 999,
      userAccessVlan: 10,
      tagNativeEnabled: true,
      unusedNativeVlan: true,
      dtpMode: 'nonegotiate',
      dtpDisabled: true,
      allowedVlans: '10,20,100,200',
      trunkPruningExplicit: true,
      accessPortHardened: true,
      isQinQ: false,
      interfaceMtu: 9216,
      vtpMode: 'transparent',
      stormControlEnabled: true,
      bpduGuardActive: true,
      fhsTrustBoundaryEnforced: true
    },
    'carrier-qinq': {
      tagMode: 'qinq',
      outerVlan: 500,
      innerVlan: 100,
      pcp: 5,
      dei: false,
      trunkNativeVlan: 999,
      userAccessVlan: 10,
      tagNativeEnabled: true,
      unusedNativeVlan: true,
      dtpMode: 'nonegotiate',
      dtpDisabled: true,
      allowedVlans: '500,501,502',
      trunkPruningExplicit: true,
      accessPortHardened: true,
      isQinQ: true,
      interfaceMtu: 9216,
      vtpMode: 'off',
      stormControlEnabled: true,
      bpduGuardActive: true,
      fhsTrustBoundaryEnforced: true
    },
    'vulnerable-hopping': {
      tagMode: 'single',
      outerVlan: 1,
      innerVlan: 100,
      pcp: 0,
      dei: false,
      trunkNativeVlan: 1, // DEFAULT VLAN 1
      userAccessVlan: 1,  // ATTACKER ON NATIVE
      tagNativeEnabled: false, // UNTAGGED NATIVE
      unusedNativeVlan: false,
      dtpMode: 'dynamic_desirable', // SWITCH SPOOFING
      dtpDisabled: false,
      allowedVlans: '1-4094', // UNPRUNED
      trunkPruningExplicit: false,
      accessPortHardened: false,
      isQinQ: false,
      interfaceMtu: 1500,
      vtpMode: 'server', // ROGUE VTP HAZARD
      stormControlEnabled: false,
      bpduGuardActive: false,
      fhsTrustBoundaryEnforced: false
    }
  };

  let currentConfig = Object.assign({}, PRESETS['enterprise-hardened']);
  let activeTab = 'cisco-ios';
  let forgedFrameCache = null;

  // DOM Elements
  const selectTagMode = document.getElementById('select-tag-mode');
  const inputOuterVlan = document.getElementById('input-outer-vlan');
  const groupInnerVlan = document.getElementById('group-inner-vlan');
  const inputInnerVlan = document.getElementById('input-inner-vlan');
  const selectPcp = document.getElementById('select-pcp');
  const inputNativeVlan = document.getElementById('input-native-vlan');
  const inputInterfaceMtu = document.getElementById('input-interface-mtu');
  const badgeFrameLen = document.getElementById('badge-frame-len');

  const inputUserAccessVlan = document.getElementById('input-user-access-vlan');
  const selectTagNative = document.getElementById('select-tag-native');
  const badgeHoppingStatus = document.getElementById('badge-hopping-status');
  const hoppingDiagBanner = document.getElementById('hopping-diag-banner');
  const hoppingDiagTitle = document.getElementById('hopping-diag-title');
  const hoppingDiagDesc = document.getElementById('hopping-diag-desc');

  const selectDtpMode = document.getElementById('select-dtp-mode');
  const badgeDtpStatus = document.getElementById('badge-dtp-status');
  const dtpDiagBanner = document.getElementById('dtp-diag-banner');
  const dtpDiagTitle = document.getElementById('dtp-diag-title');
  const dtpDiagDesc = document.getElementById('dtp-diag-desc');

  const auditGradeCircle = document.getElementById('audit-grade-circle');
  const auditScoreText = document.getElementById('audit-score-text');
  const auditComplianceText = document.getElementById('audit-compliance-text');
  const auditScoreBar = document.getElementById('audit-score-bar');
  const auditStatusBadge = document.getElementById('audit-status-badge');
  const findingsContainer = document.getElementById('findings-container');

  const hexDissectorBox = document.getElementById('hex-dissector-box');
  const synthesizerOutputBox = document.getElementById('synthesizer-output-box');

  const btnCopyHex = document.getElementById('btn-copy-hex');
  const btnDownloadPcap = document.getElementById('btn-download-pcap');
  const btnCopyConfig = document.getElementById('btn-copy-config');
  const presetButtons = document.querySelectorAll('.btn-preset');
  const tabButtons = document.querySelectorAll('.tab-btn');

  function updateUiFromConfig() {
    selectTagMode.value = currentConfig.tagMode;
    groupInnerVlan.style.display = (currentConfig.tagMode === 'qinq') ? 'flex' : 'none';
    inputOuterVlan.value = currentConfig.outerVlan;
    inputInnerVlan.value = currentConfig.innerVlan;
    selectPcp.value = currentConfig.pcp;
    inputNativeVlan.value = currentConfig.trunkNativeVlan;
    inputInterfaceMtu.value = currentConfig.interfaceMtu;

    inputUserAccessVlan.value = currentConfig.userAccessVlan;
    selectTagNative.value = currentConfig.tagNativeEnabled ? 'true' : 'false';
    selectDtpMode.value = currentConfig.dtpMode;

    recomputeAll();
  }

  function readConfigFromUi() {
    currentConfig.tagMode = selectTagMode.value;
    currentConfig.isQinQ = (currentConfig.tagMode === 'qinq');
    groupInnerVlan.style.display = currentConfig.isQinQ ? 'flex' : 'none';

    currentConfig.outerVlan = parseInt(inputOuterVlan.value, 10) || 100;
    currentConfig.innerVlan = parseInt(inputInnerVlan.value, 10) || 200;
    currentConfig.pcp = parseInt(selectPcp.value, 10) || 0;
    currentConfig.trunkNativeVlan = parseInt(inputNativeVlan.value, 10) || 999;
    currentConfig.interfaceMtu = parseInt(inputInterfaceMtu.value, 10) || 9216;

    currentConfig.userAccessVlan = parseInt(inputUserAccessVlan.value, 10) || 10;
    currentConfig.tagNativeEnabled = (selectTagNative.value === 'true');
    currentConfig.unusedNativeVlan = (currentConfig.trunkNativeVlan !== 1 && currentConfig.trunkNativeVlan >= 900);
    currentConfig.dtpMode = selectDtpMode.value;
    currentConfig.dtpDisabled = (currentConfig.dtpMode === 'nonegotiate');

    recomputeAll();
  }

  function recomputeAll() {
    // 1. Forge Tagged Frame & Hex Dump
    forgedFrameCache = Dot1qProtocolEngine.forgeEthernetFrame({
      isQinQ: currentConfig.isQinQ,
      outerVlan: currentConfig.outerVlan,
      innerVlan: currentConfig.innerVlan,
      pcp: currentConfig.pcp,
      srcMac: '00:1a:2b:3c:4d:5e',
      dstMac: '00:50:56:a1:b2:c3'
    });

    badgeFrameLen.textContent = `FRAME: ${forgedFrameCache.totalLength}B`;
    hexDissectorBox.textContent = Dot1qProtocolEngine.formatHexDump(forgedFrameCache.rawBytes);

    // 2. Native VLAN Hopping Simulation
    const hopSim = Dot1qProtocolEngine.simulateVlanHopping({
      userAccessVlan: currentConfig.userAccessVlan,
      trunkNativeVlan: currentConfig.trunkNativeVlan,
      targetVlan: 100,
      tagNativeEnabled: currentConfig.tagNativeEnabled,
      unusedNativeVlan: currentConfig.unusedNativeVlan
    });

    hoppingDiagTitle.textContent = hopSim.title;
    hoppingDiagDesc.textContent = hopSim.summary;

    if (hopSim.riskLevel === 'CRITICAL') {
      badgeHoppingStatus.textContent = 'EXPLOITABLE';
      badgeHoppingStatus.className = 'badge badge-rose';
      hoppingDiagBanner.className = 'diag-banner diag-critical';
    } else {
      badgeHoppingStatus.textContent = 'PROTECTED';
      badgeHoppingStatus.className = 'badge badge-emerald';
      hoppingDiagBanner.className = 'diag-banner diag-protected';
    }

    // 3. DTP Simulation
    const dtpSim = Dot1qProtocolEngine.simulateDtpSpoofing(currentConfig.dtpMode);
    dtpDiagTitle.textContent = dtpSim.title;
    dtpDiagDesc.textContent = dtpSim.summary;

    if (dtpSim.riskLevel === 'CRITICAL') {
      badgeDtpStatus.textContent = 'VULNERABLE';
      badgeDtpStatus.className = 'badge badge-rose';
      dtpDiagBanner.className = 'diag-banner diag-critical';
    } else if (dtpSim.riskLevel === 'WARN') {
      badgeDtpStatus.textContent = 'DTP ACTIVE';
      badgeDtpStatus.className = 'badge badge-amber';
      dtpDiagBanner.className = 'diag-banner diag-warn';
    } else {
      badgeDtpStatus.textContent = 'NONEGOTIATE';
      badgeDtpStatus.className = 'badge badge-emerald';
      dtpDiagBanner.className = 'diag-banner diag-protected';
    }

    // 4. 10-Point Zero-Trust Security Audit
    const audit = Dot1qSecurityAuditor.auditConfiguration({
      trunkNativeVlan: currentConfig.trunkNativeVlan,
      tagNativeEnabled: currentConfig.tagNativeEnabled,
      dtpMode: currentConfig.dtpMode,
      dtpDisabled: currentConfig.dtpDisabled,
      trunkPruningExplicit: currentConfig.trunkPruningExplicit,
      allowedVlans: currentConfig.allowedVlans,
      accessPortHardened: currentConfig.accessPortHardened,
      isQinQ: currentConfig.isQinQ,
      interfaceMtu: currentConfig.interfaceMtu,
      vtpMode: currentConfig.vtpMode,
      stormControlEnabled: currentConfig.stormControlEnabled,
      bpduGuardActive: currentConfig.bpduGuardActive,
      fhsTrustBoundaryEnforced: currentConfig.fhsTrustBoundaryEnforced
    });

    auditScoreText.textContent = `${audit.score} / 100 Points`;
    auditGradeCircle.textContent = audit.grade;
    auditGradeCircle.className = `grade-circle grade-${audit.grade.toLowerCase().replace('+', 'plus')}`;
    auditScoreBar.style.width = `${audit.score}%`;

    if (audit.passed) {
      auditScoreBar.style.background = 'var(--primary-emerald)';
      auditComplianceText.textContent = 'Zero-Trust Hardened';
      auditComplianceText.style.color = 'var(--primary-emerald)';
      auditStatusBadge.textContent = 'PASSING';
      auditStatusBadge.className = 'badge badge-emerald';
    } else {
      auditScoreBar.style.background = 'var(--primary-rose)';
      auditComplianceText.textContent = 'Non-Compliant / Audit Failure';
      auditComplianceText.style.color = 'var(--primary-rose)';
      auditStatusBadge.textContent = 'CRITICAL FAILS';
      auditStatusBadge.className = 'badge badge-rose';
    }

    // Render findings
    findingsContainer.innerHTML = '';
    audit.findings.forEach(f => {
      const div = document.createElement('div');
      div.className = `finding-item ${f.level.toLowerCase()}`;
      div.innerHTML = `
        <div style="display: flex; justify-content: space-between; font-weight: 700; margin-bottom: 0.2rem;">
          <span>[${f.level}] ${f.id} - ${f.title}</span>
          <span style="font-family: var(--font-mono);">${f.score}/${f.maxPoints} pts</span>
        </div>
        <div style="color: var(--text-muted); font-size: 0.78rem;">${f.finding}</div>
      `;
      findingsContainer.appendChild(div);
    });

    // 5. Update Synthesizer
    renderSynthesizerConfig();
  }

  function renderSynthesizerConfig() {
    const synthParams = {
      trunkNativeVlan: currentConfig.trunkNativeVlan || 999,
      allowedVlans: currentConfig.allowedVlans || '10,20,100,200',
      interfaceMtu: currentConfig.interfaceMtu || 9216,
      isQinQ: currentConfig.isQinQ,
      outerVlan: currentConfig.outerVlan || 500,
      innerVlan: currentConfig.innerVlan || 100
    };

    let text = '';
    if (activeTab === 'cisco-ios') {
      text = Dot1qConfigSynthesizer.synthesizeCiscoIosXe(synthParams);
    } else if (activeTab === 'cisco-nxos') {
      text = Dot1qConfigSynthesizer.synthesizeCiscoNxos(synthParams);
    } else if (activeTab === 'arista') {
      text = Dot1qConfigSynthesizer.synthesizeArista(synthParams);
    } else if (activeTab === 'juniper') {
      text = Dot1qConfigSynthesizer.synthesizeJunos(synthParams);
    } else if (activeTab === 'linux') {
      text = Dot1qConfigSynthesizer.synthesizeLinux(synthParams);
    }
    synthesizerOutputBox.textContent = text;
  }

  // Event Listeners
  [selectTagMode, inputOuterVlan, inputInnerVlan, selectPcp, inputNativeVlan,
   inputInterfaceMtu, inputUserAccessVlan, selectTagNative, selectDtpMode].forEach(el => {
    el.addEventListener('change', readConfigFromUi);
    el.addEventListener('input', readConfigFromUi);
  });

  presetButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      presetButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const presetKey = btn.getAttribute('data-preset');
      if (PRESETS[presetKey]) {
        currentConfig = Object.assign({}, PRESETS[presetKey]);
        updateUiFromConfig();
      }
    });
  });

  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      tabButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      activeTab = btn.getAttribute('data-tab');
      renderSynthesizerConfig();
    });
  });

  btnCopyHex.addEventListener('click', () => {
    navigator.clipboard.writeText(hexDissectorBox.textContent).then(() => {
      btnCopyHex.textContent = 'Copied!';
      setTimeout(() => btnCopyHex.textContent = 'Copy Hex', 2000);
    });
  });

  btnCopyConfig.addEventListener('click', () => {
    navigator.clipboard.writeText(synthesizerOutputBox.textContent).then(() => {
      btnCopyConfig.textContent = 'Copied!';
      setTimeout(() => btnCopyConfig.textContent = 'Copy Config', 2000);
    });
  });

  btnDownloadPcap.addEventListener('click', () => {
    if (!forgedFrameCache) return;
    const pcapBytes = Dot1qProtocolEngine.generatePcap(forgedFrameCache);
    const blob = new Blob([pcapBytes], { type: 'application/vnd.tcpdump.pcap' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `dot1q-frame-${currentConfig.tagMode}-${Date.now()}.pcap`;
    a.click();
    URL.revokeObjectURL(url);
  });

  // Initial load
  updateUiFromConfig();
})();
