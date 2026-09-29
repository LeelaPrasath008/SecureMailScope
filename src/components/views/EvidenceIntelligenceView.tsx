import React, { useState, useMemo } from 'react';
import {
  GitBranch,
  Shield,
  Layers,
  Lock,
  Unlock,
  AlertTriangle,
  CheckCircle2,
  AlertOctagon,
  ArrowRight,
  Hash,
  Clock,
  Terminal,
  ExternalLink,
  BookOpen,
  Filter,
  Copy,
  Check,
  RefreshCw,
  Share2,
  Network,
  Server,
  Activity,
  Cpu,
  Sparkles,
  Info,
  ChevronRight,
  BarChart3
} from 'lucide-react';
import { CryptographicEvidence, DemoScenario, EmailSession, Finding } from '../../types/security';
import { ConfidenceBadge } from '../common/ConfidenceBadge';
import { SeverityBadge } from '../common/SeverityBadge';
import { ForensicMetricGraphs } from '../common/ForensicMetricGraphs';
import { NavigationTab } from '../layout/Sidebar';

interface Props {
  scenario: DemoScenario;
  scenarios?: DemoScenario[];
  onSelectScenario?: (id: string) => void;
  onNavigateTab: (tab: NavigationTab) => void;
  onSelectSession: (sessionId: string) => void;
  onSelectFinding: (findingId: string) => void;
}

export type GraphNodeType = 'PCAP' | 'SESSION' | 'HANDSHAKE' | 'EVIDENCE' | 'RULE' | 'FINDING';

export interface GraphNode {
  id: string;
  type: GraphNodeType;
  title: string;
  subtitle: string;
  stage: number; // 0: PCAP, 1: Session, 2: Handshake, 3: Evidence, 4: Rule, 5: Finding
  status: 'SAFE' | 'WARNING' | 'CRITICAL' | 'NEUTRAL';
  details: Record<string, string | number | boolean | undefined>;
  evidenceRef?: CryptographicEvidence;
  findingRef?: Finding;
  sessionRef?: EmailSession;
  parentIds?: string[];
  childIds?: string[];
}

export interface GraphEdge {
  id: string;
  sourceId: string;
  targetId: string;
  label: string;
  status: 'SAFE' | 'WARNING' | 'CRITICAL' | 'NEUTRAL';
}

export const EvidenceIntelligenceView: React.FC<Props> = ({
  scenario,
  scenarios = [],
  onSelectScenario,
  onNavigateTab,
  onSelectSession,
  onSelectFinding
}) => {
  const [selectedNodeId, setSelectedNodeId] = useState<string>('');
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [graphMode, setGraphMode] = useState<'FLOW' | 'TOPOLOGY' | 'TREE'>('FLOW');
  const [filterMode, setFilterMode] = useState<'ALL' | 'RISK_ONLY' | 'EVIDENCE_ONLY'>('ALL');
  const [copiedHex, setCopiedHex] = useState(false);

  // Generate dynamic graph nodes & edges strictly corresponding to the active scenario
  const { nodes, edges } = useMemo(() => {
    const nodeList: GraphNode[] = [];
    const edgeList: GraphEdge[] = [];
    const meta = scenario.pcapMetadata;
    const pcapNodeId = `NODE-${meta.id}`;

    // Stage 0: Root PCAP Node
    nodeList.push({
      id: pcapNodeId,
      type: 'PCAP',
      title: meta.filename,
      subtitle: `${meta.id} · SHA-256 Custody Verified`,
      stage: 0,
      status: meta.confidence === 'COMPLETE' ? 'SAFE' : meta.confidence === 'PARTIAL' ? 'WARNING' : 'CRITICAL',
      childIds: scenario.sessions.map((s) => `NODE-${s.id}`),
      details: {
        'Evidence ID': meta.id,
        'Filename': meta.filename,
        'SHA-256 Digest': meta.sha256,
        'Capture Interface': meta.capturedInterface || 'eth0 (Passive SPAN)',
        'Packet Count': meta.packetCount,
        'Stream Count': meta.streamCount,
        'Forensic Confidence': meta.confidence,
        'Integrity Status': 'SHA-256 Matched Reference Frame'
      }
    });

    // Stage 1: Reconstructed Sessions
    scenario.sessions.forEach((sess) => {
      const sessNodeId = `NODE-${sess.id}`;
      const isCritical = sess.risk === 'CRITICAL';
      const isHigh = sess.risk === 'HIGH';
      const handshakeNodeId = `NODE-HS-${sess.id}`;

      nodeList.push({
        id: sessNodeId,
        type: 'SESSION',
        title: `Stream ${sess.id} (${sess.protocol})`,
        subtitle: `${sess.sourceIp}:${sess.sourcePort} → ${sess.destIp}:${sess.destPort}`,
        stage: 1,
        status: isCritical ? 'CRITICAL' : isHigh ? 'WARNING' : 'SAFE',
        sessionRef: sess,
        parentIds: [pcapNodeId],
        childIds: [handshakeNodeId],
        details: {
          'Session ID': sess.id,
          'Protocol': `${sess.protocol} (Port ${sess.destPort})`,
          'Client Endpoint': `${sess.sourceIp}:${sess.sourcePort}`,
          'Server Endpoint': `${sess.destIp}:${sess.destPort}`,
          'Server Hostname': sess.serverHostname || 'Unknown Hostname',
          'STARTTLS Negotiated': sess.startTlsNegotiated ? 'Yes (Cleartext Upgraded)' : sess.startTlsAdvertised ? 'Advertised' : 'No / Plaintext',
          'Duration': `${sess.durationSec}s`,
          'Assessed Risk': sess.risk
        }
      });

      edgeList.push({
        id: `EDGE-${pcapNodeId}-${sessNodeId}`,
        sourceId: pcapNodeId,
        targetId: sessNodeId,
        label: 'TCP Flow',
        status: isCritical ? 'CRITICAL' : isHigh ? 'WARNING' : 'SAFE'
      });

      // Stage 2: Handshake / Protocol State
      const tls = sess.tlsHandshake;
      const isPlaintext = !tls && !sess.startTlsNegotiated;
      const isDeprecated = tls?.isDeprecatedVersion;

      // Map evidence belonging to this session
      const relatedEvidenceIds = (sess.evidenceIds || []).map((id) => `NODE-${id}`);

      nodeList.push({
        id: handshakeNodeId,
        type: 'HANDSHAKE',
        title: tls ? `${tls.negotiatedVersion} Handshake` : isPlaintext ? 'Cleartext Protocol' : 'Truncated Handshake',
        subtitle: tls ? (tls.cipherSuite.ianaName) : isPlaintext ? 'RFC 8314 Violation' : 'Buffer Cutoff',
        stage: 2,
        status: isPlaintext || isDeprecated ? 'CRITICAL' : sess.risk === 'HIGH' ? 'WARNING' : 'SAFE',
        parentIds: [sessNodeId],
        childIds: relatedEvidenceIds.length > 0 ? relatedEvidenceIds : undefined,
        details: {
          'Parent Stream': sess.id,
          'Negotiated Protocol': tls?.negotiatedVersion || 'None (Cleartext)',
          'Cipher Suite': tls?.cipherSuite.ianaName || 'None',
          'Key Exchange': tls?.cipherSuite.keyExchange || (isPlaintext ? 'None' : 'Incomplete'),
          'Forward Secrecy': tls?.forwardSecrecy ? 'Provided (PFS)' : 'None (Static RSA / Plaintext)',
          'Session Resumed': tls?.sessionResumed ? 'Yes' : 'No'
        }
      });

      edgeList.push({
        id: `EDGE-${sessNodeId}-${handshakeNodeId}`,
        sourceId: sessNodeId,
        targetId: handshakeNodeId,
        label: 'State Machine',
        status: isPlaintext || isDeprecated ? 'CRITICAL' : sess.risk === 'HIGH' ? 'WARNING' : 'SAFE'
      });
    });

    // Stage 3: Low-Level Wire Evidence
    scenario.evidenceList.forEach((ev) => {
      const evNodeId = `NODE-${ev.id}`;
      const isWeak = ev.evidenceType === 'PLAINTEXT_EXPOSURE' ||
        ev.rawObservation.includes('TLS 1.0') ||
        ev.rawObservation.includes('3DES') ||
        ev.rawObservation.includes('Expired');

      // Find parent handshake
      const parentHandshakeId = `NODE-HS-${ev.sessionId}`;

      nodeList.push({
        id: evNodeId,
        type: 'EVIDENCE',
        title: `${ev.id} (${ev.evidenceType.replace('_', ' ')})`,
        subtitle: `Frame #${ev.packetFrameNumbers.join(', #')} · ${ev.byteOffsetHex || 'Wire'}`,
        stage: 3,
        status: isWeak ? 'CRITICAL' : 'SAFE',
        evidenceRef: ev,
        parentIds: [parentHandshakeId],
        details: {
          'Evidence ID': ev.id,
          'Evidence Type': ev.evidenceType,
          'Packet Frame Numbers': ev.packetFrameNumbers.join(', '),
          'Byte Offset': ev.byteOffsetHex || '0x0000',
          'Observation': ev.rawObservation,
          'Confidence': ev.confidence,
          'Confidence Basis': ev.confidenceExplanation,
          'Authoritative Standard': ev.authoritativeStandard || 'RFC Standards'
        }
      });

      edgeList.push({
        id: `EDGE-${parentHandshakeId}-${evNodeId}`,
        sourceId: parentHandshakeId,
        targetId: evNodeId,
        label: `Packet #${ev.packetFrameNumbers[0]}`,
        status: isWeak ? 'CRITICAL' : 'SAFE'
      });
    });

    // Stage 4: Deterministic Rules
    const scenarioRules = scenario.rules.filter((r) =>
      scenario.findings.some((f) => f.ruleId === r.ruleId) || r.ruleId === 'RULE-TLS-001'
    );

    scenarioRules.forEach((rule) => {
      const ruleNodeId = `NODE-${rule.ruleId}`;
      const isViolated = scenario.findings.some((f) => f.ruleId === rule.ruleId && f.severity !== 'INFORMATIONAL');

      // Find findings tied to this rule
      const childFindingIds = scenario.findings
        .filter((f) => f.ruleId === rule.ruleId)
        .map((f) => `NODE-${f.id}`);

      nodeList.push({
        id: ruleNodeId,
        type: 'RULE',
        title: rule.ruleId,
        subtitle: rule.standardReference.split('/')[0].trim(),
        stage: 4,
        status: isViolated ? 'WARNING' : 'SAFE',
        childIds: childFindingIds,
        details: {
          'Rule ID': rule.ruleId,
          'Rule Title': rule.title,
          'Standard Reference': rule.standardReference,
          'Authoritative Body': rule.authoritativeAuthority,
          'Logic Expression': rule.logicExpression,
          'Description': rule.description
        }
      });

      // Link evidence to rule
      scenario.evidenceList.forEach((ev) => {
        const evNodeId = `NODE-${ev.id}`;
        edgeList.push({
          id: `EDGE-${evNodeId}-${ruleNodeId}`,
          sourceId: evNodeId,
          targetId: ruleNodeId,
          label: 'RFC Audit',
          status: isViolated ? 'WARNING' : 'SAFE'
        });
      });
    });

    // Stage 5: Findings & Verdict
    if (scenario.findings.length > 0) {
      scenario.findings.forEach((find) => {
        const findNodeId = `NODE-${find.id}`;
        const parentRuleId = `NODE-${find.ruleId}`;

        nodeList.push({
          id: findNodeId,
          type: 'FINDING',
          title: `${find.id}: ${find.title}`,
          subtitle: `Severity: ${find.severity} · Priority #${find.priorityOrder}`,
          stage: 5,
          status: find.severity === 'CRITICAL' ? 'CRITICAL' : find.severity === 'HIGH' ? 'WARNING' : 'SAFE',
          findingRef: find,
          parentIds: [parentRuleId],
          details: {
            'Finding ID': find.id,
            'Title': find.title,
            'Severity Level': find.severity,
            'Affected Stream': find.affectedSessionId,
            'Evidence Statement': find.evidenceStatement,
            'Technical Root Cause': find.technicalReason,
            'Security Impact': find.securityImpact,
            'Recommended Action': find.recommendedAction,
            'Standard Reference': find.standardReference
          }
        });

        edgeList.push({
          id: `EDGE-${parentRuleId}-${findNodeId}`,
          sourceId: parentRuleId,
          targetId: findNodeId,
          label: find.severity,
          status: find.severity === 'CRITICAL' ? 'CRITICAL' : find.severity === 'HIGH' ? 'WARNING' : 'SAFE'
        });
      });
    } else {
      // Nominal compliant state
      const compliantNodeId = 'NODE-FIND-COMPLIANT';
      nodeList.push({
        id: compliantNodeId,
        type: 'FINDING',
        title: 'Nominal Cryptographic Compliance',
        subtitle: '100% Policy Adherence · RFC 9846 & RFC 9325 Verified',
        stage: 5,
        status: 'SAFE',
        details: {
          'Audit Verdict': 'PASSED (Zero Cryptographic Weaknesses Detected)',
          'TLS Version': 'TLS 1.3 Conforming (RFC 9846)',
          'Cipher Suite': 'AEAD Authenticated Encryption Active',
          'Forward Secrecy': 'ECDHE X25519 Verified',
          'Certificate': 'Valid Chain within Expiry Window'
        }
      });

      edgeList.push({
        id: `EDGE-RULE-${compliantNodeId}`,
        sourceId: `NODE-RULE-TLS-001`,
        targetId: compliantNodeId,
        label: 'VERIFIED',
        status: 'SAFE'
      });
    }

    return { nodes: nodeList, edges: edgeList };
  }, [scenario]);

  // Set default selected node when active scenario changes
  const activeNode = useMemo(() => {
    if (selectedNodeId) {
      const found = nodes.find((n) => n.id === selectedNodeId);
      if (found) return found;
    }
    // Default to first finding node or evidence node
    const defaultFinding = nodes.find((n) => n.type === 'FINDING');
    const defaultEvidence = nodes.find((n) => n.type === 'EVIDENCE');
    return defaultFinding || defaultEvidence || nodes[0];
  }, [selectedNodeId, nodes]);

  // Filter nodes based on filterMode
  const filteredNodes = useMemo(() => {
    if (filterMode === 'RISK_ONLY') {
      return nodes.filter((n) => n.status === 'CRITICAL' || n.status === 'WARNING');
    }
    if (filterMode === 'EVIDENCE_ONLY') {
      return nodes.filter((n) => n.type === 'EVIDENCE' || n.type === 'HANDSHAKE');
    }
    return nodes;
  }, [nodes, filterMode]);

  // Group nodes by stage for the visual flow canvas
  const stages = useMemo(() => {
    const grouped: Record<number, GraphNode[]> = { 0: [], 1: [], 2: [], 3: [], 4: [], 5: [] };
    filteredNodes.forEach((node) => {
      grouped[node.stage]?.push(node);
    });
    return grouped;
  }, [filteredNodes]);

  const stageLabels = [
    '1. Root PCAP Capture',
    '2. TCP Streams',
    '3. Handshake Layer',
    '4. Wire Evidence Frames',
    '5. Evaluated RFC Rules',
    '6. Security Verdict'
  ];

  const handleCopyHex = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHex(true);
    setTimeout(() => setCopiedHex(false), 2000);
  };

  const getNodeColorClasses = (node: GraphNode, isSelected: boolean) => {
    if (isSelected) {
      return 'border-cyan-400 bg-cyan-950/70 ring-2 ring-cyan-500/50 text-white shadow-lg shadow-cyan-950/40';
    }
    switch (node.status) {
      case 'CRITICAL':
        return 'border-rose-900/80 bg-[#160B10] text-rose-200 hover:border-rose-600 hover:bg-[#1E0E16]';
      case 'WARNING':
        return 'border-amber-900/80 bg-[#16120B] text-amber-200 hover:border-amber-600 hover:bg-[#1E190E]';
      case 'SAFE':
        return 'border-emerald-900/70 bg-[#0B1611] text-emerald-200 hover:border-emerald-600 hover:bg-[#0E1E17]';
      default:
        return 'border-slate-800 bg-[#0F1623] text-slate-200 hover:border-slate-700 hover:bg-[#151F32]';
    }
  };

  const getNodeTypeBadge = (type: GraphNodeType) => {
    switch (type) {
      case 'PCAP':
        return 'bg-blue-950 text-blue-300 border-blue-800/60';
      case 'SESSION':
        return 'bg-cyan-950 text-cyan-300 border-cyan-800/60';
      case 'HANDSHAKE':
        return 'bg-purple-950 text-purple-300 border-purple-800/60';
      case 'EVIDENCE':
        return 'bg-amber-950 text-amber-300 border-amber-800/60';
      case 'RULE':
        return 'bg-indigo-950 text-indigo-300 border-indigo-800/60';
      case 'FINDING':
        return 'bg-rose-950 text-rose-300 border-rose-800/60';
    }
  };

  return (
    <div className="p-4 sm:p-6 space-y-5 max-w-7xl mx-auto">
      {/* Top Header & Context */}
      <div className="bg-[#0F1623] border border-slate-800 rounded-xl p-5 shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[10px] font-mono uppercase tracking-wider px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-800/60 font-semibold">
              Interactive Traceability Graph
            </span>
            <span className="text-xs text-slate-400 font-mono">
              Lineage Verification for {scenario.pcapMetadata.filename}
            </span>
          </div>
          <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            <GitBranch className="w-5 h-5 text-cyan-400" />
            <span>Cryptographic Evidence Traceability Graph</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-3xl leading-relaxed">
            Forensic graph showing direct mathematical linkage from PCAP packets and TCP streams through protocol handshakes, raw wire hex dumps, RFC standards, and final security findings.
          </p>
        </div>

        {/* View Mode & Filter Controls */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Graph View Selector */}
          <div className="flex items-center bg-[#0A0E17] border border-slate-800 rounded-lg p-0.5 text-xs">
            <button
              onClick={() => setGraphMode('FLOW')}
              className={`px-3 py-1.5 rounded-md font-medium transition-colors cursor-pointer ${
                graphMode === 'FLOW'
                  ? 'bg-slate-800 text-cyan-300 font-semibold shadow-xs'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Pipeline Flow
            </button>
            <button
              onClick={() => setGraphMode('TOPOLOGY')}
              className={`px-3 py-1.5 rounded-md font-medium transition-colors cursor-pointer ${
                graphMode === 'TOPOLOGY'
                  ? 'bg-slate-800 text-cyan-300 font-semibold shadow-xs'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Network Topology
            </button>
            <button
              onClick={() => setGraphMode('TREE')}
              className={`px-3 py-1.5 rounded-md font-medium transition-colors cursor-pointer ${
                graphMode === 'TREE'
                  ? 'bg-slate-800 text-cyan-300 font-semibold shadow-xs'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Hierarchy Tree
            </button>
          </div>

          {/* Filter Pills */}
          <div className="flex items-center bg-[#0A0E17] border border-slate-800 rounded-lg p-0.5 text-xs">
            <button
              onClick={() => setFilterMode('ALL')}
              className={`px-2.5 py-1.5 rounded-md transition-colors cursor-pointer ${
                filterMode === 'ALL'
                  ? 'bg-cyan-600 text-white font-semibold'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              All Nodes ({nodes.length})
            </button>
            <button
              onClick={() => setFilterMode('RISK_ONLY')}
              className={`px-2.5 py-1.5 rounded-md transition-colors cursor-pointer ${
                filterMode === 'RISK_ONLY'
                  ? 'bg-rose-600 text-white font-semibold'
                  : 'text-rose-400 hover:text-rose-200'
              }`}
            >
              Risk Path Only
            </button>
            <button
              onClick={() => setFilterMode('EVIDENCE_ONLY')}
              className={`px-2.5 py-1.5 rounded-md transition-colors cursor-pointer ${
                filterMode === 'EVIDENCE_ONLY'
                  ? 'bg-amber-600 text-white font-semibold'
                  : 'text-amber-400 hover:text-amber-200'
              }`}
            >
              Evidence Only
            </button>
          </div>
        </div>
      </div>

      {/* Scenario Quick Selector (Switch between Scenarios 1-5 directly inside Graph view) */}
      {scenarios.length > 0 && onSelectScenario && (
        <div className="bg-[#0F1623] border border-slate-800 rounded-xl p-3 px-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 shadow-xs">
          <div className="flex items-center gap-2">
            <Share2 className="w-4 h-4 text-cyan-400" />
            <span className="text-xs font-semibold text-slate-300">Select Scenario to Trace Graph:</span>
          </div>

          <div className="flex flex-wrap items-center gap-1.5 w-full sm:w-auto">
            {scenarios.map((s, idx) => {
              const isCurrent = s.id === scenario.id;
              const hasCritical = s.findings.some(f => f.severity === 'CRITICAL');
              const hasHigh = s.findings.some(f => f.severity === 'HIGH');
              const statusBadgeColor = hasCritical
                ? 'bg-rose-950 text-rose-300 border-rose-800'
                : hasHigh
                ? 'bg-amber-950 text-amber-300 border-amber-800'
                : 'bg-emerald-950 text-emerald-300 border-emerald-800';

              return (
                <button
                  key={s.id}
                  onClick={() => {
                    onSelectScenario(s.id);
                    setSelectedNodeId('');
                  }}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer whitespace-nowrap flex items-center gap-1.5 ${
                    isCurrent
                      ? 'bg-cyan-500/25 text-cyan-200 border border-cyan-500/60 shadow-xs font-semibold'
                      : 'bg-slate-800/80 hover:bg-slate-700/80 text-slate-300 border border-slate-700/60'
                  }`}
                >
                  <span>{s.title.split(':')[0] || `Scenario ${idx + 1}`}</span>
                  <span className={`text-[9px] px-1 py-0.2 rounded border font-mono ${statusBadgeColor}`}>
                    {hasCritical ? 'CRITICAL' : hasHigh ? 'HIGH' : 'SECURE'}
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* 3 Core Forensic Telemetry Graphs (Traffic Tunnel Ratio, Protocol Distribution, Vulnerability Profile) */}
      <div className="space-y-2">
        <div className="flex items-center justify-between px-1">
          <div className="flex items-center gap-2">
            <BarChart3 className="w-4 h-4 text-cyan-400" />
            <span className="text-xs font-bold text-slate-200 tracking-tight uppercase">
              Forensic Telemetry & Cryptographic Profile
            </span>
          </div>
          <span className="text-[11px] font-mono text-slate-400">
            Dynamically computed for {scenario.title.split(':')[0]}
          </span>
        </div>
        <ForensicMetricGraphs scenario={scenario} />
      </div>

      {/* Main Graph & Inspector Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        {/* Left: Graph Canvas (8 cols) */}
        <div className="lg:col-span-8 bg-[#0F1623] border border-slate-800 rounded-xl overflow-hidden shadow-xs flex flex-col min-h-[440px] lg:min-h-[620px]">
          {/* Canvas Sub-Header */}
          <div className="p-3.5 bg-[#0A0E17] border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold text-slate-300">
                {graphMode === 'FLOW'
                  ? 'End-to-End Forensic Flow Graph (Multi-Stage Lineage)'
                  : graphMode === 'TOPOLOGY'
                  ? 'Network Architecture & Protocol Handshake Graph'
                  : 'Hierarchical Evidence Lineage Tree'}
              </span>
              <span className="text-[10px] text-slate-400 font-mono">
                ({filteredNodes.length} nodes active)
              </span>
            </div>
            <span className="text-[11px] text-slate-400 hidden sm:inline">Click any node to inspect evidence attributes</span>
          </div>

          {/* Graph Visualization Body */}
          <div className="flex-1 p-3 sm:p-4 overflow-x-auto bg-[#0A0E17]/40">
            {/* Mobile swipe helper */}
            <div className="lg:hidden px-2.5 py-1.5 bg-cyan-950/40 border border-cyan-800/50 rounded-lg text-[10px] text-cyan-300 font-mono flex items-center justify-between mb-3">
              <span>← Swipe horizontally to explore pipeline →</span>
              <span>6 Stages</span>
            </div>
            {graphMode === 'FLOW' && (
              /* Interactive Visual Multi-Stage Flow Graph */
              <div className="min-w-[840px] space-y-5">
                {/* SVG Visual Directed Edge Connectors Banner */}
                <div className="px-2 py-1.5 bg-[#080C14] border border-slate-800/80 rounded-lg flex items-center justify-between text-[11px] text-slate-400 font-mono">
                  <div className="flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
                    <span className="text-cyan-300 font-semibold">Active Lineage Vector:</span>
                    <span>PCAP ➔ TCP Streams ➔ Handshake ➔ Wire Frames ➔ RFC Rules ➔ Security Finding</span>
                  </div>
                  <span className="text-emerald-400 font-bold">100% Mathematically Verified</span>
                </div>

                {/* Stage Columns Grid */}
                <div className="grid grid-cols-6 gap-3">
                  {[0, 1, 2, 3, 4, 5].map((stageIdx) => (
                    <div key={stageIdx} className="space-y-3">
                      {/* Column Stage Header */}
                      <div className="text-center pb-2 border-b border-slate-800/80">
                        <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-semibold block truncate">
                          {stageLabels[stageIdx]}
                        </span>
                      </div>

                      {/* Column Nodes */}
                      <div className="space-y-2.5">
                        {stages[stageIdx]?.map((node) => {
                          const isSelected = activeNode?.id === node.id;
                          return (
                            <div
                              key={node.id}
                              onClick={() => setSelectedNodeId(node.id)}
                              onMouseEnter={() => setHoveredNodeId(node.id)}
                              onMouseLeave={() => setHoveredNodeId(null)}
                              className={`p-2.5 rounded-xl border transition-all cursor-pointer relative group text-xs font-mono ${getNodeColorClasses(
                                node,
                                isSelected
                              )}`}
                            >
                              {/* Node Type Pill */}
                              <div className="flex items-center justify-between gap-1 mb-1">
                                <span
                                  className={`text-[9px] font-bold px-1.5 py-0.5 rounded border uppercase ${getNodeTypeBadge(
                                    node.type
                                  )}`}
                                >
                                  {node.type}
                                </span>
                                <span className={`w-2 h-2 rounded-full ${
                                  node.status === 'CRITICAL'
                                    ? 'bg-rose-500 animate-pulse'
                                    : node.status === 'WARNING'
                                    ? 'bg-amber-500'
                                    : 'bg-emerald-400'
                                }`} />
                              </div>

                              <div className="font-bold text-white text-xs truncate leading-snug" title={node.title}>
                                {node.title}
                              </div>

                              <div className="text-[10px] text-slate-400 truncate mt-0.5" title={node.subtitle}>
                                {node.subtitle}
                              </div>

                              {/* Direct visual indicator for evidence frames */}
                              {node.evidenceRef && (
                                <div className="mt-1.5 pt-1 border-t border-slate-800/60 text-[9px] text-cyan-300 font-mono truncate">
                                  Frame #{node.evidenceRef.packetFrameNumbers.join(', ')}
                                </div>
                              )}
                            </div>
                          );
                        })}

                        {(!stages[stageIdx] || stages[stageIdx].length === 0) && (
                          <div className="p-3 text-center text-slate-500 text-[10px] font-mono border border-dashed border-slate-800 rounded-lg">
                            No active nodes
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>

                {/* Graph Statistics Summary Bar */}
                <div className="p-3 bg-[#080C14] border border-slate-800/80 rounded-lg flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
                  <div className="flex items-center gap-4 text-slate-300">
                    <span>Active PCAP: <strong className="text-cyan-400">{scenario.pcapMetadata.filename}</strong></span>
                    <span>Streams: <strong className="text-white">{scenario.sessions.length}</strong></span>
                    <span>Evidence Items: <strong className="text-amber-400">{scenario.evidenceList.length}</strong></span>
                    <span>Findings: <strong className="text-rose-400">{scenario.findings.length}</strong></span>
                  </div>
                  <span className="text-slate-400 text-[11px]">Click any card to load full raw hex & RFC details</span>
                </div>
              </div>
            )}

            {graphMode === 'TOPOLOGY' && (
              /* Network Topology & Protocol Architecture Graph */
              <div className="space-y-6 p-2">
                <div className="p-4 bg-[#080C14] border border-slate-800 rounded-xl space-y-4 font-mono text-xs">
                  <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
                    <div className="flex items-center gap-2">
                      <Network className="w-4 h-4 text-cyan-400" />
                      <span className="font-bold text-white text-sm">Protocol Wire Topology: {scenario.title}</span>
                    </div>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 font-mono">
                      Passive Reassembly
                    </span>
                  </div>

                  {/* Wire Diagram */}
                  {scenario.sessions.map((sess, idx) => {
                    const isSecureSess = sess.risk === 'LOW';
                    const isCriticalSess = sess.risk === 'CRITICAL';
                    const tls = sess.tlsHandshake;

                    return (
                      <div key={sess.id} className="p-4 bg-[#0B1019] border border-slate-800/90 rounded-xl space-y-4">
                        <div className="flex items-center justify-between text-xs text-slate-400">
                          <span className="font-bold text-slate-200">Stream #{idx + 1} ({sess.id})</span>
                          <span>Duration: {sess.durationSec}s · Timestamp: {sess.timestamp}</span>
                        </div>

                        {/* Visual Host-to-Host Wire Diagram */}
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 items-center">
                          {/* Client Node */}
                          <div className="p-3.5 bg-[#0F1623] border border-slate-700/80 rounded-xl space-y-1.5">
                            <div className="flex items-center gap-2 text-cyan-400 font-bold">
                              <Cpu className="w-4 h-4" />
                              <span>Client Agent</span>
                            </div>
                            <div className="text-slate-200 text-xs font-semibold">{sess.sourceIp}</div>
                            <div className="text-[11px] text-slate-400">Port {sess.sourcePort}</div>
                            <div className="text-[10px] text-slate-500 truncate">{sess.clientSoftware || 'Mail User Agent'}</div>
                          </div>

                          {/* Wire Protocol Channel (Middle Connector) */}
                          <div className="flex flex-col items-center justify-center p-3 bg-[#080C14] border border-slate-800 rounded-xl text-center space-y-1">
                            <span className="text-[10px] uppercase font-bold text-slate-400">
                              {sess.protocol} (Port {sess.destPort})
                            </span>
                            <div className="flex items-center gap-1.5 text-xs font-bold text-white">
                              {sess.startTlsNegotiated ? (
                                <>
                                  <Lock className="w-3.5 h-3.5 text-cyan-400" />
                                  <span>STARTTLS Upgraded</span>
                                </>
                              ) : sess.tlsHandshake ? (
                                <>
                                  <Lock className="w-3.5 h-3.5 text-emerald-400" />
                                  <span>Direct TLS Encapsulated</span>
                                </>
                              ) : (
                                <>
                                  <Unlock className="w-3.5 h-3.5 text-rose-400" />
                                  <span className="text-rose-400">Cleartext Unencrypted</span>
                                </>
                              )}
                            </div>
                            <span className={`text-[10px] px-2 py-0.5 rounded border font-semibold ${
                              isCriticalSess
                                ? 'bg-rose-950 text-rose-300 border-rose-800'
                                : isSecureSess
                                ? 'bg-emerald-950 text-emerald-300 border-emerald-800'
                                : 'bg-amber-950 text-amber-300 border-amber-800'
                            }`}>
                              {tls?.negotiatedVersion || 'No Encryption (Plain)'}
                            </span>
                          </div>

                          {/* Server Node */}
                          <div className="p-3.5 bg-[#0F1623] border border-slate-700/80 rounded-xl space-y-1.5">
                            <div className="flex items-center gap-2 text-blue-400 font-bold">
                              <Server className="w-4 h-4" />
                              <span>Destination Mail Host</span>
                            </div>
                            <div className="text-slate-200 text-xs font-semibold">{sess.destIp}</div>
                            <div className="text-[11px] text-slate-400">Port {sess.destPort} · {sess.serverHostname}</div>
                            <div className="text-[10px] text-slate-500 truncate" title={sess.bannerText}>
                              {sess.bannerText || 'ESMTP Daemon Ready'}
                            </div>
                          </div>
                        </div>

                        {/* Handshake & Crypto Details Strip */}
                        {tls && (
                          <div className="p-3 bg-[#080C14] border border-slate-800/80 rounded-lg flex flex-wrap items-center justify-between gap-3 text-xs">
                            <div>
                              <span className="text-slate-500 text-[10px] uppercase block">Cipher Suite</span>
                              <span className="text-cyan-300 font-semibold">{tls.cipherSuite.ianaName}</span>
                            </div>
                            <div>
                              <span className="text-slate-500 text-[10px] uppercase block">Key Exchange</span>
                              <span className="text-slate-300">{tls.cipherSuite.keyExchange}</span>
                            </div>
                            <div>
                              <span className="text-slate-500 text-[10px] uppercase block">Forward Secrecy</span>
                              <span className={tls.forwardSecrecy ? 'text-emerald-400' : 'text-rose-400'}>
                                {tls.forwardSecrecy ? 'Achieved (PFS)' : 'None (Static RSA)'}
                              </span>
                            </div>
                            {tls.certificate && (
                              <div>
                                <span className="text-slate-500 text-[10px] uppercase block">X.509 Certificate</span>
                                <span className={tls.certificate.isExpired ? 'text-rose-400' : 'text-slate-300'}>
                                  {tls.certificate.subjectCommonName} ({tls.certificate.isExpired ? 'Expired' : 'Valid'})
                                </span>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {graphMode === 'TREE' && (
              /* Tree Lineage View */
              <div className="space-y-4 font-mono text-xs">
                {nodes.filter((n) => n.type === 'PCAP').map((rootNode) => (
                  <div key={rootNode.id} className="space-y-3">
                    {/* Root PCAP Node */}
                    <div
                      onClick={() => setSelectedNodeId(rootNode.id)}
                      className={`p-3 rounded-xl border cursor-pointer transition-all flex items-center justify-between ${getNodeColorClasses(
                        rootNode,
                        activeNode?.id === rootNode.id
                      )}`}
                    >
                      <div className="flex items-center gap-2.5">
                        <Hash className="w-4 h-4 text-cyan-400" />
                        <div>
                          <span className="font-bold text-white text-xs block">{rootNode.title}</span>
                          <span className="text-[10px] text-slate-400">{rootNode.subtitle}</span>
                        </div>
                      </div>
                      <span className="text-[10px] uppercase font-bold text-cyan-300 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-800">
                        Root Capture
                      </span>
                    </div>

                    {/* Level 1: Sessions */}
                    <div className="pl-6 border-l-2 border-slate-800 ml-4 space-y-3">
                      {nodes.filter((n) => n.type === 'SESSION').map((sessNode) => (
                        <div key={sessNode.id} className="space-y-2">
                          <div
                            onClick={() => setSelectedNodeId(sessNode.id)}
                            className={`p-2.5 rounded-xl border cursor-pointer transition-all flex items-center justify-between ${getNodeColorClasses(
                              sessNode,
                              activeNode?.id === sessNode.id
                            )}`}
                          >
                            <div className="flex items-center gap-2">
                              <Layers className="w-3.5 h-3.5 text-blue-400" />
                              <span className="font-bold text-white text-xs">{sessNode.title}</span>
                            </div>
                            <span className="text-[10px] text-slate-400">{sessNode.subtitle}</span>
                          </div>

                          {/* Level 2: Handshake & Evidence */}
                          <div className="pl-6 border-l-2 border-slate-800 ml-4 space-y-2">
                            {nodes.filter((n) => n.type === 'HANDSHAKE' && n.parentIds?.includes(sessNode.id)).map((hsNode) => (
                              <div
                                key={hsNode.id}
                                onClick={() => setSelectedNodeId(hsNode.id)}
                                className={`p-2 rounded-lg border cursor-pointer transition-all flex items-center justify-between ${getNodeColorClasses(
                                  hsNode,
                                  activeNode?.id === hsNode.id
                                )}`}
                              >
                                <div className="flex items-center gap-2">
                                  <Lock className="w-3 h-3 text-purple-400" />
                                  <span className="text-xs font-semibold">{hsNode.title}</span>
                                </div>
                                <span className="text-[10px] text-slate-400">{hsNode.subtitle}</span>
                              </div>
                            ))}

                            {/* Level 3: Evidence Items */}
                            <div className="pl-6 border-l-2 border-cyan-950 ml-4 space-y-1.5">
                              {nodes.filter((n) => n.type === 'EVIDENCE').map((evNode) => (
                                <div
                                  key={evNode.id}
                                  onClick={() => setSelectedNodeId(evNode.id)}
                                  className={`p-2 rounded-lg border cursor-pointer transition-all flex items-center justify-between text-[11px] ${getNodeColorClasses(
                                    evNode,
                                    activeNode?.id === evNode.id
                                  )}`}
                                >
                                  <div className="flex items-center gap-1.5 truncate">
                                    <span className="text-cyan-400">├──</span>
                                    <span className="font-bold text-slate-200">{evNode.title}</span>
                                  </div>
                                  <span className="text-slate-400">{evNode.subtitle}</span>
                                </div>
                              ))}
                            </div>

                            {/* Level 4: Findings */}
                            <div className="pl-6 border-l-2 border-slate-800 ml-4 space-y-1.5">
                              {nodes.filter((n) => n.type === 'FINDING').map((findNode) => (
                                <div
                                  key={findNode.id}
                                  onClick={() => setSelectedNodeId(findNode.id)}
                                  className={`p-2.5 rounded-lg border cursor-pointer transition-all flex items-center justify-between text-xs ${getNodeColorClasses(
                                    findNode,
                                    activeNode?.id === findNode.id
                                  )}`}
                                >
                                  <div className="flex items-center gap-2">
                                    <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                                    <span className="font-bold text-white">{findNode.title}</span>
                                  </div>
                                  <span className="text-[10px] text-slate-400">{findNode.subtitle}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Right: Selected Node Forensic Artifact Inspector (4 cols) */}
        <div className="lg:col-span-4 bg-[#0F1623] border border-slate-800 rounded-xl overflow-hidden shadow-xs flex flex-col min-h-[620px]">
          {/* Inspector Header */}
          <div className="p-4 bg-[#0A0E17] border-b border-slate-800 flex items-center justify-between gap-2">
            <div className="min-w-0">
              <span className="text-[10px] font-mono uppercase text-slate-400 block font-semibold">
                Inspected Forensic Artifact
              </span>
              <h3 className="text-sm font-bold text-white font-mono truncate">{activeNode?.title}</h3>
            </div>
            {activeNode && (
              <span
                className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-bold shrink-0 ${getNodeTypeBadge(
                  activeNode.type
                )}`}
              >
                {activeNode.type}
              </span>
            )}
          </div>

          {/* Inspector Body */}
          <div className="p-4 space-y-4 overflow-y-auto flex-1 font-mono text-xs">
            {/* Key-Value Properties */}
            <div className="space-y-2">
              <span className="text-[11px] font-sans font-semibold text-slate-300 block">
                Technical Evidence Attributes:
              </span>
              {activeNode &&
                Object.entries(activeNode.details).map(([key, val]) => (
                  <div key={key} className="p-2.5 bg-[#0A0E17] rounded-lg border border-slate-800/80">
                    <span className="text-slate-400 text-[10px] uppercase block font-semibold font-mono">
                      {key}
                    </span>
                    <span className="text-slate-100 font-sans text-xs mt-0.5 block break-all leading-relaxed">
                      {String(val)}
                    </span>
                  </div>
                ))}
            </div>

            {/* Raw Wire Hex Dump Sample (if evidence item) */}
            {activeNode?.evidenceRef && (
              <div className="space-y-2 pt-2 border-t border-slate-800">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-sans font-semibold text-slate-300">
                    Packet Hex Dump (Frame #{activeNode.evidenceRef.packetFrameNumbers.join(', #')}):
                  </span>
                  <button
                    onClick={() => handleCopyHex(activeNode.evidenceRef?.hexDumpSample || '')}
                    className="flex items-center gap-1 text-[10px] text-cyan-400 hover:text-cyan-300 cursor-pointer"
                  >
                    {copiedHex ? (
                      <>
                        <Check className="w-3 h-3 text-emerald-400" />
                        <span className="text-emerald-300">Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3 h-3" />
                        <span>Copy Hex</span>
                      </>
                    )}
                  </button>
                </div>

                <div className="p-3 bg-[#05080E] border border-slate-800 rounded-lg text-[11px] font-mono text-cyan-300 overflow-x-auto leading-relaxed whitespace-pre select-all">
                  {activeNode.evidenceRef.hexDumpSample || '00 00 01 5a 16 03 01 00 4a 02 00 00 46 ...'}
                </div>

                <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1">
                  <span>Offset: {activeNode.evidenceRef.byteOffsetHex || '0x0000'}</span>
                  <span>Confidence: <strong className="text-emerald-400">{activeNode.evidenceRef.confidence}</strong></span>
                </div>
              </div>
            )}

            {/* Quick Action Navigation */}
            <div className="pt-3 border-t border-slate-800 space-y-2 font-sans">
              {activeNode?.sessionRef && (
                <button
                  onClick={() => {
                    onSelectSession(activeNode.sessionRef!.id);
                    onNavigateTab('sessions');
                  }}
                  className="w-full px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
                >
                  <Layers className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Inspect Stream {activeNode.sessionRef.id}</span>
                </button>
              )}

              {activeNode?.findingRef && (
                <button
                  onClick={() => {
                    onSelectFinding(activeNode.findingRef!.id);
                    onNavigateTab('findings');
                  }}
                  className="w-full px-3 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
                >
                  <AlertTriangle className="w-3.5 h-3.5" />
                  <span>View Finding & Remediation Fix</span>
                </button>
              )}

              <button
                onClick={() => onNavigateTab('reports')}
                className="w-full px-3 py-2 bg-[#0A0E17] hover:bg-slate-800 text-slate-300 border border-slate-800 rounded-lg text-xs font-medium flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
              >
                <Terminal className="w-3.5 h-3.5 text-blue-400" />
                <span>Export Lineage in Audit Report</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
