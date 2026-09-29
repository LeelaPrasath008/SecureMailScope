import React, { useState } from 'react';
import {
  X,
  ChevronRight,
  ChevronLeft,
  CheckCircle2,
  FileSearch,
  Layers,
  Lock,
  AlertTriangle,
  GitBranch,
  Cpu,
  ShieldAlert,
  FileText,
  ArrowRight
} from 'lucide-react';
import { NavigationTab } from '../layout/Sidebar';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  onNavigateTab: (tab: NavigationTab) => void;
  onSelectSession?: (sessionId: string) => void;
  onSelectFinding?: (findingId: string) => void;
}

interface DemoStep {
  step: number;
  title: string;
  targetTab: NavigationTab;
  category: string;
  icon: any;
  summary: string;
  technicalConcept: string;
  evidenceAnchor: string;
  actionLabel: string;
}

export const GuidedDemoModal: React.FC<Props> = ({
  isOpen,
  onClose,
  onNavigateTab,
  onSelectSession,
  onSelectFinding
}) => {
  const [currentStepIndex, setCurrentStepIndex] = useState(0);

  if (!isOpen) return null;

  const steps: DemoStep[] = [
    {
      step: 1,
      title: 'PCAP Ingestion & Passive Evidence Capture',
      targetTab: 'pcap_analysis',
      category: 'FORENSIC INGESTION',
      icon: FileSearch,
      summary: 'Demonstrates passive traffic ingestion with verifiable SHA-256 evidence integrity hashing and no live interception.',
      technicalConcept: 'Zero packet modification; digital forensic custody established via 64-character SHA-256 hash.',
      evidenceAnchor: 'Evidence ID: PCAP-2026-002 (exchange_edge_smtp_tls10_sweet32.pcapng)',
      actionLabel: 'View Ingestion & Metadata'
    },
    {
      step: 2,
      title: '12-Stage Dissection Pipeline',
      targetTab: 'pcap_analysis',
      category: 'PIPELINE ARCHITECTURE',
      icon: Layers,
      summary: 'Shows deterministic packet parsing: TCP reconstruction → protocol identification → STARTTLS tracking → TLS handshake dissection.',
      technicalConcept: 'Deterministic rules parse bytes into structured forensic artifacts before any AI involvement.',
      evidenceAnchor: '1,420 packets reassembled into 18 bidirectional application streams.',
      actionLabel: 'Inspect Analysis Pipeline'
    },
    {
      step: 3,
      title: 'Reconstructed SMTP Session (SES-014)',
      targetTab: 'sessions',
      category: 'SESSION RECONSTRUCTION',
      icon: Layers,
      summary: 'Inspects complete client-server email dialogue on port 25, from TCP SYN to banner, EHLO, and STARTTLS state transition.',
      technicalConcept: 'State machine reconstruction tracks protocol transitions across the cleartext-to-TLS boundary.',
      evidenceAnchor: 'SES-014: 198.51.100.44:51240 → 203.0.113.25:25 (mail.legacy-corp.example.com)',
      actionLabel: 'Inspect Reconstructed Session'
    },
    {
      step: 4,
      title: 'Low-Level TLS & Cryptographic Evidence',
      targetTab: 'evidence',
      category: 'CRYPTOGRAPHIC DISSECTION',
      icon: Lock,
      summary: 'Inspects raw byte offsets and hex dumps showing Server Hello negotiation of TLS 1.0 (0x0301) and 3DES-CBC cipher (0x000A).',
      technicalConcept: 'Definitive cryptographic facts are extracted from wire evidence, not guessed or hallucinated.',
      evidenceAnchor: 'EVD-014-TLS: Packet #34 offset 0x0000015A (Version 0x0301)',
      actionLabel: 'View Raw Evidence Offsets'
    },
    {
      step: 5,
      title: 'Evidence-Linked Finding (FIND-014 & FIND-015)',
      targetTab: 'findings',
      category: 'DETERMINISTIC RULES',
      icon: AlertTriangle,
      summary: 'Deterministic security rules bind wire evidence directly to standards violations: RFC 8996 (TLS 1.0/1.1 Deprecation) and CVE-2016-2183 Sweet32.',
      technicalConcept: 'Every finding explicitly cites the violated rule, authoritative standard, impact, and wire evidence frame.',
      evidenceAnchor: 'Rule: RULE-TLS-001 (RFC 8996 & RFC 9325 Deprecated TLS Version Policy)',
      actionLabel: 'View Deterministic Findings'
    },
    {
      step: 6,
      title: 'Evidence Intelligence & Traceability Chain',
      targetTab: 'evidence',
      category: 'TRACEABILITY GRAPH',
      icon: GitBranch,
      summary: 'Interactive correlation tree proving end-to-end lineage: PCAP → Session → Handshake → Crypto Evidence → Rule → Finding.',
      technicalConcept: 'Eliminates black-box ambiguity; evaluators can trace every risk decision back to packet frames.',
      evidenceAnchor: 'Traceability Tree: PCAP-2026-002 ➔ SES-014 ➔ Handshake ➔ FIND-014',
      actionLabel: 'Explore Traceability Graph'
    },
    {
      step: 7,
      title: 'AI-Assisted Grounded Reasoning',
      targetTab: 'ai_reasoning',
      category: 'GROUNDED AI ANALYSIS',
      icon: Cpu,
      summary: 'AI receives structured JSON evidence (not raw packets) and evaluates compound risk interactions and triage urgency.',
      technicalConcept: 'AI does not invent cryptographic facts; it synthesizes how multiple weaknesses (e.g. 3DES + No PFS) compound risk.',
      evidenceAnchor: 'Structured Input: { tls_version: "TLS 1.0", cipher: "3DES", forward_secrecy: false }',
      actionLabel: 'View AI Grounded Reasoning'
    },
    {
      step: 8,
      title: 'Actionable Remediation & What-If Simulator',
      targetTab: 'posture',
      category: 'WHAT-IF SIMULATION',
      icon: ShieldAlert,
      summary: 'Interactive toggles simulate server policy hardening (disabling TLS 1.0, removing 3DES) and project posture changes.',
      technicalConcept: 'Allows security architects to project the risk reduction of planned MTA configuration updates.',
      evidenceAnchor: 'Projected Posture: AT RISK ➔ SECURE (100% Risk Reduction simulated)',
      actionLabel: 'Test What-If Remediation'
    },
    {
      step: 9,
      title: 'Executive & Technical Security Posture Report',
      targetTab: 'reports',
      category: 'AUDIT REPORTING',
      icon: FileText,
      summary: 'Generates comprehensive compliance audit reports incorporating evidence SHA-256, protocol summaries, and RFC citations.',
      technicalConcept: 'Exports verifiable PDF/HTML/JSON reports suitable for executive stakeholders and compliance auditors.',
      evidenceAnchor: 'SHA-256 Digest: 7b2a9f4c3d81e05a8b291ca8234fd6e902187a552bf891c01e9a38210459a112',
      actionLabel: 'Generate Audit Report'
    }
  ];

  const current = steps[currentStepIndex];

  const handleExecuteStep = () => {
    onNavigateTab(current.targetTab);
    if (current.step === 3 && onSelectSession) {
      onSelectSession('SES-014');
    }
    if (current.step === 5 && onSelectFinding) {
      onSelectFinding('FIND-014');
    }
    onClose();
  };

  const handleNext = () => {
    if (currentStepIndex < steps.length - 1) {
      setCurrentStepIndex(currentStepIndex + 1);
    }
  };

  const handlePrev = () => {
    if (currentStepIndex > 0) {
      setCurrentStepIndex(currentStepIndex - 1);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="bg-[#0D121D] border border-slate-700/80 rounded-lg max-w-2xl w-full shadow-2xl flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800/60 font-semibold tracking-wider uppercase">
                Step {current.step} of {steps.length}
              </span>
              <span className="text-xs font-mono text-slate-400">SIH Evaluator Guided Tour</span>
            </div>
            <h2 className="text-lg font-bold text-white mt-1">{current.title}</h2>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Step Progress Indicators */}
        <div className="px-6 py-2.5 bg-[#090D14] border-b border-slate-800/80 flex items-center justify-between gap-1 overflow-x-auto">
          {steps.map((s, idx) => (
            <button
              key={s.step}
              onClick={() => setCurrentStepIndex(idx)}
              className={`flex-1 min-w-[28px] h-1.5 rounded transition-all cursor-pointer ${
                idx === currentStepIndex
                  ? 'bg-cyan-400 ring-2 ring-cyan-500/30'
                  : idx < currentStepIndex
                  ? 'bg-emerald-500'
                  : 'bg-slate-800 hover:bg-slate-700'
              }`}
              title={`Step ${s.step}: ${s.title}`}
            />
          ))}
        </div>

        {/* Body Content */}
        <div className="p-6 space-y-4">
          <div className="p-3.5 bg-slate-900/60 border border-slate-800 rounded">
            <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-1">
              Demonstration Purpose
            </div>
            <p className="text-sm text-slate-200 leading-relaxed">{current.summary}</p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
            <div className="p-3 bg-[#080C14] border border-slate-800 rounded">
              <div className="text-[10px] font-mono text-cyan-400 uppercase tracking-wider mb-1">
                Technical Mechanism
              </div>
              <p className="text-slate-300 leading-relaxed font-mono text-[11px]">
                {current.technicalConcept}
              </p>
            </div>

            <div className="p-3 bg-[#080C14] border border-slate-800 rounded">
              <div className="text-[10px] font-mono text-amber-400 uppercase tracking-wider mb-1">
                Forensic Evidence Anchor
              </div>
              <p className="text-slate-300 leading-relaxed font-mono text-[11px] break-all">
                {current.evidenceAnchor}
              </p>
            </div>
          </div>

          <div className="pt-2">
            <button
              onClick={handleExecuteStep}
              className="w-full py-2.5 px-4 bg-cyan-600 hover:bg-cyan-500 text-white rounded font-semibold text-xs flex items-center justify-center gap-2 shadow-lg shadow-cyan-950/50 transition-all cursor-pointer"
            >
              <span>{current.actionLabel}</span>
              <ArrowRight className="w-4 h-4" />
            </button>
            <p className="text-[11px] text-slate-400 text-center mt-1.5 font-mono">
              Clicking navigates to the live screen with target evidence selected
            </p>
          </div>
        </div>

        {/* Footer Navigation */}
        <div className="px-6 py-3 bg-slate-900/80 border-t border-slate-800 flex items-center justify-between">
          <button
            onClick={handlePrev}
            disabled={currentStepIndex === 0}
            className="flex items-center gap-1 px-3 py-1.5 text-xs text-slate-300 hover:text-white disabled:text-slate-600 disabled:cursor-not-allowed cursor-pointer"
          >
            <ChevronLeft className="w-4 h-4" />
            <span>Previous Step</span>
          </button>

          <div className="text-xs font-mono text-slate-400">
            {current.category}
          </div>

          <button
            onClick={handleNext}
            disabled={currentStepIndex === steps.length - 1}
            className="flex items-center gap-1 px-3 py-1.5 text-xs text-cyan-400 hover:text-cyan-300 disabled:text-slate-600 disabled:cursor-not-allowed cursor-pointer font-medium"
          >
            <span>Next Step</span>
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
};
