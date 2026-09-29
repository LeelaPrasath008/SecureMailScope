import React, { useState } from 'react';
import {
  Settings,
  Shield,
  Lock,
  HardDrive,
  Users,
  CheckCircle2,
  FileCode2,
  AlertTriangle,
  Cpu,
  Key,
  Database
} from 'lucide-react';

export const SettingsView: React.FC = () => {
  const [activeRole, setActiveRole] = useState<'ANALYST' | 'CRYPTOGRAPHER' | 'AUDITOR'>('CRYPTOGRAPHER');
  const [piiMasking, setPiiMasking] = useState(true);
  const [autoHashing, setAutoHashing] = useState(true);
  const [maxUploadMb, setMaxUploadMb] = useState(250);

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            <Settings className="w-5 h-5 text-cyan-400" />
            <span>Forensic Engine Configuration & Security Policy</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Cryptographic standards thresholds, ingestion constraints, RBAC policy, and data isolation controls.
          </p>
        </div>

        <div className="text-xs font-mono text-emerald-400 flex items-center gap-1.5">
          <CheckCircle2 className="w-4 h-4" />
          <span>Security Baseline: Compliant (BCP 195: RFC 8996 & RFC 9325 / NIST SP 800-52r2)</span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Section 27: Safe PCAP Processing & Ingestion Policy */}
        <div className="bg-[#0B0F17] border border-slate-800 rounded p-5 space-y-4">
          <div className="flex items-center gap-2 border-b border-slate-800/80 pb-3">
            <HardDrive className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-white">Safe PCAP Ingestion & Parsing Sandboxing</h3>
          </div>

          <div className="space-y-3 text-xs font-mono">
            <div className="flex items-center justify-between p-3 bg-[#080C14] rounded border border-slate-800">
              <div>
                <span className="text-slate-200 font-semibold block">Maximum Capture File Size</span>
                <span className="text-slate-400 text-[11px]">Enforces DoS protection on parser memory limits</span>
              </div>
              <span className="text-cyan-400 font-bold">{maxUploadMb} MB</span>
            </div>

            <div className="flex items-center justify-between p-3 bg-[#080C14] rounded border border-slate-800">
              <div>
                <span className="text-slate-200 font-semibold block">Automatic SHA-256 Chain-of-Custody</span>
                <span className="text-slate-400 text-[11px]">Computes verifiable digital evidence hash on ingest</span>
              </div>
              <button
                onClick={() => setAutoHashing(!autoHashing)}
                className={`px-2.5 py-1 rounded text-[11px] font-bold border cursor-pointer ${
                  autoHashing ? 'bg-cyan-950 text-cyan-300 border-cyan-800' : 'bg-slate-900 text-slate-500'
                }`}
              >
                {autoHashing ? 'ENFORCED' : 'DISABLED'}
              </button>
            </div>

            <div className="flex items-center justify-between p-3 bg-[#080C14] rounded border border-slate-800">
              <div>
                <span className="text-slate-200 font-semibold block">PII & Credential Masking in UI/Reports</span>
                <span className="text-slate-400 text-[11px]">Masks raw cleartext passwords (USER/PASS) in exports</span>
              </div>
              <button
                onClick={() => setPiiMasking(!piiMasking)}
                className={`px-2.5 py-1 rounded text-[11px] font-bold border cursor-pointer ${
                  piiMasking ? 'bg-emerald-950 text-emerald-300 border-emerald-800' : 'bg-slate-900 text-slate-500'
                }`}
              >
                {piiMasking ? 'MASKED' : 'EXPOSED'}
              </button>
            </div>

            <div className="p-3 bg-[#080C14] rounded border border-slate-800 space-y-1">
              <span className="text-slate-500 text-[10px] uppercase block">Parser Isolation Strategy</span>
              <p className="text-slate-300 font-sans text-xs">
                Zero system calls or raw socket writes. Captured frames are decoded inside a read-only memory buffer with strict recursion bounds on ASN.1 DER certificate sequences.
              </p>
            </div>
          </div>
        </div>

        {/* Section 27: Role-Based Access Control (RBAC) */}
        <div className="bg-[#0B0F17] border border-slate-800 rounded p-5 space-y-4">
          <div className="flex items-center gap-2 border-b border-slate-800/80 pb-3">
            <Users className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-white">Forensic Role-Based Access Control (RBAC)</h3>
          </div>

          <div className="space-y-3">
            <div className="flex items-center gap-2 text-xs font-mono">
              <span className="text-slate-400">Active Operator Role:</span>
              <div className="flex items-center gap-1.5 bg-[#080C14] p-1 rounded border border-slate-800">
                {(['CRYPTOGRAPHER', 'ANALYST', 'AUDITOR'] as const).map(role => (
                  <button
                    key={role}
                    onClick={() => setActiveRole(role)}
                    className={`px-2.5 py-1 rounded text-[11px] font-bold transition-colors cursor-pointer ${
                      activeRole === role
                        ? 'bg-cyan-600 text-white shadow'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    {role}
                  </button>
                ))}
              </div>
            </div>

            <div className="p-4 bg-[#080C14] rounded border border-slate-800 text-xs font-mono space-y-2">
              <div className="text-slate-300 font-bold">
                Permissions for {activeRole}:
              </div>
              <ul className="space-y-1 text-slate-400 text-[11px]">
                <li className="flex items-center gap-2">
                  <span className="text-emerald-400">✓</span> View all low-level TLS handshake records & byte offsets
                </li>
                <li className="flex items-center gap-2">
                  <span className="text-emerald-400">✓</span> Execute What-If simulation and policy delta calculations
                </li>
                <li className="flex items-center gap-2">
                  <span className="text-emerald-400">✓</span> Export cryptographically signed audit compliance packages
                </li>
                <li className="flex items-center gap-2 text-slate-500">
                  <span className="text-slate-600">✕</span> Zero live network interception privileges (passive only)
                </li>
              </ul>
            </div>
          </div>
        </div>

        {/* AI Prompt & Technical Evidence Isolation Policy */}
        <div className="lg:col-span-2 bg-[#0B0F17] border border-slate-800 rounded p-5 space-y-3">
          <div className="flex items-center gap-2 border-b border-slate-800/80 pb-3">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-white">AI Data Isolation & Grounding Governance</h3>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
            <div className="p-3 bg-[#080C14] border border-slate-800 rounded space-y-1">
              <span className="text-cyan-400 font-bold block">1. Zero Body Leakage</span>
              <p className="text-slate-300 font-sans text-xs">
                Email message bodies (MIME content, text, attachments) are never passed to the AI reasoning engine. Only cryptographic parameters are transmitted.
              </p>
            </div>

            <div className="p-3 bg-[#080C14] border border-slate-800 rounded space-y-1">
              <span className="text-cyan-400 font-bold block">2. Structured Input Only</span>
              <p className="text-slate-300 font-sans text-xs">
                Reasoning prompts are restricted to pre-validated JSON key-value pairs (version, cipher, cert expiry). No open-ended raw packet streaming.
              </p>
            </div>

            <div className="p-3 bg-[#080C14] border border-slate-800 rounded space-y-1">
              <span className="text-cyan-400 font-bold block">3. Secrets Custody</span>
              <p className="text-slate-300 font-sans text-xs">
                All external API keys (Gemini / AI Studio) are held server-side. Zero API keys are hard-coded or exposed to client-side bundles.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
