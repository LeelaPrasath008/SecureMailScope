import React, { useState, useRef } from 'react';
import {
  FileSearch,
  Upload,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Layers,
  HardDrive,
  Hash,
  ChevronDown,
  ChevronUp,
  Cpu,
  Lock,
  FileCode2,
  ShieldCheck,
  RefreshCw,
  FolderOpen
} from 'lucide-react';
import { DemoScenario, PipelineStage } from '../../types/security';
import { ConfidenceBadge } from '../common/ConfidenceBadge';

interface Props {
  scenario: DemoScenario;
  scenarios: DemoScenario[];
  pipelineStages: PipelineStage[];
  onSelectScenario: (id: string) => void;
  onCustomUpload: (file: File) => void;
  onNavigateToSessions: () => void;
}

export const PcapAnalysisView: React.FC<Props> = ({
  scenario,
  scenarios,
  pipelineStages,
  onSelectScenario,
  onCustomUpload,
  onNavigateToSessions
}) => {
  const [expandedStageId, setExpandedStageId] = useState<string | null>('tls_handshake_analysis');
  const [isDragging, setIsDragging] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const meta = scenario.pcapMetadata;

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileSelected(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      handleFileSelected(e.target.files[0]);
    }
  };

  const handleFileSelected = (file: File) => {
    setIsAnalyzing(true);
    setTimeout(() => {
      onCustomUpload(file);
      setIsAnalyzing(false);
    }, 600);
  };

  const toggleStage = (stageId: string) => {
    setExpandedStageId(expandedStageId === stageId ? null : stageId);
  };

  const totalTimeMs = pipelineStages.reduce((acc, s) => acc + (s.processingTimeMs || 0), 0);

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            <FileSearch className="w-5 h-5 text-cyan-400" />
            <span>PCAP Analysis & Ingestion Pipeline</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Passive cryptographic traffic dissection, state machine reassembly, and verifiable forensic hash computation.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-slate-400">Target Capture:</span>
          <select
            value={scenario.id}
            onChange={e => onSelectScenario(e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500 cursor-pointer"
          >
            {scenarios.map(s => (
              <option key={s.id} value={s.id}>
                {s.pcapMetadata.filename} ({s.title.split(':')[0]})
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Mandatory Passive Analysis Warning (Prompt Section 7) */}
      <div className="p-3.5 bg-[#0B111A] border-l-4 border-cyan-500 rounded-r border-y border-r border-slate-800 flex items-start gap-3">
        <ShieldCheck className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
        <div className="text-xs">
          <span className="font-semibold text-cyan-300 font-mono">PASSIVE FORENSIC GUARANTEE:</span>
          <p className="text-slate-300 mt-0.5 leading-relaxed">
            Analysis is strictly passive. SecureMailScope analyzes captured packet captures (PCAP/PCAPNG) offline and does not intercept, modify, or inject into live email communications.
          </p>
        </div>
      </div>

      {/* Drag & Drop Upload + Scenarios Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Upload Zone */}
        <div className="lg:col-span-7 bg-[#0B0F17] border border-slate-800 rounded p-5 flex flex-col justify-between">
          <div
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`border-2 border-dashed rounded p-8 text-center cursor-pointer transition-colors flex flex-col items-center justify-center ${
              isDragging
                ? 'border-cyan-400 bg-cyan-950/20'
                : 'border-slate-700/80 hover:border-slate-600 bg-[#080C14]'
            }`}
          >
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileChange}
              accept=".pcap,.pcapng,.cap"
              className="hidden"
            />
            <div className="w-12 h-12 rounded-full bg-slate-900 border border-slate-700 flex items-center justify-center text-cyan-400 mb-3">
              {isAnalyzing ? (
                <RefreshCw className="w-6 h-6 animate-spin text-cyan-400" />
              ) : (
                <Upload className="w-6 h-6" />
              )}
            </div>
            <h3 className="text-sm font-semibold text-white">
              Drag & Drop PCAP / PCAPNG
            </h3>
            <p className="text-xs text-slate-400 mt-1 max-w-sm">
              Supports full-duplex captures, SPAN port mirrors, and upstream network taps. Maximum tested size: 250 MB.
            </p>
            <div className="mt-4 flex items-center gap-2">
              <button
                type="button"
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded text-xs font-mono font-medium transition-colors"
              >
                Browse Files
              </button>
              <span className="text-[11px] font-mono text-slate-500">or select demonstration scenario below</span>
            </div>
          </div>

          {/* Quick Scenario Buttons (Prompt Section 21) */}
          <div className="mt-4 pt-3 border-t border-slate-800/80">
            <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block mb-2 font-semibold">
              Load Demonstration Scenarios (SIH 2026 Evaluation Suite):
            </span>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
              {scenarios.map(s => (
                <button
                  key={s.id}
                  onClick={() => onSelectScenario(s.id)}
                  className={`p-2 rounded border text-left transition-colors cursor-pointer ${
                    s.id === scenario.id
                      ? 'bg-cyan-950/40 border-cyan-700 text-cyan-200'
                      : 'bg-[#080C14] border-slate-800 hover:border-slate-700 text-slate-300'
                  }`}
                >
                  <div className="font-semibold truncate">{s.title}</div>
                  <div className="text-[10px] text-slate-400 truncate">{s.subtitle}</div>
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Evidence Metadata Card (Prompt Section 7) */}
        <div className="lg:col-span-5 bg-[#0B0F17] border border-slate-800 rounded p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
              <span className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-300">
                Evidence Metadata
              </span>
              <span className="px-2 py-0.5 rounded bg-emerald-950/40 border border-emerald-800/60 text-emerald-400 text-[10px] font-mono font-bold">
                STATUS: {meta.status}
              </span>
            </div>

            <div className="mt-4 space-y-3 text-xs font-mono">
              <div>
                <span className="text-slate-500 block text-[10px] uppercase">Evidence ID</span>
                <span className="text-cyan-400 font-bold text-sm">{meta.id}</span>
              </div>

              <div>
                <span className="text-slate-500 block text-[10px] uppercase">Filename</span>
                <span className="text-white font-medium break-all">{meta.filename}</span>
              </div>

              <div>
                <span className="text-slate-500 block text-[10px] uppercase flex items-center gap-1">
                  <Hash className="w-3 h-3 text-cyan-400" />
                  SHA-256 Digest (Verifiable Evidence Integrity)
                </span>
                <span className="text-slate-300 bg-[#080C14] p-1.5 rounded border border-slate-800 text-[11px] block break-all tabular-nums select-all">
                  {meta.sha256}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-2 pt-1">
                <div>
                  <span className="text-slate-500 block text-[10px] uppercase">File Size</span>
                  <span className="text-slate-200 tabular-nums">
                    {(meta.fileSizeBytes / (1024 * 1024)).toFixed(2)} MB ({meta.fileSizeBytes.toLocaleString()} bytes)
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px] uppercase">Total Packets</span>
                  <span className="text-slate-200 tabular-nums">{meta.packetCount.toLocaleString()}</span>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-2 pt-1">
                <div>
                  <span className="text-slate-500 block text-[10px] uppercase">Capture Timestamp</span>
                  <span className="text-slate-300 tabular-nums text-[11px]">{meta.captureTimestamp}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px] uppercase">Analysis Timestamp</span>
                  <span className="text-slate-300 tabular-nums text-[11px]">{meta.analysisTimestamp}</span>
                </div>
              </div>

              <div className="pt-2 border-t border-slate-800/80">
                <span className="text-slate-500 block text-[10px] uppercase">Evidence Confidence</span>
                <div className="mt-1 flex items-center gap-2">
                  <ConfidenceBadge confidence={meta.confidence} />
                  {meta.confidenceReason && (
                    <span className="text-[10px] text-slate-400">{meta.confidenceReason}</span>
                  )}
                </div>
              </div>
            </div>
          </div>

          <div className="mt-5 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs">
            <span className="text-slate-400 font-mono text-[11px]">
              Tap Interface: <span className="text-slate-300">{meta.capturedInterface || 'eth0'}</span>
            </span>
            <button
              onClick={onNavigateToSessions}
              className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs font-semibold flex items-center gap-1 transition-colors cursor-pointer"
            >
              <span>Explore Sessions ({scenario.sessions.length})</span>
            </button>
          </div>
        </div>
      </div>

      {/* Analysis Pipeline Visualization (Prompt Section 8) */}
      <div className="bg-[#0B0F17] border border-slate-800 rounded p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
          <div>
            <h3 className="text-sm font-bold text-white tracking-tight flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              <span>Deterministic Forensics & AI Posture Pipeline</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Sequence of 12 discrete analysis phases from raw packet framing to actionable remediation recommendations.
            </p>
          </div>
          <div className="flex items-center gap-3 text-xs font-mono text-slate-400">
            <span>
              Total Pipeline Execution Time: <strong className="text-cyan-400 tabular-nums">{totalTimeMs} ms</strong>
            </span>
          </div>
        </div>

        {/* Pipeline Stage Steps */}
        <div className="space-y-2">
          {pipelineStages.map((stage, idx) => {
            const isExpanded = expandedStageId === stage.id;
            return (
              <div
                key={stage.id}
                className="bg-[#080C14] border border-slate-800/90 rounded overflow-hidden transition-colors"
              >
                <div
                  onClick={() => toggleStage(stage.id)}
                  className="px-4 py-3 flex items-center justify-between cursor-pointer hover:bg-slate-800/30 transition-colors"
                >
                  <div className="flex items-center gap-3">
                    <span className="w-6 h-6 rounded bg-slate-900 border border-slate-700 text-slate-300 text-[11px] font-mono font-bold flex items-center justify-center">
                      {idx + 1}
                    </span>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-semibold text-slate-200">{stage.name}</span>
                        <span className="text-[10px] font-mono text-emerald-400 flex items-center gap-1">
                          <CheckCircle2 className="w-3 h-3" />
                          <span>COMPLETED</span>
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400 mt-0.5 max-w-2xl">{stage.details}</p>
                    </div>
                  </div>

                  <div className="flex items-center gap-4 text-xs font-mono text-slate-400 shrink-0">
                    {stage.count !== undefined && (
                      <span className="tabular-nums">
                        {stage.count.toLocaleString()} artifacts
                      </span>
                    )}
                    {stage.processingTimeMs !== undefined && (
                      <span className="tabular-nums text-slate-500">
                        {stage.processingTimeMs} ms
                      </span>
                    )}
                    {isExpanded ? (
                      <ChevronUp className="w-4 h-4 text-slate-400" />
                    ) : (
                      <ChevronDown className="w-4 h-4 text-slate-400" />
                    )}
                  </div>
                </div>

                {isExpanded && stage.subSteps && (
                  <div className="px-14 py-2.5 bg-slate-900/40 border-t border-slate-800/60 text-xs font-mono text-slate-300 space-y-1">
                    <span className="text-[10px] text-slate-500 uppercase tracking-wider block">
                      Internal Forensic Invariants & Verifications:
                    </span>
                    {stage.subSteps.map((step, sIdx) => (
                      <div key={sIdx} className="flex items-center gap-2 text-[11px]">
                        <span className="text-cyan-400 font-bold">✓</span>
                        <span>{step}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
