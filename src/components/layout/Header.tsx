import React from 'react';
import {
  FileUp,
  HelpCircle,
  FileText,
  Search,
  Sparkles,
  ChevronDown,
  Layers,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2
} from 'lucide-react';
import { NavigationTab } from './Sidebar';
import { DemoScenario } from '../../types/security';

interface Props {
  activeTab: NavigationTab;
  activeScenario: DemoScenario;
  scenarios: DemoScenario[];
  onSelectScenario: (id: string) => void;
  onOpenUpload: () => void;
  onLaunchGuidedDemo: () => void;
  onNavigateTab: (tab: NavigationTab) => void;
}

export const Header: React.FC<Props> = ({
  activeTab,
  activeScenario,
  scenarios,
  onSelectScenario,
  onOpenUpload,
  onLaunchGuidedDemo,
  onNavigateTab
}) => {
  const getTabLabel = (tab: NavigationTab) => {
    switch (tab) {
      case 'dashboard':
        return 'Overview';
      case 'pcap_analysis':
        return 'PCAP Ingestion';
      case 'sessions':
        return 'Session Forensics';
      case 'posture':
        return 'Posture & What-If Lab';
      case 'findings':
        return 'Security Findings';
      case 'evidence':
        return 'Traceability Graph';
      case 'timeline':
        return 'Event Timeline';
      case 'ai_reasoning':
        return 'AI Security Analyst';
      case 'reports':
        return 'Audit Reports';
      case 'settings':
        return 'Settings & Policy';
      default:
        return 'Forensics';
    }
  };

  const getRiskColor = (status: string) => {
    switch (status) {
      case 'AT RISK':
        return 'text-rose-400 bg-rose-950/40 border-rose-800/60';
      case 'DEGRADED':
        return 'text-amber-400 bg-amber-950/40 border-amber-800/60';
      default:
        return 'text-emerald-400 bg-emerald-950/40 border-emerald-800/60';
    }
  };

  const activeStatus = activeScenario.findings.some(f => f.severity === 'CRITICAL')
    ? 'AT RISK'
    : activeScenario.findings.some(f => f.severity === 'HIGH')
    ? 'DEGRADED'
    : 'SECURE';

  return (
    <header className="h-14 bg-[#0A0E17] border-b border-slate-800/80 px-4 sm:px-6 flex items-center justify-between shrink-0 select-none z-20">
      {/* Left: Context Breadcrumb */}
      <div className="flex items-center gap-2.5 text-xs">
        <div className="flex items-center gap-1.5 font-medium text-slate-400">
          <span>Forensics</span>
          <span className="text-slate-600">/</span>
          <span className="text-slate-200 font-semibold">{getTabLabel(activeTab)}</span>
        </div>

        <div className="hidden md:flex items-center gap-1.5 pl-2 border-l border-slate-800 text-[11px] text-slate-400 font-mono">
          <span className="text-slate-500">Capture:</span>
          <span className="text-slate-300 font-medium truncate max-w-[200px]" title={activeScenario.pcapMetadata.filename}>
            {activeScenario.pcapMetadata.filename}
          </span>
        </div>
      </div>

      {/* Center: Scenario Quick Switcher */}
      <div className="hidden lg:flex items-center gap-2 bg-[#0F1623] border border-slate-800 rounded-lg px-2.5 py-1">
        <span className="text-[11px] font-medium text-slate-400">Scenario:</span>
        <select
          value={activeScenario.id}
          onChange={(e) => onSelectScenario(e.target.value)}
          className="bg-transparent text-xs text-cyan-300 font-medium focus:outline-none cursor-pointer pr-1"
        >
          {scenarios.map((s) => (
            <option key={s.id} value={s.id} className="bg-[#0B0F17] text-slate-200">
              {s.title}
            </option>
          ))}
        </select>
        <span className={`text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded border ${getRiskColor(activeStatus)}`}>
          {activeStatus}
        </span>
      </div>

      {/* Right: Quick Action Buttons */}
      <div className="flex items-center gap-2">
        <button
          onClick={onLaunchGuidedDemo}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-cyan-300 bg-cyan-950/40 hover:bg-cyan-900/50 border border-cyan-800/60 transition-colors cursor-pointer"
          title="Start interactive guided tour"
        >
          <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
          <span className="hidden sm:inline">Guided Tour</span>
        </button>

        <button
          onClick={onOpenUpload}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-white bg-cyan-600 hover:bg-cyan-500 transition-colors shadow-sm cursor-pointer"
        >
          <FileUp className="w-3.5 h-3.5" />
          <span>Upload PCAP</span>
        </button>
      </div>
    </header>
  );
};

