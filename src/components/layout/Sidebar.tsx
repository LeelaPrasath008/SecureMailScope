import React from 'react';
import {
  LayoutDashboard,
  FileSearch,
  Layers,
  Shield,
  AlertTriangle,
  FileCode2,
  GitBranch,
  FileText,
  Settings,
  Sparkles,
  Radio,
  Lock,
  Clock,
  ChevronRight,
  X
} from 'lucide-react';
import { DemoScenario } from '../../types/security';

export type NavigationTab =
  | 'dashboard'
  | 'pcap_analysis'
  | 'sessions'
  | 'posture'
  | 'findings'
  | 'evidence'
  | 'timeline'
  | 'ai_reasoning'
  | 'reports'
  | 'settings';

interface Props {
  activeTab: NavigationTab;
  onSelectTab: (tab: NavigationTab) => void;
  scenarios: DemoScenario[];
  activeScenario: DemoScenario;
  onSelectScenario: (id: string) => void;
  onLaunchGuidedDemo: () => void;
  isAiOnline: boolean;
  onToggleAi: (online: boolean) => void;
  isMobileOpen?: boolean;
  onCloseMobile?: () => void;
}

interface NavGroup {
  label: string;
  items: {
    id: NavigationTab;
    label: string;
    icon: React.ComponentType<{ className?: string }>;
    count?: number;
    badge?: string;
  }[];
}

export const Sidebar: React.FC<Props> = ({
  activeTab,
  onSelectTab,
  scenarios,
  activeScenario,
  onSelectScenario,
  onLaunchGuidedDemo,
  isAiOnline,
  onToggleAi,
  isMobileOpen = false,
  onCloseMobile
}) => {
  const navGroups: NavGroup[] = [
    {
      label: 'Overview',
      items: [
        { id: 'dashboard', label: 'Executive Dashboard', icon: LayoutDashboard }
      ]
    },
    {
      label: 'Traffic Forensics',
      items: [
        { id: 'sessions', label: 'Reconstructed Sessions', icon: Layers, count: activeScenario.sessions.length },
        { id: 'findings', label: 'Security Findings', icon: AlertTriangle, count: activeScenario.findings.length },
        { id: 'pcap_analysis', label: 'PCAP Ingestion & Hash', icon: FileSearch }
      ]
    },
    {
      label: 'Deep Analysis & AI',
      items: [
        { id: 'posture', label: 'Posture & What-If Lab', icon: Shield },
        { id: 'evidence', label: 'Traceability Graph', icon: GitBranch },
        { id: 'timeline', label: 'Protocol Event Timeline', icon: Clock },
        { id: 'ai_reasoning', label: 'AI Security Analyst', icon: Sparkles }
      ]
    },
    {
      label: 'Audit & Compliance',
      items: [
        { id: 'reports', label: 'Audit Reports & Export', icon: FileText },
        { id: 'settings', label: 'Forensic Policy & Ciphers', icon: Settings }
      ]
    }
  ];

  return (
    <>
      {/* Mobile Backdrop Overlay */}
      {isMobileOpen && (
        <div
          onClick={onCloseMobile}
          className="fixed inset-0 bg-black/70 backdrop-blur-xs z-40 lg:hidden transition-opacity duration-300"
          aria-hidden="true"
        />
      )}

      {/* Responsive Sidebar Container */}
      <aside
        className={`fixed inset-y-0 left-0 z-50 w-72 max-w-[85vw] bg-[#0A0E17] border-r border-slate-800/80 shadow-2xl flex flex-col h-full select-none transition-transform duration-300 ease-in-out lg:static lg:w-64 lg:h-screen lg:shrink-0 lg:shadow-none lg:translate-x-0 ${
          isMobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        }`}
      >
        {/* Brand Header */}
        <div className="p-4 border-b border-slate-800/80 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center text-white shadow-sm shadow-cyan-500/20">
              <Lock className="w-4 h-4" />
            </div>
            <div>
              <span className="font-bold tracking-tight text-white text-sm block">
                SecureMailScope
              </span>
              <span className="text-[11px] text-slate-400 block -mt-0.5">
                Email Cryptographic Forensics
              </span>
            </div>
          </div>

          {/* Close Button on Mobile Drawer */}
          {onCloseMobile && (
            <button
              onClick={onCloseMobile}
              className="lg:hidden p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800/80 transition-colors cursor-pointer"
              aria-label="Close navigation"
            >
              <X className="w-5 h-5" />
            </button>
          )}
        </div>

        {/* Guided Tour Banner */}
        <div className="p-3 border-b border-slate-800/60 bg-gradient-to-r from-cyan-950/30 via-slate-900/40 to-blue-950/20">
          <button
            onClick={() => {
              onLaunchGuidedDemo();
              onCloseMobile?.();
            }}
            className="w-full flex items-center justify-between px-3 py-2 bg-[#0F172A] hover:bg-[#1E293B] border border-cyan-800/50 hover:border-cyan-700 rounded-lg text-xs font-medium text-cyan-200 transition-all cursor-pointer group shadow-xs"
          >
            <div className="flex items-center gap-2">
              <Sparkles className="w-3.5 h-3.5 text-cyan-400 group-hover:scale-110 transition-transform" />
              <span>Interactive Walkthrough</span>
            </div>
            <ChevronRight className="w-3.5 h-3.5 text-slate-400 group-hover:text-cyan-300 transition-colors" />
          </button>
        </div>

        {/* Grouped Navigation */}
        <nav className="flex-1 overflow-y-auto px-3 py-3 space-y-4">
          {navGroups.map((group) => (
            <div key={group.label} className="space-y-1">
              <div className="px-2 text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                {group.label}
              </div>
              {group.items.map((item) => {
                const Icon = item.icon;
                const isActive = activeTab === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => {
                      onSelectTab(item.id);
                      onCloseMobile?.();
                    }}
                    className={`w-full flex items-center justify-between px-2.5 py-2 rounded-lg text-xs font-medium transition-colors text-left cursor-pointer ${
                      isActive
                        ? 'bg-cyan-500/15 text-cyan-200 font-semibold'
                        : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/50'
                    }`}
                  >
                    <div className="flex items-center gap-2.5 min-w-0">
                      <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                      <span className="truncate">{item.label}</span>
                    </div>
                    {item.count !== undefined && (
                      <span
                        className={`text-[10px] font-mono tabular-nums px-1.5 py-0.5 rounded-md ${
                          isActive
                            ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/60'
                            : 'bg-slate-800/80 text-slate-400'
                        }`}
                      >
                        {item.count}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          ))}
        </nav>

        {/* Scenario Selector Footer */}
        <div className="p-3 border-t border-slate-800/80 bg-[#080C14]">
          <div className="flex items-center justify-between text-[11px] text-slate-400 mb-1.5">
            <span className="font-medium">Active Traffic Capture</span>
          </div>
          <select
            value={activeScenario.id}
            onChange={(e) => {
              onSelectScenario(e.target.value);
              onCloseMobile?.();
            }}
            className="w-full bg-[#0F1623] border border-slate-700/80 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 cursor-pointer"
          >
            {scenarios.map((s) => (
              <option key={s.id} value={s.id}>
                {s.title}
              </option>
            ))}
          </select>

          {/* AI Status Resilience Switcher */}
          <div className="mt-3 pt-2.5 border-t border-slate-800/60 flex items-center justify-between text-xs">
            <div className="flex items-center gap-1.5 text-slate-400">
              <Radio className={`w-3 h-3 ${isAiOnline ? 'text-cyan-400' : 'text-slate-500'}`} />
              <span>AI Reasoning</span>
            </div>
            <button
              onClick={() => onToggleAi(!isAiOnline)}
              className={`px-2 py-0.5 rounded text-[10px] font-medium border transition-colors cursor-pointer ${
                isAiOnline
                  ? 'bg-cyan-950/60 text-cyan-300 border-cyan-800/70 hover:bg-cyan-900/60'
                  : 'bg-rose-950/50 text-rose-300 border-rose-800/70 hover:bg-rose-900/50'
              }`}
              title="Toggle to test offline graceful degradation"
            >
              {isAiOnline ? 'Online' : 'Offline'}
            </button>
          </div>
        </div>
      </aside>
    </>
  );
};
