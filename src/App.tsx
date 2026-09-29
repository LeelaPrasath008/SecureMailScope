/**
 * SecureMailScope - Main Application
 * SIH 2026 Problem Statement 26159
 * AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications
 */

import React, { useState } from 'react';
import {
  LayoutDashboard,
  Layers,
  GitBranch,
  AlertTriangle,
  Menu
} from 'lucide-react';
import { Sidebar, NavigationTab } from './components/layout/Sidebar';
import { Header } from './components/layout/Header';
import { DashboardView } from './components/views/DashboardView';
import { PcapAnalysisView } from './components/views/PcapAnalysisView';
import { SessionsView } from './components/views/SessionsView';
import { CryptographicPostureView } from './components/views/CryptographicPostureView';
import { FindingsView } from './components/views/FindingsView';
import { EvidenceIntelligenceView } from './components/views/EvidenceIntelligenceView';
import { InvestigationTimelineView } from './components/views/InvestigationTimelineView';
import { AiReasoningView } from './components/views/AiReasoningView';
import { ReportsView } from './components/views/ReportsView';
import { SettingsView } from './components/views/SettingsView';
import { GuidedDemoModal } from './components/common/GuidedDemoModal';
import { securityService } from './services/securityService';
import { DemoScenario } from './types/security';

export default function App() {
  const [activeTab, setActiveTab] = useState<NavigationTab>('dashboard');
  const [scenarios, setScenarios] = useState<DemoScenario[]>(securityService.getScenarios());
  const [activeScenario, setActiveScenario] = useState<DemoScenario>(securityService.getActiveScenario());
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [isGuidedDemoOpen, setIsGuidedDemoOpen] = useState(false);
  const [isAiOnline, setIsAiOnline] = useState(securityService.isAiOnline());
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  const posture = securityService.getSecurityPosture();
  const pipelineStages = securityService.getPipelineStages();

  const handleSelectScenario = (id: string) => {
    const updated = securityService.setActiveScenario(id);
    setActiveScenario(updated);
    setSelectedSessionId(null);
    setSelectedFindingId(null);
  };

  const handleCustomUpload = (file: File) => {
    const newScenario = securityService.uploadSimulatedPCAP(file.name, file.size);
    setScenarios([...securityService.getScenarios()]);
    setActiveScenario(newScenario);
    setActiveTab('pcap_analysis');
  };

  const handleToggleAi = (online: boolean) => {
    securityService.setAiServiceStatus(online);
    setIsAiOnline(online);
  };

  const handleSelectFinding = (findingId: string) => {
    setSelectedFindingId(findingId);
  };

  const handleSelectSession = (sessionId: string | null) => {
    setSelectedSessionId(sessionId);
  };

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[#090D14] text-slate-100 font-sans">
      {/* Left Navigation Sidebar (Desktop + Mobile Drawer) */}
      <Sidebar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        scenarios={scenarios}
        activeScenario={activeScenario}
        onSelectScenario={handleSelectScenario}
        onLaunchGuidedDemo={() => setIsGuidedDemoOpen(true)}
        isAiOnline={isAiOnline}
        onToggleAi={handleToggleAi}
        isMobileOpen={isMobileMenuOpen}
        onCloseMobile={() => setIsMobileMenuOpen(false)}
      />

      {/* Main Content Workspace */}
      <div className="flex-1 flex flex-col min-w-0 h-screen overflow-hidden">
        {/* Top Header Bar */}
        <Header
          activeTab={activeTab}
          activeScenario={activeScenario}
          scenarios={scenarios}
          onSelectScenario={handleSelectScenario}
          onOpenUpload={() => setActiveTab('pcap_analysis')}
          onLaunchGuidedDemo={() => setIsGuidedDemoOpen(true)}
          onNavigateTab={setActiveTab}
          onToggleMobileMenu={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
        />

        {/* View Content Port */}
        <main className="flex-1 overflow-y-auto pb-16 lg:pb-0">
          {activeTab === 'dashboard' && (
            <DashboardView
              scenario={activeScenario}
              scenarios={scenarios}
              onSelectScenario={handleSelectScenario}
              posture={posture}
              onNavigateTab={setActiveTab}
              onSelectSession={(sessId) => {
                setSelectedSessionId(sessId);
                setActiveTab('sessions');
              }}
              onSelectFinding={(findId) => {
                setSelectedFindingId(findId);
                setActiveTab('findings');
              }}
            />
          )}

          {activeTab === 'pcap_analysis' && (
            <PcapAnalysisView
              scenario={activeScenario}
              scenarios={scenarios}
              pipelineStages={pipelineStages}
              onSelectScenario={handleSelectScenario}
              onCustomUpload={handleCustomUpload}
              onNavigateToSessions={() => setActiveTab('sessions')}
            />
          )}

          {activeTab === 'sessions' && (
            <SessionsView
              sessions={activeScenario.sessions}
              evidenceList={activeScenario.evidenceList}
              selectedSessionId={selectedSessionId}
              onSelectSession={handleSelectSession}
              onNavigateTab={setActiveTab}
              onSelectFinding={handleSelectFinding}
            />
          )}

          {activeTab === 'posture' && (
            <CryptographicPostureView
              scenario={activeScenario}
              posture={posture}
              onNavigateTab={setActiveTab}
              onSelectFinding={(findId) => {
                setSelectedFindingId(findId);
                setActiveTab('findings');
              }}
            />
          )}

          {activeTab === 'findings' && (
            <FindingsView
              findings={activeScenario.findings}
              selectedFindingId={selectedFindingId}
              onSelectFinding={handleSelectFinding}
              onNavigateTab={setActiveTab}
              onSelectSession={(sessId) => {
                setSelectedSessionId(sessId);
                setActiveTab('sessions');
              }}
            />
          )}

          {activeTab === 'evidence' && (
            <EvidenceIntelligenceView
              scenario={activeScenario}
              scenarios={scenarios}
              onSelectScenario={handleSelectScenario}
              onNavigateTab={setActiveTab}
              onSelectSession={(sessId) => {
                setSelectedSessionId(sessId);
                setActiveTab('sessions');
              }}
              onSelectFinding={(findId) => {
                setSelectedFindingId(findId);
                setActiveTab('findings');
              }}
            />
          )}

          {activeTab === 'timeline' && (
            <InvestigationTimelineView
              scenario={activeScenario}
              onNavigateTab={setActiveTab}
              onSelectSession={(sessId) => {
                setSelectedSessionId(sessId);
                setActiveTab('sessions');
              }}
            />
          )}

          {activeTab === 'ai_reasoning' && (
            <AiReasoningView
              scenario={activeScenario}
              isAiOnline={isAiOnline}
              onToggleAi={handleToggleAi}
              onNavigateTab={setActiveTab}
              onSelectSession={(sessId) => {
                setSelectedSessionId(sessId);
                setActiveTab('sessions');
              }}
            />
          )}

          {activeTab === 'reports' && (
            <ReportsView scenario={activeScenario} posture={posture} />
          )}

          {activeTab === 'settings' && <SettingsView />}
        </main>
      </div>

      {/* Mobile Bottom Quick-Navigation Bar */}
      <nav className="lg:hidden fixed bottom-0 left-0 right-0 z-30 bg-[#0A0E17]/95 backdrop-blur-md border-t border-slate-800/90 px-1 py-1 flex items-center justify-around shadow-2xl">
        <button
          onClick={() => setActiveTab('dashboard')}
          className={`flex flex-col items-center justify-center py-1 px-2.5 rounded-lg text-[10px] font-medium transition-colors cursor-pointer ${
            activeTab === 'dashboard'
              ? 'text-cyan-400 font-semibold'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <LayoutDashboard className="w-4 h-4 mb-0.5" />
          <span>Overview</span>
        </button>

        <button
          onClick={() => setActiveTab('sessions')}
          className={`flex flex-col items-center justify-center py-1 px-2.5 rounded-lg text-[10px] font-medium transition-colors cursor-pointer ${
            activeTab === 'sessions'
              ? 'text-cyan-400 font-semibold'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Layers className="w-4 h-4 mb-0.5" />
          <span>Streams</span>
        </button>

        <button
          onClick={() => setActiveTab('evidence')}
          className={`flex flex-col items-center justify-center py-1 px-2.5 rounded-lg text-[10px] font-medium transition-colors cursor-pointer ${
            activeTab === 'evidence'
              ? 'text-cyan-400 font-semibold'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <GitBranch className="w-4 h-4 mb-0.5" />
          <span>Graph</span>
        </button>

        <button
          onClick={() => setActiveTab('findings')}
          className={`flex flex-col items-center justify-center py-1 px-2.5 rounded-lg text-[10px] font-medium transition-colors cursor-pointer ${
            activeTab === 'findings'
              ? 'text-cyan-400 font-semibold'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <AlertTriangle className="w-4 h-4 mb-0.5" />
          <span>Findings</span>
        </button>

        <button
          onClick={() => setIsMobileMenuOpen(true)}
          className="flex flex-col items-center justify-center py-1 px-2.5 rounded-lg text-[10px] font-medium text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
        >
          <Menu className="w-4 h-4 mb-0.5" />
          <span>Menu</span>
        </button>
      </nav>

      {/* Guided Demo Walkthrough Modal */}
      <GuidedDemoModal
        isOpen={isGuidedDemoOpen}
        onClose={() => setIsGuidedDemoOpen(false)}
        onNavigateTab={setActiveTab}
        onSelectSession={setSelectedSessionId}
        onSelectFinding={setSelectedFindingId}
      />
    </div>
  );
}
