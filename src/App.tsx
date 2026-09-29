/**
 * SecureMailScope - Main Application
 * SIH 2026 Problem Statement 26159
 * AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications
 */

import React, { useState } from 'react';
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
      {/* Left Navigation Sidebar */}
      <Sidebar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        scenarios={scenarios}
        activeScenario={activeScenario}
        onSelectScenario={handleSelectScenario}
        onLaunchGuidedDemo={() => setIsGuidedDemoOpen(true)}
        isAiOnline={isAiOnline}
        onToggleAi={handleToggleAi}
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
        />

        {/* View Content Port */}
        <main className="flex-1 overflow-y-auto">
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
