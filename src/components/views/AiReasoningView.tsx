import React, { useState, useEffect } from 'react';
import {
  Cpu,
  ShieldCheck,
  AlertTriangle,
  ArrowRight,
  RefreshCw,
  Terminal,
  FileCode2,
  CheckCircle2,
  Sliders,
  Layers,
  Sparkles,
  Info,
  Radio,
  Send,
  HelpCircle,
  BookOpen,
  MessageSquare,
  Copy,
  Check
} from 'lucide-react';
import { AIReasoningAnalysis, DemoScenario, EmailSession } from '../../types/security';
import { securityService } from '../../services/securityService';
import { ConfidenceBadge } from '../common/ConfidenceBadge';
import { NavigationTab } from '../layout/Sidebar';

interface Props {
  scenario: DemoScenario;
  isAiOnline: boolean;
  onToggleAi: (online: boolean) => void;
  onNavigateTab: (tab: NavigationTab) => void;
  onSelectSession: (sessionId: string) => void;
}

type AiTab = 'assessment' | 'chat' | 'evidence_json';

interface ChatMessage {
  id: string;
  sender: 'user' | 'ai';
  text: string;
  timestamp: string;
  evidenceAnchor?: string;
}

export const AiReasoningView: React.FC<Props> = ({
  scenario,
  isAiOnline,
  onToggleAi,
  onNavigateTab,
  onSelectSession
}) => {
  const [selectedSessionId, setSelectedSessionId] = useState<string>(
    scenario.defaultSelectedSessionId || scenario.sessions[0]?.id || ''
  );
  const [aiAnalysis, setAiAnalysis] = useState<AIReasoningAnalysis | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [activeAiTab, setActiveAiTab] = useState<AiTab>('assessment');
  const [userQuery, setUserQuery] = useState('');
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [copiedJson, setCopiedJson] = useState(false);

  const activeSession =
    scenario.sessions.find((s) => s.id === selectedSessionId) || scenario.sessions[0];

  const fetchAnalysis = async (sessId: string) => {
    setIsLoading(true);
    const result = await securityService.runAIContextualReasoning(sessId);
    setAiAnalysis(result);
    setIsLoading(false);
  };

  useEffect(() => {
    fetchAnalysis(selectedSessionId);
    // Initialize welcome chat message for this session
    const welcomeText = activeSession
      ? `Forensic context loaded for Stream ${activeSession.id} (${activeSession.protocol} on port ${activeSession.destPort}). You can ask me to explain specific RFC standard violations, compounding cryptographic risks, or generate server hardening configurations.`
      : scenario.findings.length > 0
      ? `Forensic context loaded for capture ${scenario.pcapMetadata.filename}. Evaluated rule: ${scenario.findings[0].title}. You can ask me to explain this finding, assess risk impact, or generate server remediation.`
      : `Forensic capture ${scenario.pcapMetadata.filename} loaded. Zero transport sessions and zero security findings detected.`;

    const welcomeAnchor = activeSession
      ? `Grounded in ${activeSession.evidenceConfidence} wire evidence`
      : scenario.findings.length > 0
      ? `Grounded in ${scenario.findings[0].standardReference}`
      : 'Passive Ingestion Verified';

    setChatMessages([
      {
        id: 'msg-welcome',
        sender: 'ai',
        text: welcomeText,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        evidenceAnchor: welcomeAnchor
      }
    ]);
  }, [selectedSessionId, isAiOnline, scenario.id]);

  const handleSendQuery = (textToSend?: string) => {
    const query = (textToSend || userQuery).trim();
    if (!query) return;

    const userMsg: ChatMessage = {
      id: `usr-${Date.now()}`,
      sender: 'user',
      text: query,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    setChatMessages((prev) => [...prev, userMsg]);
    if (!textToSend) setUserQuery('');

    // Generate grounded contextual response
    setTimeout(() => {
      let reply = '';
      let anchor = '';

      const q = query.toLowerCase();
      const tls = activeSession?.tlsHandshake;

      if (q.includes('sweet32') || q.includes('3des') || q.includes('cipher')) {
        reply = `Analysis for ${activeSession?.id}: The negotiated cipher suite is ${tls?.cipherSuite.ianaName || '3DES-EDE-CBC'}. Under CVE-2016-2183 (Sweet32), 64-bit block ciphers are vulnerable to birthday attacks after capturing ~32GB of encrypted traffic, exposing session cookies or plain auth tokens. Remediate by configuring Postfix/Dovecot with: 'smtpd_tls_mandatory_ciphers = high' and excluding 3DES.`;
        anchor = 'Evidence: CVE-2016-2183 & RFC 9325 Section 4.3';
      } else if (q.includes('tls 1.0') || q.includes('version') || q.includes('deprecat')) {
        reply = `Stream ${activeSession?.id} negotiated ${tls?.negotiatedVersion || 'TLS 1.0'}. RFC 8996 formally deprecated TLS 1.0 and TLS 1.1 in March 2021 due to lack of modern AEAD ciphers and support for vulnerable CBC modes (BEAST, POODLE). Minimum required version is TLS 1.2, while RFC 9846 recommends TLS 1.3.`;
        anchor = 'Evidence: RFC 8996 & Server Hello handshake frame';
      } else if (q.includes('striptls') || q.includes('downgrade') || q.includes('starttls')) {
        reply = `In stream ${activeSession?.id}, STARTTLS was negotiated. Opportunistic STARTTLS without strict MTA-STS (RFC 8461) or DANE (RFC 7672) is vulnerable to passive man-in-the-middle STRIPTLS attacks, where an adversary deletes the '250-STARTTLS' response string to force the client to transmit mail in cleartext.`;
        anchor = 'Evidence: RFC 8314 & RFC 8461 MTA-STS';
      } else if (q.includes('cert') || q.includes('x509') || q.includes('expir')) {
        const cert = tls?.certificate;
        if (cert) {
          reply = `Certificate presented for ${activeSession?.id} is issued to '${cert.subjectCommonName}' by '${cert.issuerCommonName}'. Validity: ${cert.validFrom} to ${cert.validUntil}. Status: ${cert.isExpired ? 'EXPIRED' : 'ACTIVE'}. ${cert.isExpired ? 'Clients encountering an expired certificate will either abort the connection or drop to insecure bypass modes.' : 'Certificate is within validity window.'}`;
          anchor = `Evidence: X.509 Serial ${cert.serialNumber}`;
        } else {
          reply = `No X.509 certificate was negotiated in this cleartext stream.`;
          anchor = 'Evidence: Plaintext TCP stream';
        }
      } else {
        reply = `Based on the deterministic telemetry for stream ${activeSession?.id}: Risk level is ${activeSession?.risk} with ${activeSession?.evidenceConfidence} evidence. The primary vulnerability is ${activeSession?.tlsHandshake?.isDeprecatedVersion ? 'negotiation of deprecated ' + activeSession?.tlsHandshake.negotiatedVersion : 'weak transport parameters'}. Prioritize disabling legacy protocols and enforcing authenticated AEAD cipher suites.`;
        anchor = `Evidence: Stream ${activeSession?.id} Dissection`;
      }

      const aiMsg: ChatMessage = {
        id: `ai-${Date.now()}`,
        sender: 'ai',
        text: reply,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        evidenceAnchor: anchor
      };

      setChatMessages((prev) => [...prev, aiMsg]);
    }, 400);
  };

  const handleCopyJson = () => {
    if (aiAnalysis?.groundedEvidenceInput) {
      navigator.clipboard.writeText(JSON.stringify(aiAnalysis.groundedEvidenceInput, null, 2));
      setCopiedJson(true);
      setTimeout(() => setCopiedJson(false), 2000);
    }
  };

  return (
    <div className="p-4 sm:p-6 space-y-5 max-w-7xl mx-auto">
      {/* Header */}
      <div className="bg-[#0F1623] border border-slate-800 rounded-xl p-5 shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            <Sparkles className="w-5 h-5 text-cyan-400" />
            <span>AI-Assisted Cryptographic Reasoning</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Grounded contextual risk synthesis, vulnerability interaction modeling, and remediation triage assistance.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {scenario.sessions.length > 0 ? (
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <span>Target Stream:</span>
              <select
                value={selectedSessionId}
                onChange={(e) => setSelectedSessionId(e.target.value)}
                className="bg-[#0A0E17] border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 cursor-pointer font-mono"
              >
                {scenario.sessions.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.id} ({s.protocol} - {s.risk})
                  </option>
                ))}
              </select>
            </div>
          ) : (
            <div className="text-xs font-mono text-cyan-300 bg-cyan-950/60 border border-cyan-800/80 px-2.5 py-1.5 rounded-lg">
              Target: {scenario.pcapMetadata.filename}
            </div>
          )}

          <button
            onClick={() => onToggleAi(!isAiOnline)}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition-colors cursor-pointer ${
              isAiOnline
                ? 'bg-cyan-950/60 border-cyan-800/80 text-cyan-300 hover:bg-cyan-900/60'
                : 'bg-rose-950/60 border-rose-800/80 text-rose-300 hover:bg-rose-900/60'
            }`}
            title="Toggle to simulate service resiliency when AI is offline"
          >
            {isAiOnline ? 'AI Online' : 'AI Offline (Simulated)'}
          </button>
        </div>
      </div>

      {/* Safety Contract Callout */}
      <div className="bg-[#0F1623] border-l-4 border-cyan-500 border border-slate-800 rounded-xl p-4 flex items-start gap-3 shadow-xs">
        <ShieldCheck className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
        <div className="text-xs">
          <span className="font-semibold text-slate-200">Grounded Reasoning Contract:</span>
          <p className="text-slate-400 mt-0.5 leading-relaxed">
            Deterministic rules establish objective facts (TLS version, ciphers, key lengths, certificates, RFC standards). The AI receives serialized, structured technical evidence to evaluate compound risk and assist with remediation sequencing without hallucinations.
          </p>
        </div>
      </div>

      {isAiOnline && aiAnalysis && aiAnalysis.available ? (
        <div className="space-y-4">
          {/* Navigation Sub-Tabs */}
          <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
            <button
              onClick={() => setActiveAiTab('assessment')}
              className={`px-3.5 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                activeAiTab === 'assessment'
                  ? 'bg-cyan-600 text-white font-semibold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              Contextual Risk Assessment
            </button>
            <button
              onClick={() => setActiveAiTab('chat')}
              className={`px-3.5 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer flex items-center gap-1.5 ${
                activeAiTab === 'chat'
                  ? 'bg-cyan-600 text-white font-semibold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <MessageSquare className="w-3.5 h-3.5" />
              <span>Interactive Forensic Assistant</span>
            </button>
            <button
              onClick={() => setActiveAiTab('evidence_json')}
              className={`px-3.5 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer flex items-center gap-1.5 ${
                activeAiTab === 'evidence_json'
                  ? 'bg-cyan-600 text-white font-semibold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>Evidence Input (JSON)</span>
            </button>
          </div>

          {/* Tab 1: Contextual Assessment */}
          {activeAiTab === 'assessment' && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
              {/* Left Column: Context & Compound Risks */}
              <div className="lg:col-span-7 space-y-4">
                <div className="bg-[#0F1623] border border-slate-800 rounded-xl p-5 space-y-3 shadow-xs">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-300">Contextual Posture Assessment</span>
                    <span className="text-xs font-mono text-cyan-400">Confidence: {aiAnalysis.aiConfidence}</span>
                  </div>
                  <p className="text-xs text-slate-200 leading-relaxed font-sans">
                    {aiAnalysis.contextualAssessment}
                  </p>
                </div>

                <div className="bg-[#0F1623] border border-slate-800 rounded-xl p-5 space-y-3 shadow-xs">
                  <div className="flex items-center gap-2 text-amber-400 text-xs font-semibold">
                    <AlertTriangle className="w-4 h-4" />
                    <span>Compounding Vulnerability Interactions</span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed font-sans whitespace-pre-line">
                    {aiAnalysis.interactionImpact}
                  </p>
                </div>
              </div>

              {/* Right Column: Prioritization & Quick Links */}
              <div className="lg:col-span-5 space-y-4">
                <div className="bg-[#0F1623] border border-slate-800 rounded-xl p-5 space-y-3 shadow-xs">
                  <div className="flex items-center gap-2 text-emerald-400 text-xs font-semibold">
                    <CheckCircle2 className="w-4 h-4" />
                    <span>Remediation Sequence Priority</span>
                  </div>
                  <div className="space-y-2 font-mono text-xs">
                    {aiAnalysis.prioritizedSequence.map((step, idx) => (
                      <div key={idx} className="p-3 bg-[#0A0E17] border border-slate-800 rounded-lg text-slate-200">
                        {step}
                      </div>
                    ))}
                  </div>
                </div>

                <div className="bg-[#0F1623] border border-slate-800 rounded-xl p-4 flex items-center justify-between shadow-xs">
                  <span className="text-xs text-slate-400">Want to inspect affected findings?</span>
                  <button
                    onClick={() => onNavigateTab('findings')}
                    className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-cyan-300 text-xs font-semibold rounded-lg transition-colors cursor-pointer flex items-center gap-1.5"
                  >
                    <span>View Findings</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Tab 2: Interactive Forensic Assistant */}
          {activeAiTab === 'chat' && (
            <div className="bg-[#0F1623] border border-slate-800 rounded-xl overflow-hidden shadow-xs flex flex-col h-[520px]">
              {/* Chat Messages Log */}
              <div className="flex-1 overflow-y-auto p-4 space-y-3 bg-[#0A0E17]/60">
                {chatMessages.map((msg) => (
                  <div
                    key={msg.id}
                    className={`flex flex-col ${msg.sender === 'user' ? 'items-end' : 'items-start'}`}
                  >
                    <div
                      className={`max-w-2xl rounded-xl p-3.5 text-xs ${
                        msg.sender === 'user'
                          ? 'bg-cyan-600 text-white'
                          : 'bg-[#0F1623] border border-slate-800 text-slate-200 shadow-xs'
                      }`}
                    >
                      <p className="leading-relaxed whitespace-pre-line">{msg.text}</p>
                      {msg.evidenceAnchor && (
                        <div className="mt-2 pt-2 border-t border-slate-800/80 text-[10px] text-cyan-400 font-mono">
                          {msg.evidenceAnchor}
                        </div>
                      )}
                    </div>
                    <span className="text-[10px] text-slate-500 mt-1 px-1 font-mono">{msg.timestamp}</span>
                  </div>
                ))}
              </div>

              {/* Quick Prompt Suggestions */}
              <div className="p-2.5 bg-[#0F1623] border-t border-slate-800 flex items-center gap-2 overflow-x-auto text-xs">
                <span className="text-slate-400 text-[11px] shrink-0 font-medium">Quick Queries:</span>
                {[
                  'Explain Sweet32 3DES risk',
                  'Why is TLS 1.0 deprecated?',
                  'How to protect against STRIPTLS?',
                  'Check X.509 certificate expiry'
                ].map((promptText) => (
                  <button
                    key={promptText}
                    onClick={() => handleSendQuery(promptText)}
                    className="px-2.5 py-1 bg-[#0A0E17] hover:bg-slate-800 text-slate-300 border border-slate-700/80 rounded-lg text-xs whitespace-nowrap transition-colors cursor-pointer"
                  >
                    {promptText}
                  </button>
                ))}
              </div>

              {/* Input Bar */}
              <div className="p-3 bg-[#0A0E17] border-t border-slate-800 flex items-center gap-2">
                <input
                  type="text"
                  value={userQuery}
                  onChange={(e) => setUserQuery(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleSendQuery()}
                  placeholder="Ask a forensic question regarding this email stream's cryptographic posture..."
                  className="flex-1 bg-[#0F1623] border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-sans"
                />
                <button
                  onClick={() => handleSendQuery()}
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
                >
                  <Send className="w-3.5 h-3.5" />
                  <span>Ask</span>
                </button>
              </div>
            </div>
          )}

          {/* Tab 3: Structured Technical JSON Input */}
          {activeAiTab === 'evidence_json' && (
            <div className="bg-[#0F1623] border border-slate-800 rounded-xl p-5 space-y-3 shadow-xs">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-xs font-bold text-white font-mono flex items-center gap-1.5">
                    <Terminal className="w-4 h-4 text-cyan-400" />
                    <span>Deterministic Evidence Payload Passed to Reasoning Layer</span>
                  </h3>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    Raw evidence verified with SHA-256 custody hash before passing into the contextual model.
                  </p>
                </div>

                <button
                  onClick={handleCopyJson}
                  className="flex items-center gap-1.5 px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs rounded-lg transition-colors cursor-pointer border border-slate-700"
                >
                  {copiedJson ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      <span className="text-emerald-300">Copied!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5 text-slate-400" />
                      <span>Copy Payload</span>
                    </>
                  )}
                </button>
              </div>

              <pre className="p-4 bg-[#05080E] border border-slate-800 rounded-lg text-xs font-mono text-cyan-300 overflow-x-auto leading-relaxed select-all max-h-96">
                {JSON.stringify(aiAnalysis.groundedEvidenceInput, null, 2)}
              </pre>
            </div>
          )}
        </div>
      ) : (
        /* Graceful Offline Simulation State */
        <div className="bg-[#0F1623] border border-rose-900/60 rounded-xl p-8 text-center space-y-4 max-w-2xl mx-auto shadow-xs">
          <div className="w-12 h-12 rounded-full bg-rose-950 border border-rose-800 flex items-center justify-center text-rose-400 mx-auto">
            <Radio className="w-6 h-6 animate-pulse" />
          </div>

          <h3 className="text-lg font-bold text-white font-mono">
            AI ANALYSIS SERVICE OFFLINE (SIMULATED)
          </h3>

          <p className="text-xs text-slate-300 leading-relaxed font-sans">
            Deterministic cryptographic analysis completed successfully. Reconstructed streams, RFC evaluations, and findings remain 100% authoritative and accessible.
          </p>

          <div className="pt-2 flex items-center justify-center gap-3">
            <button
              onClick={() => onToggleAi(true)}
              className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-semibold transition-colors cursor-pointer"
            >
              Reconnect AI Service
            </button>
            <button
              onClick={() => onNavigateTab('findings')}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg border border-slate-700 text-xs transition-colors cursor-pointer"
            >
              Continue to Deterministic Findings
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
