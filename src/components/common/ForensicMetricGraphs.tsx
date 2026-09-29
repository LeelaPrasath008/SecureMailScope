import React from 'react';
import { DemoScenario } from '../../types/security';

interface Props {
  scenario: DemoScenario;
  className?: string;
}

export const ForensicMetricGraphs: React.FC<Props> = ({ scenario, className = '' }) => {
  // 1. Calculate Traffic Tunnel Ratio
  const sessions = scenario.sessions || [];
  const encryptedCount = sessions.filter(
    (s) => s.tlsHandshake != null || s.startTlsNegotiated === true
  ).length;
  const cleartextCount = sessions.filter(
    (s) => s.plaintextCredentialsExposed || (!s.tlsHandshake && !s.startTlsNegotiated)
  ).length;
  const totalSessions = encryptedCount + cleartextCount || 1;
  const encryptedPct = Math.round((encryptedCount / totalSessions) * 100);
  const cleartextPct = 100 - encryptedPct;

  // Donut geometry (r = 52, perimeter = 2 * PI * 52 = ~326.726)
  const donutR = 52;
  const donutC = 2 * Math.PI * donutR;
  const encryptedDash = (encryptedPct / 100) * donutC;
  const cleartextDash = (cleartextPct / 100) * donutC;

  // 2. Calculate Protocol Distribution
  const smtpCount = sessions.filter((s) => s.protocol === 'SMTP').length;
  const imapCount = sessions.filter((s) => s.protocol === 'IMAP').length;
  const pop3Count = sessions.filter((s) => s.protocol === 'POP3').length;
  const maxProtoCount = Math.max(4, Math.max(smtpCount, imapCount, pop3Count) + 1);

  // 3. Calculate Cryptographic Vulnerability Profile
  const findings = scenario.findings || [];
  const starttlsStrippedCount = findings.filter(
    (f) =>
      f.ruleId === 'RULE-STARTTLS-002' ||
      f.ruleId === 'RULE-PLAIN-001' ||
      f.title.toLowerCase().includes('cleartext') ||
      f.title.toLowerCase().includes('striptls')
  ).length;

  const deprecatedTlsCount = findings.filter(
    (f) =>
      f.ruleId === 'RULE-TLS-001' ||
      f.title.toLowerCase().includes('tls 1.0') ||
      f.title.toLowerCase().includes('deprecated tls')
  ).length;

  const brokenCiphersCount = findings.filter(
    (f) =>
      f.ruleId === 'RULE-CIPHER-002' ||
      f.ruleId === 'RULE-CIPHER-003' ||
      f.title.toLowerCase().includes('3des') ||
      f.title.toLowerCase().includes('cipher') ||
      f.title.toLowerCase().includes('forward secrecy')
  ).length;

  const certificateIssuesCount = findings.filter(
    (f) =>
      f.ruleId === 'RULE-CERT-001' ||
      f.ruleId === 'RULE-CERT-004' ||
      f.title.toLowerCase().includes('certificate') ||
      f.title.toLowerCase().includes('expired') ||
      f.title.toLowerCase().includes('sha-1')
  ).length;

  const isolationForestCount = findings.filter(
    (f) =>
      f.ruleId === 'RULE-PCAP-009' ||
      f.title.toLowerCase().includes('truncated') ||
      f.title.toLowerCase().includes('anomaly') ||
      f.confidence === 'INSUFFICIENT'
  ).length;

  const maxVulnCount = Math.max(
    4,
    Math.max(
      starttlsStrippedCount,
      deprecatedTlsCount,
      brokenCiphersCount,
      certificateIssuesCount,
      isolationForestCount
    ) + 1
  );

  return (
    <div className={`grid grid-cols-1 lg:grid-cols-3 gap-5 ${className}`}>
      {/* 1. Traffic Tunnel Ratio Card */}
      <div className="bg-[#0F1623] border border-slate-800 rounded-xl p-5 shadow-xs flex flex-col justify-between">
        <div className="flex items-center justify-between border-b border-slate-800/80 pb-3 mb-4">
          <h3 className="text-sm font-bold text-white tracking-tight">Traffic Tunnel Ratio</h3>
          <span className="text-[11px] font-mono text-slate-400">Passive Dissection</span>
        </div>

        {/* Donut Chart Canvas */}
        <div className="flex-1 flex flex-col items-center justify-center py-2">
          <div className="relative w-44 h-44 flex items-center justify-center">
            <svg className="w-full h-full -rotate-90 transform" viewBox="0 0 140 140">
              {/* Background circle if cleartext */}
              <circle
                cx="70"
                cy="70"
                r={donutR}
                fill="none"
                stroke="#1E293B"
                strokeWidth="16"
              />

              {/* Encrypted slice (Green) */}
              {encryptedPct > 0 && (
                <circle
                  cx="70"
                  cy="70"
                  r={donutR}
                  fill="none"
                  stroke="#16A34A"
                  strokeWidth="16"
                  strokeDasharray={`${encryptedDash} ${donutC}`}
                  strokeDashoffset="0"
                  className="transition-all duration-700 ease-out"
                />
              )}

              {/* Cleartext slice (Red) */}
              {cleartextPct > 0 && (
                <circle
                  cx="70"
                  cy="70"
                  r={donutR}
                  fill="none"
                  stroke="#DC2626"
                  strokeWidth="16"
                  strokeDasharray={`${cleartextDash} ${donutC}`}
                  strokeDashoffset={encryptedPct > 0 ? `-${encryptedDash}` : '0'}
                  className="transition-all duration-700 ease-out"
                />
              )}
            </svg>

            {/* Inner Center Label */}
            <div className="absolute inset-0 flex flex-col items-center justify-center text-center select-none">
              <span className="text-2xl font-bold font-mono text-white tabular-nums">
                {encryptedPct}%
              </span>
              <span className="text-[10px] uppercase font-mono tracking-wider text-slate-400">
                Encrypted
              </span>
            </div>
          </div>
        </div>

        {/* Legend */}
        <div className="mt-4 pt-3 border-t border-slate-800/80 flex flex-wrap items-center justify-center gap-3 sm:gap-5 text-xs font-mono">
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-xs bg-[#16A34A] shrink-0" />
            <span className="text-slate-300">
              Encrypted TLS Tunnel <strong className="text-white">({encryptedCount})</strong>
            </span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-xs bg-[#DC2626] shrink-0" />
            <span className="text-slate-300">
              Unencrypted Cleartext <strong className="text-white">({cleartextCount})</strong>
            </span>
          </div>
        </div>
      </div>

      {/* 2. Protocol Distribution Card */}
      <div className="bg-[#0F1623] border border-slate-800 rounded-xl p-5 shadow-xs flex flex-col justify-between">
        <div className="flex items-center justify-between border-b border-slate-800/80 pb-3 mb-2">
          <h3 className="text-sm font-bold text-white tracking-tight">Protocol Distribution</h3>
          <span className="text-[11px] font-mono text-slate-400">Reconstructed Ports</span>
        </div>

        {/* Vertical Bar Chart Canvas */}
        <div className="flex-1 flex flex-col justify-end py-2">
          <div className="h-44 w-full">
            <svg className="w-full h-full" viewBox="0 0 280 160">
              {/* Y-Axis lines and tick labels */}
              {[4, 3, 2, 1, 0].map((tick) => {
                const y = 15 + ((4 - tick) / 4) * 110;
                return (
                  <g key={tick}>
                    <line
                      x1="35"
                      y1={y}
                      x2="270"
                      y2={y}
                      stroke="#1E293B"
                      strokeWidth="1"
                      strokeDasharray={tick === 0 ? 'none' : '3 3'}
                    />
                    <text
                      x="28"
                      y={y + 4}
                      fill="#94A3B8"
                      fontSize="10"
                      fontFamily="monospace"
                      textAnchor="end"
                    >
                      {tick}
                    </text>
                  </g>
                );
              })}

              {/* Y-Axis Main Spine */}
              <line x1="35" y1="15" x2="35" y2="125" stroke="#475569" strokeWidth="1" />
              {/* X-Axis Main Spine */}
              <line x1="35" y1="125" x2="270" y2="125" stroke="#475569" strokeWidth="1" />

              {/* Bar 1: SMTP */}
              {(() => {
                const barHeight = (smtpCount / 4) * 110;
                const barY = 125 - barHeight;
                return (
                  <g className="group cursor-pointer">
                    <rect
                      x="60"
                      y={barY}
                      width="42"
                      height={Math.max(barHeight, 0)}
                      fill="#06B6D4"
                      rx="3"
                      className="transition-all duration-500 hover:fill-cyan-300"
                    />
                    {smtpCount > 0 && (
                      <text
                        x="81"
                        y={barY - 5}
                        fill="#06B6D4"
                        fontSize="11"
                        fontWeight="bold"
                        fontFamily="monospace"
                        textAnchor="middle"
                      >
                        {smtpCount}
                      </text>
                    )}
                  </g>
                );
              })()}

              {/* Bar 2: IMAP */}
              {(() => {
                const barHeight = (imapCount / 4) * 110;
                const barY = 125 - barHeight;
                return (
                  <g className="group cursor-pointer">
                    <rect
                      x="135"
                      y={barY}
                      width="42"
                      height={Math.max(barHeight, 0)}
                      fill="#06B6D4"
                      rx="3"
                      className="transition-all duration-500 hover:fill-cyan-300"
                    />
                    {imapCount > 0 && (
                      <text
                        x="156"
                        y={barY - 5}
                        fill="#06B6D4"
                        fontSize="11"
                        fontWeight="bold"
                        fontFamily="monospace"
                        textAnchor="middle"
                      >
                        {imapCount}
                      </text>
                    )}
                  </g>
                );
              })()}

              {/* Bar 3: POP3 */}
              {(() => {
                const barHeight = (pop3Count / 4) * 110;
                const barY = 125 - barHeight;
                return (
                  <g className="group cursor-pointer">
                    <rect
                      x="210"
                      y={barY}
                      width="42"
                      height={Math.max(barHeight, 0)}
                      fill="#06B6D4"
                      rx="3"
                      className="transition-all duration-500 hover:fill-cyan-300"
                    />
                    {pop3Count > 0 && (
                      <text
                        x="231"
                        y={barY - 5}
                        fill="#06B6D4"
                        fontSize="11"
                        fontWeight="bold"
                        fontFamily="monospace"
                        textAnchor="middle"
                      >
                        {pop3Count}
                      </text>
                    )}
                  </g>
                );
              })()}

              {/* X-Axis Labels */}
              <text
                x="81"
                y="142"
                fill="#94A3B8"
                fontSize="9"
                fontFamily="sans-serif"
                textAnchor="middle"
              >
                SMTP (Port 25/587)
              </text>
              <text
                x="156"
                y="142"
                fill="#94A3B8"
                fontSize="9"
                fontFamily="sans-serif"
                textAnchor="middle"
              >
                IMAP (Port 143/993)
              </text>
              <text
                x="231"
                y="142"
                fill="#94A3B8"
                fontSize="9"
                fontFamily="sans-serif"
                textAnchor="middle"
              >
                POP3 (Port 110/995)
              </text>
            </svg>
          </div>
        </div>

        {/* Card Footer Metric */}
        <div className="mt-2 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono text-slate-400">
          <span>Total Flows: <strong className="text-white">{sessions.length}</strong></span>
          <span className="text-cyan-400">100% Reconstructed</span>
        </div>
      </div>

      {/* 3. Cryptographic Vulnerability Profile Card */}
      <div className="bg-[#0F1623] border border-slate-800 rounded-xl p-5 shadow-xs flex flex-col justify-between">
        <div className="flex items-center justify-between border-b border-slate-800/80 pb-3 mb-2">
          <h3 className="text-sm font-bold text-white tracking-tight">
            Cryptographic Vulnerability Profile
          </h3>
          <span className="text-[11px] font-mono text-slate-400">Rule & Heuristic Engine</span>
        </div>

        {/* Horizontal Bar Chart Canvas */}
        <div className="flex-1 flex flex-col justify-end py-1">
          <div className="h-44 w-full">
            <svg className="w-full h-full" viewBox="0 0 280 160">
              {/* Y-Axis Spine */}
              <line x1="110" y1="10" x2="110" y2="135" stroke="#475569" strokeWidth="1" />
              {/* X-Axis Spine */}
              <line x1="110" y1="135" x2="270" y2="135" stroke="#475569" strokeWidth="1" />

              {/* X-Axis Ticks: 0, 1, 2, 3, 4 */}
              {[0, 1, 2, 3, 4].map((tick) => {
                const x = 110 + (tick / 4) * 150;
                return (
                  <g key={tick}>
                    <line x1={x} y1="135" x2={x} y2="140" stroke="#475569" strokeWidth="1" />
                    <text
                      x={x}
                      y="150"
                      fill="#94A3B8"
                      fontSize="9"
                      fontFamily="monospace"
                      textAnchor="middle"
                    >
                      {tick}
                    </text>
                  </g>
                );
              })}

              {/* Items definition */}
              {[
                {
                  label: 'STARTTLS Stripped',
                  count: starttlsStrippedCount,
                  color: '#DC2626',
                  y: 20
                },
                {
                  label: 'Deprecated TLS 1.0/1.1',
                  count: deprecatedTlsCount,
                  color: '#EA580C',
                  y: 45
                },
                {
                  label: 'Broken Ciphers (RC4/3DES)',
                  count: brokenCiphersCount,
                  color: '#E11D48',
                  y: 70
                },
                {
                  label: 'Certificate Issues',
                  count: certificateIssuesCount,
                  color: '#EA580C',
                  y: 95
                },
                {
                  label: 'Isolation Forest Anomalies',
                  count: isolationForestCount,
                  color: '#8B5CF6',
                  y: 120
                }
              ].map((item) => {
                const barWidth = Math.min((item.count / 4) * 150, 150);
                return (
                  <g key={item.label} className="group cursor-pointer">
                    {/* Y label */}
                    <text
                      x="104"
                      y={item.y + 4}
                      fill="#CBD5E1"
                      fontSize="8.5"
                      fontFamily="sans-serif"
                      textAnchor="end"
                    >
                      {item.label}
                    </text>

                    {/* Bar background track */}
                    <line
                      x1="110"
                      y1={item.y}
                      x2="260"
                      y2={item.y}
                      stroke="#1E293B"
                      strokeWidth="1"
                      strokeDasharray="2 2"
                    />

                    {/* Active Bar */}
                    {item.count > 0 && (
                      <>
                        <rect
                          x="110"
                          y={item.y - 6}
                          width={barWidth}
                          height="12"
                          fill={item.color}
                          rx="2"
                          className="transition-all duration-500 opacity-90 hover:opacity-100"
                        />
                        <text
                          x={110 + barWidth + 6}
                          y={item.y + 3}
                          fill={item.color}
                          fontSize="9.5"
                          fontWeight="bold"
                          fontFamily="monospace"
                        >
                          {item.count}
                        </text>
                      </>
                    )}
                  </g>
                );
              })}
            </svg>
          </div>
        </div>

        {/* Card Footer Metric */}
        <div className="mt-2 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono text-slate-400">
          <span>Active Findings: <strong className="text-rose-400">{findings.length}</strong></span>
          <span className="text-amber-400">RFC & Heuristics</span>
        </div>
      </div>
    </div>
  );
};
