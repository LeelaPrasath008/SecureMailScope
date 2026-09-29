import React from 'react';
import { EvidenceConfidence } from '../../types/security';
import { CheckCircle2, AlertTriangle, AlertOctagon } from 'lucide-react';

interface Props {
  confidence: EvidenceConfidence;
  showIcon?: boolean;
}

export const ConfidenceBadge: React.FC<Props> = ({ confidence, showIcon = true }) => {
  const configs: Record<EvidenceConfidence, { bg: string; text: string; border: string; icon: React.ReactNode; label: string }> = {
    COMPLETE: {
      bg: 'bg-emerald-950/30',
      text: 'text-emerald-400',
      border: 'border-emerald-800/40',
      icon: <CheckCircle2 className="w-3 h-3 text-emerald-400" />,
      label: 'COMPLETE EVIDENCE'
    },
    PARTIAL: {
      bg: 'bg-amber-950/30',
      text: 'text-amber-400',
      border: 'border-amber-800/40',
      icon: <AlertTriangle className="w-3 h-3 text-amber-400" />,
      label: 'PARTIAL EVIDENCE'
    },
    INSUFFICIENT: {
      bg: 'bg-purple-950/30',
      text: 'text-purple-300',
      border: 'border-purple-800/40',
      icon: <AlertOctagon className="w-3 h-3 text-purple-300" />,
      label: 'INSUFFICIENT (TRUNCATED)'
    }
  };

  const c = configs[confidence] || configs.COMPLETE;

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-mono font-medium border ${c.bg} ${c.text} ${c.border}`}
      title={`Forensic evidence certainty: ${confidence}`}
    >
      {showIcon && c.icon}
      <span>{c.label}</span>
    </span>
  );
};
