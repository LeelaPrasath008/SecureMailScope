import React from 'react';
import { EvidenceClass } from '../../types/security';
import { Eye, CheckCircle2, Shield, Compass, Sparkles } from 'lucide-react';

interface Props {
  evidenceClass?: EvidenceClass;
  className?: string;
  showIcon?: boolean;
}

export const EvidenceClassBadge: React.FC<Props> = ({
  evidenceClass = 'OBSERVED',
  className = '',
  showIcon = true
}) => {
  switch (evidenceClass) {
    case 'OBSERVED':
      return (
        <span
          className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider bg-cyan-950/70 text-cyan-300 border border-cyan-800/80 ${className}`}
          title="Direct wire evidence extracted from packet frames"
        >
          {showIcon && <Eye className="w-3 h-3 text-cyan-400" />}
          <span>OBSERVED</span>
        </span>
      );
    case 'ASSESSED':
      return (
        <span
          className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider bg-blue-950/70 text-blue-300 border border-blue-800/80 ${className}`}
          title="Deterministic conclusion derived from observed evidence"
        >
          {showIcon && <CheckCircle2 className="w-3 h-3 text-blue-400" />}
          <span>ASSESSED</span>
        </span>
      );
    case 'POLICY':
      return (
        <span
          className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider bg-purple-950/70 text-purple-300 border border-purple-800/80 ${className}`}
          title="Conclusion evaluated relative to selected security policy profile"
        >
          {showIcon && <Shield className="w-3 h-3 text-purple-400" />}
          <span>POLICY</span>
        </span>
      );
    case 'CONTEXTUAL':
      return (
        <span
          className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider bg-amber-950/70 text-amber-300 border border-amber-800/80 ${className}`}
          title="Derived contextual risk interpretation; not directly observed as an attack"
        >
          {showIcon && <Compass className="w-3 h-3 text-amber-400" />}
          <span>CONTEXTUAL</span>
        </span>
      );
    case 'AI_ASSISTED':
      return (
        <span
          className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider bg-emerald-950/70 text-emerald-300 border border-emerald-800/80 ${className}`}
          title="Contextual explanation or prioritization produced using extracted evidence"
        >
          {showIcon && <Sparkles className="w-3 h-3 text-emerald-400" />}
          <span>AI-ASSISTED</span>
        </span>
      );
    default:
      return null;
  }
};
