import React from 'react';
import { SeverityLevel } from '../../types/security';

interface Props {
  severity: SeverityLevel;
  size?: 'sm' | 'md';
}

export const SeverityBadge: React.FC<Props> = ({ severity, size = 'sm' }) => {
  const styles: Record<SeverityLevel, { bg: string; text: string; border: string }> = {
    CRITICAL: {
      bg: 'bg-rose-950/40',
      text: 'text-rose-400',
      border: 'border-rose-800/60'
    },
    HIGH: {
      bg: 'bg-amber-950/40',
      text: 'text-amber-400',
      border: 'border-amber-800/60'
    },
    MEDIUM: {
      bg: 'bg-yellow-950/30',
      text: 'text-yellow-400',
      border: 'border-yellow-800/50'
    },
    LOW: {
      bg: 'bg-cyan-950/40',
      text: 'text-cyan-400',
      border: 'border-cyan-800/50'
    },
    INFORMATIONAL: {
      bg: 'bg-slate-900',
      text: 'text-slate-400',
      border: 'border-slate-700/60'
    }
  };

  const current = styles[severity] || styles.INFORMATIONAL;
  const sizeClasses = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-xs tracking-wide';

  return (
    <span
      className={`inline-flex items-center font-mono font-medium rounded border ${current.bg} ${current.text} ${current.border} ${sizeClasses}`}
    >
      <span className="w-1.5 h-1.5 rounded-full mr-1.5 bg-current opacity-80" />
      {severity}
    </span>
  );
};
