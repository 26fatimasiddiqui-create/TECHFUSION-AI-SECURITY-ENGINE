import React from 'react';

export function RiskBadge({ level = 'LOW', score = null, className = '' }) {
  const normLevel = (level || 'LOW').toUpperCase();

  const styles = {
    LOW: 'bg-emerald-50 dark:bg-emerald-950/70 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-700/50 shadow-sm',
    MODERATE: 'bg-amber-50 dark:bg-amber-950/70 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-700/50 shadow-sm',
    HIGH: 'bg-orange-50 dark:bg-orange-950/70 text-orange-700 dark:text-orange-400 border-orange-200 dark:border-orange-700/50 shadow-sm',
    CRITICAL: 'bg-red-50 dark:bg-red-950/80 text-red-700 dark:text-red-300 border-red-300 dark:border-red-600/70 shadow-sm font-bold',
  };

  const activeStyle = styles[normLevel] || styles.LOW;

  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold tracking-wider border ${activeStyle} ${className}`}>
      <span className="w-1.5 h-1.5 rounded-full bg-current"></span>
      {normLevel}
      {score !== null && score !== undefined && (
        <span className="opacity-80 font-mono text-[11px] ml-0.5">({score})</span>
      )}
    </span>
  );
}

export function StatusBadge({ status = 'active', className = '' }) {
  const normStatus = (status || 'active').toLowerCase();

  const statusStyles = {
    active: 'bg-cyan-50 dark:bg-cyan-950/60 text-cyan-700 dark:text-cyan-400 border-cyan-200 dark:border-cyan-800/40',
    escalated: 'bg-red-50 dark:bg-red-950/70 text-red-700 dark:text-red-400 border-red-200 dark:border-red-700/50',
    acknowledged: 'bg-blue-50 dark:bg-blue-950/60 text-blue-700 dark:text-blue-400 border-blue-200 dark:border-blue-800/40',
    resolved: 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-400 border-slate-300 dark:border-slate-700',
    archived: 'bg-slate-100 dark:bg-slate-900 text-slate-500 border-slate-300 dark:border-slate-800',
  };

  const activeStyle = statusStyles[normStatus] || statusStyles.active;

  return (
    <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-md text-xs font-medium border uppercase tracking-wider ${activeStyle} ${className}`}>
      {normStatus}
    </span>
  );
}

export function SignalPill({ signal, className = '' }) {
  return (
    <span className={`inline-block px-2 py-0.5 bg-slate-100 dark:bg-slate-800/80 text-slate-700 dark:text-slate-300 border border-slate-300 dark:border-slate-700/60 rounded text-[11px] font-mono tracking-tight ${className}`}>
      {signal}
    </span>
  );
}
