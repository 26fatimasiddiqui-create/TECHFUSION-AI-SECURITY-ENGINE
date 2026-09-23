import React from 'react';

export function Card({ children, className = '', glow = false, hover = false }) {
  return (
    <div
      className={`bg-white dark:bg-slate-900/80 backdrop-blur-md border border-slate-200 dark:border-slate-800 rounded-xl p-5 shadow-sm dark:shadow-lg transition-all text-slate-900 dark:text-slate-100 ${
        glow ? 'border-cyan-500/40 shadow-cyan-950/20' : ''
      } ${hover ? 'hover:border-slate-300 dark:hover:border-slate-700 hover:shadow-md dark:hover:shadow-slate-900/40' : ''} ${className}`}
    >
      {children}
    </div>
  );
}

export function MetricCard({ title, value, subtitle, icon: Icon, trend, color = 'cyan' }) {
  const colorMap = {
    cyan: 'text-cyan-600 dark:text-cyan-400 bg-cyan-50 dark:bg-cyan-950/50 border-cyan-200 dark:border-cyan-800/40',
    red: 'text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-950/50 border-red-200 dark:border-red-800/40',
    amber: 'text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/50 border-amber-200 dark:border-amber-800/40',
    emerald: 'text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/50 border-emerald-200 dark:border-emerald-800/40',
    purple: 'text-purple-600 dark:text-purple-400 bg-purple-50 dark:bg-purple-950/50 border-purple-200 dark:border-purple-800/40',
  };

  const activeColor = colorMap[color] || colorMap.cyan;

  return (
    <Card className="flex flex-col justify-between relative overflow-hidden">
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">{title}</span>
        {Icon && (
          <div className={`p-2 rounded-lg border ${activeColor}`}>
            <Icon size={18} />
          </div>
        )}
      </div>
      <div className="flex items-baseline gap-2">
        <span className="text-2xl sm:text-3xl font-bold font-mono text-slate-900 dark:text-white tracking-tight">{value}</span>
        {trend && (
          <span className="text-xs font-medium text-slate-500 dark:text-slate-400">
            {trend}
          </span>
        )}
      </div>
      {subtitle && <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{subtitle}</p>}
    </Card>
  );
}

export default Card;
