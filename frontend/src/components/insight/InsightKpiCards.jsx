import React from 'react';
import { Users, AlertTriangle, ShieldAlert, Clock, ArrowUpRight } from 'lucide-react';

export function InsightKpiCards({ 
  totalEmployees = 0, 
  highRiskEmployees = 0, 
  criticalAlerts = 0, 
  alertsToday = 0 
}) {
  const cards = [
    {
      title: 'TOTAL EMPLOYEES',
      value: totalEmployees,
      subtitle: 'Monitored Identity Profiles',
      icon: Users,
      color: 'text-cyan-600 dark:text-cyan-400',
      badge: 'Active Baseline',
      badgeColor: 'bg-cyan-50 dark:bg-cyan-950/70 border-cyan-200 dark:border-cyan-800 text-cyan-700 dark:text-cyan-300',
      border: 'border-slate-200 dark:border-slate-800 hover:border-cyan-400 dark:hover:border-cyan-800/60'
    },
    {
      title: 'HIGH RISK EMPLOYEES',
      value: highRiskEmployees,
      subtitle: 'Risk Score ≥ 70 or Critical',
      icon: AlertTriangle,
      color: 'text-amber-600 dark:text-amber-400',
      badge: highRiskEmployees > 0 ? 'Requires Action' : 'Nominal',
      badgeColor: highRiskEmployees > 0 ? 'bg-amber-50 dark:bg-amber-950/80 border-amber-200 dark:border-amber-700 text-amber-700 dark:text-amber-300' : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-700',
      border: 'border-slate-200 dark:border-slate-800 hover:border-amber-400 dark:hover:border-amber-800/60'
    },
    {
      title: 'CRITICAL ALERTS',
      value: criticalAlerts,
      subtitle: 'Immediate Escalation Vectors',
      icon: ShieldAlert,
      color: 'text-rose-600 dark:text-rose-400',
      badge: criticalAlerts > 0 ? 'Elevated' : 'None Active',
      badgeColor: criticalAlerts > 0 ? 'bg-rose-50 dark:bg-rose-950/80 border-rose-200 dark:border-rose-700 text-rose-700 dark:text-rose-300 animate-pulse' : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-700',
      border: 'border-slate-200 dark:border-slate-800 hover:border-rose-400 dark:hover:border-rose-800/60'
    },
    {
      title: 'ALERTS TODAY',
      value: alertsToday,
      subtitle: 'Dispatched to n8n / Supabase',
      icon: Clock,
      color: 'text-purple-600 dark:text-purple-400',
      badge: 'Live Logged',
      badgeColor: 'bg-purple-50 dark:bg-purple-950/70 border-purple-200 dark:border-purple-800 text-purple-700 dark:text-purple-300',
      border: 'border-slate-200 dark:border-slate-800 hover:border-purple-400 dark:hover:border-purple-800/60'
    }
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {cards.map((card, idx) => {
        const Icon = card.icon;
        return (
          <div
            key={idx}
            className={`p-5 rounded-2xl bg-white dark:bg-slate-900/90 border ${card.border} transition-all duration-200 shadow-xs dark:shadow-lg dark:shadow-black/20 flex flex-col justify-between space-y-3 group`}
          >
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-mono uppercase font-bold tracking-wider text-slate-500 dark:text-slate-400">
                {card.title}
              </span>
              <div className={`p-2 rounded-xl bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 ${card.color} group-hover:scale-105 transition-transform`}>
                <Icon size={16} />
              </div>
            </div>

            <div className="flex items-baseline justify-between">
              <span className="text-3xl font-black font-mono text-slate-900 dark:text-white tracking-tight">
                {card.value}
              </span>
              <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${card.badgeColor}`}>
                {card.badge}
              </span>
            </div>

            <div className="pt-2 border-t border-slate-100 dark:border-slate-800/60 text-[11px] text-slate-500 dark:text-slate-400 font-sans truncate">
              {card.subtitle}
            </div>
          </div>
        );
      })}
    </div>
  );
}
