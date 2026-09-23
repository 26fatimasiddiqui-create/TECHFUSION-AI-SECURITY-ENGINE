import React from 'react';
import { 
  ShieldAlert, 
  LayoutDashboard, 
  Activity, 
  Flame, 
  Cpu, 
  Bell, 
  Network,
  Globe
} from 'lucide-react';
import { useMode } from '../../context/ModeContext';

export function Sidebar({ currentTab, setTab, alertCount = 0 }) {
  const { isEasyMode } = useMode();

  const navItems = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'internal-threats', label: 'Internal Threats', icon: ShieldAlert },
    { id: 'external-threats', label: 'External Threats', icon: Globe },
    { id: 'events', label: 'Live Events', icon: Activity },
    { id: 'incidents', label: 'Incidents', icon: Flame },
    { id: 'graph', label: 'Activity Graph', icon: Network },
    { id: 'analysis', label: 'Risk Analysis', icon: Cpu },
    { id: 'alerts', label: 'Alerts', icon: Bell, badge: alertCount },
  ];

  return (
    <aside className="w-64 bg-white dark:bg-slate-950 border-r border-slate-200 dark:border-slate-800/80 flex flex-col shrink-0 transition-colors">
      {/* Brand Header */}
      <div className="h-20 flex items-center px-4 gap-3 border-b border-slate-200 dark:border-slate-800/80 bg-slate-50/70 dark:bg-slate-950/60">
        <img 
          src="/techfusion-logo.jpg" 
          alt="TechFusion Logo" 
          className="w-11 h-11 rounded-lg object-cover ring-2 ring-cyan-500/40 shadow-md shadow-cyan-500/20"
        />
        <div className="min-w-0 flex-1">
          <div className="font-extrabold text-slate-900 dark:text-white tracking-wider text-sm flex items-center gap-1.5 font-mono">
            <span className="bg-gradient-to-r from-cyan-600 via-sky-600 to-amber-600 dark:from-cyan-400 dark:via-sky-300 dark:to-amber-300 bg-clip-text text-transparent font-black tracking-widest text-[15px]">
              TECHFUSION
            </span>
          </div>
          <p className="text-[9.5px] text-slate-500 dark:text-slate-400 tracking-tight font-medium uppercase truncate">
            Secure Today • Stronger Tomorrow
          </p>
        </div>
      </div>

      {/* Navigation Links */}
      <nav className="flex-1 px-3 py-5 space-y-1.5 overflow-y-auto">
        <div className="px-3 pb-2 text-[11px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 flex items-center justify-between">
          <span>{isEasyMode ? 'Navigation' : 'Core Modules'}</span>
          {isEasyMode && (
            <span className="text-[9px] font-mono text-emerald-600 dark:text-emerald-400 font-bold">
              EASY
            </span>
          )}
        </div>

        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setTab(item.id)}
              className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl text-xs font-medium transition-all cursor-pointer ${
                isActive
                  ? 'bg-cyan-50 dark:bg-cyan-950/70 text-cyan-700 dark:text-cyan-300 border border-cyan-200 dark:border-cyan-700/50 shadow-sm font-semibold'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-900/60'
              }`}
            >
              <div className="flex items-center gap-3">
                <Icon size={16} className={isActive ? 'text-cyan-600 dark:text-cyan-400' : 'text-slate-400 dark:text-slate-500'} />
                <span>{item.label}</span>
              </div>
              {item.badge > 0 && (
                <span className="px-2 py-0.5 text-[10px] font-bold rounded-full bg-red-100 dark:bg-red-900/80 text-red-700 dark:text-red-200 border border-red-200 dark:border-red-700">
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Bottom Status Panel */}
      <div className="p-4 border-t border-slate-200 dark:border-slate-800/80 bg-slate-50/80 dark:bg-slate-950/80">
        <div className="p-3 bg-white dark:bg-slate-900/90 rounded-xl border border-slate-200 dark:border-slate-800 flex items-center justify-between shadow-xs">
          <div className="flex items-center gap-2.5">
            <span className="inline-flex rounded-full h-2 w-2 bg-emerald-500 shadow-sm shadow-emerald-500/50"></span>
            <span className="text-[11px] font-mono text-slate-700 dark:text-slate-300">Defense Mesh</span>
          </div>
          <span className="text-[10px] font-mono text-emerald-600 dark:text-emerald-400 font-semibold">ACTIVE</span>
        </div>
      </div>
    </aside>
  );
}

export default Sidebar;
