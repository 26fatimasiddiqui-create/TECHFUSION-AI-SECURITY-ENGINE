import React, { useState, useEffect } from 'react';
import { 
  Server, 
  RefreshCw, 
  Play, 
  Sun, 
  Moon, 
  Sparkles, 
  Gauge, 
  BookOpen,
  ShieldAlert,
  Bell
} from 'lucide-react';
import { getHealth } from '../../services/api';
import { useTheme } from '../../context/ThemeContext';
import { useMode } from '../../context/ModeContext';

export function Header({ onRefresh, isRefreshing, onRunDemo, alertCount = 0, onOpenAlerts }) {
  const [healthStatus, setHealthStatus] = useState({ isLive: false, status: 'checking' });
  const [timeStr, setTimeStr] = useState('');
  
  const { theme, toggleTheme, isDark } = useTheme();
  const { mode, setMode, isProMode, isEasyMode } = useMode();

  useEffect(() => {
    const updateClock = () => {
      const now = new Date();
      setTimeStr(now.toLocaleTimeString('en-US', { hour12: false }));
    };
    updateClock();
    const timer = setInterval(updateClock, 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    async function checkBackend() {
      const h = await getHealth();
      setHealthStatus({ isLive: h.isLive, status: h.data.status });
    }
    checkBackend();
  }, []);

  return (
    <header className="h-16 bg-white/90 dark:bg-slate-950/80 backdrop-blur-md border-b border-slate-200 dark:border-slate-800/80 px-4 sm:px-6 flex items-center justify-between z-20 shrink-0 transition-colors">
      
      {/* Title & Live Engine Badge */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2">
          <div className="text-sm font-bold text-slate-900 dark:text-white tracking-wide flex items-center gap-2">
            <span className="text-cyan-600 dark:text-cyan-400 font-mono font-extrabold">ThreatFusion</span>
            <span className="text-slate-500 dark:text-slate-400 font-normal hidden sm:inline">Autonomous AI SOC</span>
          </div>
        </div>

        {/* Global Mode Pill Indicator */}
        <span className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase tracking-wider hidden lg:inline-flex items-center gap-1 border ${
          isEasyMode 
            ? 'bg-emerald-50 dark:bg-emerald-950/80 text-emerald-700 dark:text-emerald-300 border-emerald-300 dark:border-emerald-700'
            : 'bg-cyan-50 dark:bg-cyan-950/80 text-cyan-700 dark:text-cyan-300 border-cyan-300 dark:border-cyan-700'
        }`}>
          <span className="w-1.5 h-1.5 rounded-full bg-current"></span>
          {isEasyMode ? 'Easy Mode Active' : 'Pro SOC Active'}
        </span>
      </div>

      {/* Center / Right Controls Bar */}
      <div className="flex items-center gap-2 sm:gap-3">
        
        {/* 1. Global UI Mode Switch: [ Pro | Easy ] */}
        <div 
          role="radiogroup" 
          aria-label="UI Mode Selector"
          className="flex items-center p-0.5 bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl text-xs font-medium"
        >
          <button
            type="button"
            role="radio"
            aria-checked={isProMode}
            onClick={() => setMode('pro')}
            className={`px-2.5 py-1 rounded-lg flex items-center gap-1.5 transition-all cursor-pointer ${
              isProMode
                ? 'bg-white dark:bg-slate-800 text-cyan-600 dark:text-cyan-300 font-bold shadow-sm'
                : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
            }`}
            title="Pro Mode: Full detailed cybersecurity telemetry, graphs, and deep correlation"
          >
            <Gauge size={13} />
            <span>Pro</span>
          </button>

          <button
            type="button"
            role="radio"
            aria-checked={isEasyMode}
            onClick={() => setMode('easy')}
            className={`px-2.5 py-1 rounded-lg flex items-center gap-1.5 transition-all cursor-pointer ${
              isEasyMode
                ? 'bg-white dark:bg-slate-800 text-emerald-600 dark:text-emerald-300 font-bold shadow-sm'
                : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
            }`}
            title="Easy Mode: Human-understandable story flow without complex technical jargon"
          >
            <BookOpen size={13} />
            <span>Easy</span>
          </button>
        </div>

        {/* 2. Global Theme Switch: [ Dark | Light ] */}
        <button
          type="button"
          onClick={toggleTheme}
          aria-label={isDark ? 'Switch to Light Theme' : 'Switch to Dark Theme'}
          className="p-2 rounded-xl bg-slate-100 dark:bg-slate-900 hover:bg-slate-200 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 transition-colors cursor-pointer"
          title={isDark ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
        >
          {isDark ? (
            <Sun size={15} className="text-amber-400" />
          ) : (
            <Moon size={15} className="text-slate-700" />
          )}
        </button>

        {/* Run Demo Attack Chain Button */}
        {onRunDemo && (
          <button
            onClick={onRunDemo}
            className="hidden md:flex items-center gap-1.5 px-3 py-1.5 bg-gradient-to-r from-red-600 to-rose-700 hover:from-red-500 hover:to-rose-600 text-white rounded-xl text-xs font-bold shadow-sm shadow-red-950/30 transition-all cursor-pointer"
            title="Inject the 6-step attack scenario to test multi-event correlation"
          >
            <Play size={12} className="fill-white" />
            <span>Run Attack Demo</span>
          </button>
        )}

        {/* Backend API Status Pill */}
        <div className="hidden sm:flex items-center gap-2 px-2.5 py-1 bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl text-xs">
          <Server size={13} className={healthStatus.isLive ? 'text-emerald-500' : 'text-amber-500'} />
          <span className="font-mono text-[11px] text-slate-700 dark:text-slate-300">
            {healthStatus.isLive ? 'ONLINE' : 'LOCAL'}
          </span>
        </div>

        {/* Refresh Button */}
        <button
          onClick={onRefresh}
          disabled={isRefreshing}
          aria-label="Refresh telemetry data"
          className="p-2 bg-slate-100 dark:bg-slate-900 hover:bg-slate-200 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 rounded-xl transition-colors cursor-pointer disabled:opacity-50"
          title="Refresh dashboard data"
        >
          <RefreshCw size={14} className={isRefreshing ? 'animate-spin text-cyan-500' : ''} />
        </button>

        {/* UTC Time */}
        <div className="hidden xl:flex items-center gap-2 font-mono text-xs text-slate-500 dark:text-slate-400 bg-slate-100 dark:bg-slate-900/60 px-2.5 py-1 border border-slate-200 dark:border-slate-800/60 rounded-xl">
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-500"></span>
          <span>{timeStr} UTC</span>
        </div>

      </div>
    </header>
  );
}

export default Header;
