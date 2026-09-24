import React from 'react';
import { 
  ShieldAlert, 
  RefreshCw, 
  Activity, 
  Play, 
  Radio, 
  CheckCircle2, 
  XCircle,
  Clock,
  Terminal,
  Layers,
  Database,
  Sun,
  Moon
} from 'lucide-react';
import { isSupabaseConfigured } from '../../services/insightSupabase';
import { useTheme } from '../../context/ThemeContext';

export function InsightHeader({ 
  lastUpdated, 
  isRefreshing, 
  onRefresh, 
  onTestConnection, 
  isTestingConnection,
  n8nStatus,
  onOpenApiTest,
  activeSection,
  setActiveSection
}) {
  const { theme, toggleTheme, isDark } = useTheme();

  return (
    <header className="bg-white/95 dark:bg-slate-900/95 border-b border-slate-200 dark:border-slate-800 backdrop-blur-md px-4 sm:px-6 py-4 sticky top-0 z-30 shadow-xs dark:shadow-md transition-colors duration-200">
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        
        {/* Title, Subtitle & Status Badges */}
        <div className="flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-red-600 via-rose-600 to-amber-600 flex items-center justify-center text-white shadow-md shadow-red-500/20 dark:shadow-red-950/40 shrink-0">
            <ShieldAlert size={22} />
          </div>
          <div>
            <div className="flex items-center gap-2.5 flex-wrap">
              <h1 className="text-xl sm:text-2xl font-black text-slate-900 dark:text-white tracking-wider font-mono">
                INSIGHT
              </h1>
              
              {/* System Status: ONLINE */}
              <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-emerald-50 dark:bg-emerald-950/90 text-emerald-700 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800 shadow-xs">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
                <span>SYSTEM ONLINE</span>
              </span>

              {/* Supabase Status Badge */}
              <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-mono border ${
                isSupabaseConfigured 
                  ? 'bg-cyan-50 dark:bg-cyan-950/80 text-cyan-700 dark:text-cyan-300 border-cyan-200 dark:border-cyan-800' 
                  : 'bg-slate-100 dark:bg-slate-800/80 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-700'
              }`}>
                <Database size={11} />
                <span>{isSupabaseConfigured ? 'SUPABASE CONNECTED' : 'SUPABASE FALLBACK'}</span>
              </span>
            </div>
            
            <p className="text-xs text-slate-500 dark:text-slate-400 font-sans tracking-wide mt-0.5">
              Insider Threat Detection & Risk Monitoring
            </p>
          </div>
        </div>

        {/* Action Controls & Navigation Pills */}
        <div className="flex items-center gap-2.5 flex-wrap">
          
          {/* Sub-view Navigation */}
          <div className="flex items-center bg-slate-100 dark:bg-slate-950 p-1 rounded-xl border border-slate-200 dark:border-slate-800 text-xs font-mono">
            <button
              onClick={() => setActiveSection('dashboard')}
              className={`px-3 py-1.5 rounded-lg transition-all cursor-pointer font-semibold ${
                activeSection === 'dashboard'
                  ? 'bg-white dark:bg-rose-950/80 text-rose-700 dark:text-rose-300 border border-slate-200 dark:border-rose-800/60 shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
              }`}
            >
              Dashboard
            </button>
            <button
              onClick={() => setActiveSection('api-test')}
              className={`px-3 py-1.5 rounded-lg transition-all cursor-pointer font-semibold flex items-center gap-1.5 ${
                activeSection === 'api-test'
                  ? 'bg-white dark:bg-rose-950/80 text-rose-700 dark:text-rose-300 border border-slate-200 dark:border-rose-800/60 shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
              }`}
            >
              <Terminal size={13} />
              <span>API Test</span>
            </button>
          </div>

          {/* Test n8n Connection Button */}
          <button
            onClick={onTestConnection}
            disabled={isTestingConnection}
            className={`px-3 py-2 rounded-xl text-xs font-mono font-semibold border flex items-center gap-1.5 transition-all cursor-pointer ${
              n8nStatus === 'connected'
                ? 'bg-emerald-50 dark:bg-emerald-950/70 border-emerald-300 dark:border-emerald-700 text-emerald-700 dark:text-emerald-300 hover:bg-emerald-100 dark:hover:bg-emerald-900/80'
                : n8nStatus === 'failed'
                ? 'bg-rose-50 dark:bg-rose-950/70 border-rose-300 dark:border-rose-700 text-rose-700 dark:text-rose-300 hover:bg-rose-100 dark:hover:bg-rose-900/80'
                : 'bg-slate-100 dark:bg-slate-950 hover:bg-slate-200 dark:hover:bg-slate-800 border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300'
            }`}
            title="Perform live health check probe to n8n webhook"
          >
            {isTestingConnection ? (
              <RefreshCw size={13} className="animate-spin text-cyan-600 dark:text-cyan-400" />
            ) : n8nStatus === 'connected' ? (
              <CheckCircle2 size={13} className="text-emerald-600 dark:text-emerald-400" />
            ) : n8nStatus === 'failed' ? (
              <XCircle size={13} className="text-rose-600 dark:text-rose-400" />
            ) : (
              <Radio size={13} className="text-cyan-600 dark:text-cyan-400" />
            )}
            <span>{isTestingConnection ? 'Testing...' : 'Test n8n Connection'}</span>
          </button>

          {/* Light / Dark Mode Toggle Switch */}
          <button
            onClick={toggleTheme}
            className="p-2 rounded-xl bg-slate-100 dark:bg-slate-950 hover:bg-slate-200 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 transition-all cursor-pointer shadow-xs flex items-center gap-1.5"
            title={isDark ? "Switch to Light Mode" : "Switch to Dark Mode"}
            aria-label="Toggle Light/Dark Theme"
          >
            {isDark ? (
              <>
                <Sun size={15} className="text-amber-400" />
                <span className="text-[11px] font-mono font-bold text-slate-300 hidden md:inline">Light</span>
              </>
            ) : (
              <>
                <Moon size={15} className="text-cyan-600" />
                <span className="text-[11px] font-mono font-bold text-slate-700 hidden md:inline">Dark</span>
              </>
            )}
          </button>

          {/* Refresh Button & Timestamp */}
          <div className="flex items-center gap-2 pl-1 border-l border-slate-200 dark:border-slate-800">
            <button
              onClick={onRefresh}
              disabled={isRefreshing}
              className="p-2 rounded-xl bg-slate-100 dark:bg-slate-950 hover:bg-slate-200 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white transition-all cursor-pointer shadow-xs"
              title="Refresh dashboard data"
            >
              <RefreshCw size={14} className={isRefreshing ? 'animate-spin text-rose-500' : ''} />
            </button>

            <div className="hidden sm:flex flex-col text-right font-mono text-[10px] text-slate-400 dark:text-slate-500">
              <span className="text-slate-500 dark:text-slate-400 font-bold">UPDATED</span>
              <span>{lastUpdated ? new Date(lastUpdated).toLocaleTimeString() : '--:--:--'}</span>
            </div>
          </div>

        </div>

      </div>
    </header>
  );
}
