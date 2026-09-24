import React from 'react';
import { 
  Radio, 
  X, 
  CheckCircle2, 
  XCircle, 
  RefreshCw, 
  Clock, 
  ExternalLink,
  Shield,
  Zap
} from 'lucide-react';
import { N8N_PRODUCTION_WEBHOOK } from '../../services/n8nService';

export function InsightN8nHealthModal({ 
  healthResult, 
  isLoading, 
  onRetest, 
  onClose 
}) {
  if (!healthResult && !isLoading) return null;

  const isConnected = healthResult?.connected;

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4 overflow-y-auto animate-in fade-in duration-200">
      <div 
        className="w-full max-w-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-2xl overflow-hidden my-8"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="p-5 border-b border-slate-100 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-xl border ${
              isConnected 
                ? 'bg-emerald-50 dark:bg-emerald-950 border-emerald-200 dark:border-emerald-700 text-emerald-700 dark:text-emerald-400' 
                : 'bg-rose-50 dark:bg-rose-950 border-rose-200 dark:border-rose-700 text-rose-700 dark:text-rose-400'
            }`}>
              <Radio size={18} className={isLoading ? 'animate-pulse' : ''} />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-900 dark:text-white font-mono">
                n8n Webhook Connection Health
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 font-sans">
                Live automated probe to production workflow endpoint
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-xl bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors cursor-pointer"
          >
            <X size={16} />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 space-y-4 font-mono text-xs">
          
          {isLoading ? (
            <div className="p-8 text-center space-y-3">
              <RefreshCw size={24} className="animate-spin text-cyan-600 dark:text-cyan-400 mx-auto" />
              <div className="text-slate-900 dark:text-white font-bold">Pinging n8n Production Webhook...</div>
              <p className="text-slate-500 text-[11px] font-sans">Measuring latency and verifying HTTP handshake</p>
            </div>
          ) : (
            <>
              {/* Primary Status Grid */}
              <div className="grid grid-cols-2 gap-3">
                <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1">
                  <span className="text-slate-500 dark:text-slate-400 text-[10px] uppercase block">WEBHOOK STATUS</span>
                  <div className="flex items-center gap-2">
                    {isConnected ? (
                      <CheckCircle2 size={16} className="text-emerald-600 dark:text-emerald-400 shrink-0" />
                    ) : (
                      <XCircle size={16} className="text-rose-600 dark:text-rose-400 shrink-0" />
                    )}
                    <span className={`text-base font-black ${isConnected ? 'text-emerald-600 dark:text-emerald-400' : 'text-rose-600 dark:text-rose-400'}`}>
                      {isConnected ? 'CONNECTED' : 'FAILED'}
                    </span>
                  </div>
                </div>

                <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1">
                  <span className="text-slate-500 dark:text-slate-400 text-[10px] uppercase block">HTTP STATUS</span>
                  <div className="text-base font-black text-slate-900 dark:text-white">
                    {healthResult?.status || '0'} <span className="text-xs text-slate-500 dark:text-slate-400 font-normal">({healthResult?.statusText || 'Error'})</span>
                  </div>
                </div>
              </div>

              {/* Endpoint URL & Latency */}
              <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1">
                <span className="text-slate-500 dark:text-slate-400 text-[10px] uppercase block">ENDPOINT URL</span>
                <div className="text-cyan-700 dark:text-cyan-300 text-[11px] break-all select-all font-mono">
                  {N8N_PRODUCTION_WEBHOOK}
                </div>
                <div className="text-slate-500 dark:text-slate-400 text-[10px] pt-1 flex items-center justify-between">
                  <span>Roundtrip Latency: <strong className="text-slate-900 dark:text-white">{healthResult?.timeMs || 0} ms</strong></span>
                  <span className="text-emerald-600 dark:text-emerald-400 font-bold">Production Webhook Active</span>
                </div>
              </div>

              {/* Actual Response Body */}
              <div className="space-y-1.5">
                <span className="text-slate-500 dark:text-slate-400 text-[10px] uppercase font-bold block">
                  WORKFLOW RESPONSE BODY
                </span>
                <pre className="p-3.5 rounded-xl bg-slate-900 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-emerald-300 text-[11px] overflow-x-auto">
{JSON.stringify(healthResult?.data || { error: healthResult?.error || 'No response data' }, null, 2)}
                </pre>
              </div>
            </>
          )}

        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-100 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/80 flex items-center justify-between text-xs font-mono">
          <button
            onClick={onRetest}
            disabled={isLoading}
            className="px-3.5 py-1.5 rounded-xl bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 transition-colors cursor-pointer flex items-center gap-1.5 border border-slate-200 dark:border-slate-700 font-semibold"
          >
            <RefreshCw size={12} className={isLoading ? 'animate-spin' : ''} />
            <span>Retest Connection</span>
          </button>

          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-200 dark:bg-slate-800 hover:bg-slate-300 dark:hover:bg-slate-700 text-slate-800 dark:text-white rounded-xl transition-colors cursor-pointer font-semibold"
          >
            Close
          </button>
        </div>

      </div>
    </div>
  );
}
