import React from 'react';
import { AlertCircle, RefreshCw } from 'lucide-react';

export function ErrorBanner({ title = 'Error', message, onRetry }) {
  return (
    <div className="bg-red-950/40 border border-red-800/60 rounded-xl p-4 sm:p-5 flex items-start gap-3 shadow-lg shadow-red-950/20">
      <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
      <div className="flex-1 min-w-0">
        <h4 className="text-sm font-semibold text-red-300">{title}</h4>
        {message && <p className="text-xs text-red-200/80 mt-1">{message}</p>}
      </div>
      {onRetry && (
        <button
          onClick={onRetry}
          className="px-3 py-1.5 bg-red-900/60 hover:bg-red-800/80 text-red-200 rounded-lg text-xs font-medium border border-red-700/50 flex items-center gap-1.5 transition-colors cursor-pointer"
        >
          <RefreshCw size={12} />
          Retry
        </button>
      )}
    </div>
  );
}
