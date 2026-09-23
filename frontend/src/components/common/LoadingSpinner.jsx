import React from 'react';
import { RefreshCw } from 'lucide-react';

export function LoadingSpinner({ text = 'Loading security data...', size = 'default' }) {
  return (
    <div className="flex flex-col items-center justify-center py-12 px-4 gap-3">
      <RefreshCw className="w-7 h-7 text-cyan-400 animate-spin" />
      <span className="text-sm font-medium text-slate-400 tracking-wide">{text}</span>
    </div>
  );
}

export function SkeletonRow({ cols = 5 }) {
  return (
    <tr className="animate-pulse border-b border-slate-800/60">
      {Array.from({ length: cols }).map((_, idx) => (
        <td key={idx} className="py-4 px-4">
          <div className="h-4 bg-slate-800 rounded w-full max-w-[120px]"></div>
        </td>
      ))}
    </tr>
  );
}
