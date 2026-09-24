import React from 'react';
import { 
  PieChart, 
  Pie, 
  Cell, 
  ResponsiveContainer, 
  Tooltip 
} from 'recharts';
import { Shield, AlertTriangle, Flame, CheckCircle, PieChart as PieIcon } from 'lucide-react';

export function InsightRiskOverview({ employees = [] }) {
  // Aggregate employee counts strictly by each employee's LATEST risk score
  const counts = {
    LOW: 0,
    MODERATE: 0,
    HIGH: 0,
    CRITICAL: 0
  };

  employees.forEach((emp) => {
    const score = Number(emp.latestRiskScore || 0);
    if (score >= 85) counts.CRITICAL++;
    else if (score >= 70) counts.HIGH++;
    else if (score >= 40) counts.MODERATE++;
    else counts.LOW++;
  });

  const total = employees.length;

  const data = [
    { name: 'Low (0–39)', key: 'LOW', value: counts.LOW, color: '#10b981', desc: 'Standard Activity' },
    { name: 'Moderate (40–69)', key: 'MODERATE', value: counts.MODERATE, color: '#facc15', desc: 'Baseline Deviations' },
    { name: 'High (70–84)', key: 'HIGH', value: counts.HIGH, color: '#f97316', desc: 'Anomalous Sequences' },
    { name: 'Critical (85–100)', key: 'CRITICAL', value: counts.CRITICAL, color: '#ef4444', desc: 'Active Exfiltration' }
  ];

  const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
      const item = payload[0].payload;
      const pct = total > 0 ? Math.round((item.value / total) * 100) : 0;
      return (
        <div className="bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800 p-3 rounded-xl shadow-xl font-mono text-xs space-y-1">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item.color }} />
            <span className="font-bold text-slate-900 dark:text-white">{item.name}</span>
          </div>
          <div className="text-slate-600 dark:text-slate-300">
            Count: <strong className="text-slate-900 dark:text-white">{item.value}</strong> ({pct}% of staff)
          </div>
          <div className="text-[10px] text-slate-500 dark:text-slate-400 font-sans">{item.desc}</div>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="p-5 rounded-2xl bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 shadow-xs dark:shadow-lg dark:shadow-black/20 space-y-4">
      <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800/80 pb-3">
        <div>
          <h3 className="text-xs font-bold uppercase font-mono tracking-wider text-slate-800 dark:text-slate-200 flex items-center gap-2">
            <PieIcon size={14} className="text-cyan-600 dark:text-cyan-400" />
            <span>Risk Posture Overview</span>
          </h3>
          <p className="text-[11px] text-slate-500 dark:text-slate-400 font-sans">
            Calculated from the latest risk state of each employee (1 count per employee)
          </p>
        </div>
        <span className="text-[10px] font-mono font-bold text-cyan-700 dark:text-cyan-400 bg-cyan-50 dark:bg-cyan-950/60 border border-cyan-200 dark:border-cyan-800 px-2 py-0.5 rounded">
          {total} Monitored
        </span>
      </div>

      {total === 0 ? (
        <div className="py-12 text-center text-slate-500 font-mono text-xs space-y-1">
          <p className="text-slate-600 dark:text-slate-400 font-bold">No risk data available</p>
          <p className="text-[11px] text-slate-400 dark:text-slate-600">Employee risk assessments will appear once employees are registered in Supabase.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-12 gap-4 items-center">
          
          {/* Recharts Donut Pie Chart */}
          <div className="md:col-span-5 h-48 relative flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Tooltip content={<CustomTooltip />} />
                <Pie
                  data={data}
                  cx="50%"
                  cy="50%"
                  innerRadius={52}
                  outerRadius={76}
                  paddingAngle={4}
                  dataKey="value"
                  stroke="none"
                >
                  {data.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
              </PieChart>
            </ResponsiveContainer>

            {/* Central Donut Counter */}
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <span className="text-2xl font-black font-mono text-slate-900 dark:text-white">
                {counts.CRITICAL + counts.HIGH}
              </span>
              <span className="text-[9px] font-mono uppercase tracking-wider text-slate-500 dark:text-slate-400">
                Elevated
              </span>
            </div>
          </div>

          {/* Breakdown Pills List */}
          <div className="md:col-span-7 space-y-2">
            {data.map((d) => {
              const pct = total > 0 ? Math.round((d.value / total) * 100) : 0;
              return (
                <div 
                  key={d.key}
                  className="p-2 rounded-xl bg-slate-50 dark:bg-slate-950/80 border border-slate-200 dark:border-slate-800/80 flex items-center justify-between text-xs font-mono"
                >
                  <div className="flex items-center gap-2.5">
                    <span 
                      className="w-2.5 h-2.5 rounded-full shrink-0 shadow-xs" 
                      style={{ backgroundColor: d.color }} 
                    />
                    <div>
                      <span className="font-bold text-slate-800 dark:text-slate-200">{d.name}</span>
                      <span className="text-[10px] text-slate-500 dark:text-slate-400 font-sans block hidden sm:block">
                        {d.desc}
                      </span>
                    </div>
                  </div>

                  <div className="text-right">
                    <span className="font-black text-slate-900 dark:text-white">{d.value}</span>
                    <span className="text-[10px] text-slate-500 dark:text-slate-400 ml-1">({pct}%)</span>
                  </div>
                </div>
              );
            })}
          </div>

        </div>
      )}
    </div>
  );
}
