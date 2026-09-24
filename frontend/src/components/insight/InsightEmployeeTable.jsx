import React, { useState, useMemo, useEffect } from 'react';
import { 
  User, 
  Search, 
  Filter, 
  ChevronRight, 
  ChevronLeft,
  Play, 
  ShieldAlert, 
  Activity,
  ArrowUpDown,
  ExternalLink,
  Users,
  Zap,
  Map
} from 'lucide-react';

export function InsightEmployeeTable({ 
  employees = [], 
  onSelectEmployee,
  onOpenActionCenter,
  onOpenMapView,
  onQuickSimulate 
}) {
  const [search, setSearch] = useState('');
  const [filterLevel, setFilterLevel] = useState('ALL');
  const [sortBy, setSortBy] = useState('riskScore'); // 'riskScore' | 'name'
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(50); // 25 | 50 | 100 | 'ALL'

  // Full dataset filtering and sorting across all employees (e.g. all 1,000)
  const filteredEmployees = useMemo(() => {
    return employees
      .filter((emp) => {
        const query = search.toLowerCase();
        const code = (emp.employee_code || '').toLowerCase();
        const name = (emp.name || '').toLowerCase();
        const dept = (emp.department || '').toLowerCase();
        const role = (emp.role || '').toLowerCase();
        const id = (emp.id || '').toLowerCase();

        const matchesSearch = 
          name.includes(query) ||
          code.includes(query) ||
          dept.includes(query) ||
          role.includes(query) ||
          id.includes(query);
        
        if (!matchesSearch) return false;

        if (filterLevel === 'ALL') return true;
        return (emp.riskLevel || '').toUpperCase() === filterLevel;
      })
      .sort((a, b) => {
        if (sortBy === 'riskScore') {
          return (b.latestRiskScore || 0) - (a.latestRiskScore || 0);
        }
        return (a.name || '').localeCompare(b.name || '');
      });
  }, [employees, search, filterLevel, sortBy]);

  // Reset to page 1 on filter, search, sort, or page size change
  useEffect(() => {
    setCurrentPage(1);
  }, [search, filterLevel, sortBy, pageSize]);

  // UI-only pagination calculations
  const totalEmployeesCount = filteredEmployees.length;
  const numericPageSize = pageSize === 'ALL' ? totalEmployeesCount || 1 : Number(pageSize);
  const totalPages = Math.max(1, Math.ceil(totalEmployeesCount / numericPageSize));

  const paginatedEmployees = useMemo(() => {
    if (pageSize === 'ALL') return filteredEmployees;
    const startIndex = (currentPage - 1) * numericPageSize;
    return filteredEmployees.slice(startIndex, startIndex + numericPageSize);
  }, [filteredEmployees, currentPage, pageSize, numericPageSize]);

  const startRecordIndex = totalEmployeesCount === 0 ? 0 : (currentPage - 1) * numericPageSize + 1;
  const endRecordIndex = pageSize === 'ALL' ? totalEmployeesCount : Math.min(currentPage * numericPageSize, totalEmployeesCount);

  const getRiskBadgeStyles = (level, score) => {
    const l = (level || '').toUpperCase();
    if (l === 'CRITICAL' || score >= 85) {
      return {
        badge: 'bg-rose-50 dark:bg-rose-950/90 text-rose-700 dark:text-rose-300 border-rose-200 dark:border-rose-700 shadow-xs dark:shadow-rose-950/50',
        bar: 'bg-rose-500',
        text: 'text-rose-600 dark:text-rose-400 font-bold'
      };
    }
    if (l === 'HIGH' || score >= 70) {
      return {
        badge: 'bg-orange-50 dark:bg-orange-950/90 text-orange-700 dark:text-orange-300 border-orange-200 dark:border-orange-700',
        bar: 'bg-orange-500',
        text: 'text-orange-600 dark:text-orange-400 font-bold'
      };
    }
    if (l === 'MODERATE' || score >= 40) {
      return {
        badge: 'bg-amber-50 dark:bg-amber-950/80 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-700',
        bar: 'bg-amber-500',
        text: 'text-amber-600 dark:text-amber-400 font-bold'
      };
    }
    return {
      badge: 'bg-emerald-50 dark:bg-emerald-950/80 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-700',
      bar: 'bg-emerald-500',
      text: 'text-emerald-600 dark:text-emerald-400 font-bold'
    };
  };

  return (
    <div className="p-5 rounded-2xl bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 shadow-xs dark:shadow-lg dark:shadow-black/20 space-y-4">
      {/* Table Header & Search Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 dark:border-slate-800/80 pb-3">
        <div>
          <h3 className="text-xs font-bold uppercase font-mono tracking-wider text-slate-800 dark:text-slate-200 flex items-center gap-2">
            <Users size={14} className="text-cyan-600 dark:text-cyan-400" />
            <span>Employee Risk Monitoring Matrix ({totalEmployeesCount})</span>
          </h3>
          <p className="text-[11px] text-slate-500 dark:text-slate-400 font-sans">
            Joined from Supabase employees & latest risk_events records
          </p>
        </div>

        {/* Filter Controls */}
        <div className="flex items-center gap-2.5 flex-wrap">
          {/* Search box */}
          <div className="relative">
            <Search size={13} className="absolute left-2.5 top-2.5 text-slate-400 dark:text-slate-500" />
            <input
              type="text"
              placeholder="Search code, name, dept..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-8 pr-3 py-1.5 text-xs bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl text-slate-900 dark:text-white font-mono placeholder:text-slate-400 dark:placeholder:text-slate-600 focus:outline-hidden focus:border-rose-500 transition-colors"
            />
          </div>

          {/* Level Filter Pills */}
          <div className="flex items-center bg-slate-100 dark:bg-slate-950 p-1 rounded-xl border border-slate-200 dark:border-slate-800 text-[10px] font-mono">
            {['ALL', 'CRITICAL', 'HIGH', 'MODERATE', 'LOW'].map((lvl) => (
              <button
                key={lvl}
                onClick={() => setFilterLevel(lvl)}
                className={`px-2 py-1 rounded-lg transition-all cursor-pointer ${
                  filterLevel === lvl
                    ? 'bg-white dark:bg-rose-950/90 text-rose-700 dark:text-rose-300 border border-slate-200 dark:border-rose-800 font-bold shadow-xs'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                }`}
              >
                {lvl}
              </button>
            ))}
          </div>

          {/* Sort toggle */}
          <button
            onClick={() => setSortBy(prev => prev === 'riskScore' ? 'name' : 'riskScore')}
            className="p-1.5 rounded-xl bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white text-xs font-mono cursor-pointer flex items-center gap-1 shadow-xs"
            title="Toggle sort order"
          >
            <ArrowUpDown size={12} />
            <span className="text-[10px] font-semibold">{sortBy === 'riskScore' ? 'By Risk' : 'By Name'}</span>
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs font-mono">
          <thead className="text-[10px] uppercase text-slate-500 dark:text-slate-400 border-b border-slate-100 dark:border-slate-800">
            <tr>
              <th className="pb-3 font-bold">Employee Code</th>
              <th className="pb-3 font-bold">Employee Name</th>
              <th className="pb-3 font-bold">Department & Role</th>
              <th className="pb-3 font-bold">Latest Risk Score</th>
              <th className="pb-3 font-bold">Risk Level</th>
              <th className="pb-3 font-bold">Latest Activity</th>
              <th className="pb-3 font-bold">Status</th>
              <th className="pb-3 text-right font-bold">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60">
            {paginatedEmployees.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-8 text-center text-slate-500 font-mono text-xs">
                  {employees.length === 0 ? 'No employees available' : 'No matching employees found'}
                </td>
              </tr>
            ) : (
              paginatedEmployees.map((emp) => {
                const styles = getRiskBadgeStyles(emp.riskLevel, emp.latestRiskScore);
                return (
                  <tr
                    key={emp.id}
                    onClick={() => onSelectEmployee && onSelectEmployee(emp)}
                    className="hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors cursor-pointer group"
                  >
                    {/* Employee Code */}
                    <td className="py-3.5 font-bold">
                      <span className="px-2 py-1 rounded bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-cyan-700 dark:text-cyan-300">
                        {emp.employee_code || emp.id.substring(0, 8)}
                      </span>
                    </td>

                    {/* Employee Name */}
                    <td className="py-3.5">
                      <div className="font-sans">
                        <div className="font-bold text-slate-900 dark:text-slate-200 group-hover:text-cyan-600 dark:group-hover:text-cyan-300 transition-colors">
                          {emp.name}
                        </div>
                        <div className="text-[10px] text-slate-500 font-mono">
                          {emp.email}
                        </div>
                      </div>
                    </td>

                    {/* Department & Role */}
                    <td className="py-3.5 font-sans">
                      <div className="text-slate-800 dark:text-slate-300 font-medium">{emp.role}</div>
                      <div className="text-[11px] text-slate-500">{emp.department}</div>
                    </td>

                    {/* Latest Risk Score Progress Bar */}
                    <td className="py-3.5 min-w-[130px]">
                      <div className="space-y-1">
                        <div className="flex justify-between items-center text-xs">
                          <span className={styles.text}>{emp.latestRiskScore || 0}</span>
                          <span className="text-[10px] text-slate-400 dark:text-slate-500">/ 100</span>
                        </div>
                        <div className="w-full h-1.5 rounded-full bg-slate-100 dark:bg-slate-950 overflow-hidden">
                          <div
                            className={`h-full rounded-full transition-all duration-500 ${styles.bar}`}
                            style={{ width: `${Math.min(100, Math.max(3, emp.latestRiskScore || 0))}%` }}
                          />
                        </div>
                      </div>
                    </td>

                    {/* Calculated Risk Level Badge */}
                    <td className="py-3.5">
                      <span className={`px-2.5 py-0.5 rounded text-[10px] uppercase font-bold border ${styles.badge}`}>
                        {emp.riskLevel}
                      </span>
                    </td>

                    {/* Latest Activity */}
                    <td className="py-3.5 font-sans max-w-[200px]">
                      <div className="text-[11px] text-slate-700 dark:text-slate-300 truncate" title={emp.latestActivity}>
                        {emp.latestActivity}
                      </div>
                      <div className="text-[10px] text-slate-400 dark:text-slate-500 font-mono">
                        {emp.lastActivityTime}
                      </div>
                    </td>

                    {/* Status */}
                    <td className="py-3.5">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${
                        emp.status === 'CLEARED'
                          ? 'bg-cyan-50 dark:bg-cyan-950/60 text-cyan-700 dark:text-cyan-300 border-cyan-200 dark:border-cyan-800'
                          : emp.status === 'ACTIVE' 
                          ? 'bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-800' 
                          : 'bg-amber-50 dark:bg-amber-950/60 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-800'
                      }`}>
                        {emp.status}
                      </span>
                    </td>

                    {/* Action */}
                    <td className="py-3.5 text-right">
                      <div className="flex items-center justify-end gap-1.5" onClick={(e) => e.stopPropagation()}>
                        {/* Map View button */}
                        <button
                          onClick={() => onOpenMapView && onOpenMapView(emp)}
                          className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 hover:border-cyan-700 text-slate-400 hover:text-cyan-300 text-[11px] font-bold flex items-center gap-1 transition-all cursor-pointer"
                          title="Map View"
                        >
                          <Map size={12} />
                        </button>
                        {/* Action Center button */}
                        <button
                          onClick={() => onOpenActionCenter && onOpenActionCenter(emp)}
                          className="px-3 py-1.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-[11px] font-bold flex items-center gap-1.5 transition-all cursor-pointer shadow-sm shadow-cyan-500/20 hover:shadow-cyan-500/30"
                        >
                          <Zap size={12} />
                          <span>Action Center</span>
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* UI-Only Pagination Controls Bar */}
      {totalEmployeesCount > 0 && (
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-3 border-t border-slate-100 dark:border-slate-800/80 font-mono text-xs">
          <div className="text-slate-500 dark:text-slate-400 text-[11px]">
            Showing <span className="font-bold text-slate-900 dark:text-slate-200">{startRecordIndex}</span>–
            <span className="font-bold text-slate-900 dark:text-slate-200">{endRecordIndex}</span> of{' '}
            <span className="font-bold text-cyan-600 dark:text-cyan-400">{totalEmployeesCount}</span> monitored employees
          </div>

          <div className="flex items-center gap-3">
            {/* Rows Per Page selector */}
            <div className="flex items-center gap-1 text-[11px] text-slate-500 dark:text-slate-400">
              <span>Per page:</span>
              <div className="flex items-center bg-slate-100 dark:bg-slate-950 rounded-lg border border-slate-200 dark:border-slate-800 p-0.5">
                {[25, 50, 100, 'ALL'].map((size) => (
                  <button
                    key={size}
                    onClick={() => setPageSize(size)}
                    className={`px-2 py-0.5 rounded text-[10px] font-bold cursor-pointer transition-colors ${
                      pageSize === size
                        ? 'bg-white dark:bg-cyan-950 text-cyan-700 dark:text-cyan-300 border border-slate-200 dark:border-cyan-800 shadow-xs'
                        : 'text-slate-500 hover:text-slate-800 dark:hover:text-slate-300'
                    }`}
                  >
                    {size}
                  </button>
                ))}
              </div>
            </div>

            {/* Page navigation */}
            {pageSize !== 'ALL' && totalPages > 1 && (
              <div className="flex items-center gap-1.5">
                <button
                  onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                  disabled={currentPage <= 1}
                  className="p-1.5 rounded-lg bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white disabled:opacity-30 disabled:cursor-not-allowed cursor-pointer transition-colors"
                  title="Previous page"
                >
                  <ChevronLeft size={14} />
                </button>
                <span className="text-[11px] text-slate-500 dark:text-slate-400 px-1">
                  Page <strong className="text-slate-900 dark:text-slate-200">{currentPage}</strong> of{' '}
                  <strong className="text-slate-900 dark:text-slate-200">{totalPages}</strong>
                </span>
                <button
                  onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                  disabled={currentPage >= totalPages}
                  className="p-1.5 rounded-lg bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white disabled:opacity-30 disabled:cursor-not-allowed cursor-pointer transition-colors"
                  title="Next page"
                >
                  <ChevronRight size={14} />
                </button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
