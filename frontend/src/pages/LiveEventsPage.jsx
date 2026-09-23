import React, { useState } from 'react';
import { 
  Activity, 
  Search, 
  Filter, 
  Plus, 
  Eye, 
  Laptop, 
  User, 
  Bot, 
  Wrench, 
  Send,
  RefreshCw,
  AlertCircle
} from 'lucide-react';
import { Card } from '../components/common/Card';
import { Modal } from '../components/common/Modal';
import { LoadingSpinner } from '../components/common/LoadingSpinner';
import { ErrorBanner } from '../components/common/ErrorBanner';
import { ingestEvent } from '../services/api';

export function LiveEventsPage({ 
  events = [], 
  isLoading = false,
  error = null,
  onRefresh, 
  onSelectEvent,
  onViewInGraph
}) {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState('all');
  const [isIngestModalOpen, setIsIngestModalOpen] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState(null);
  const [ingestSuccess, setIngestSuccess] = useState(null);

  // New Event Form State
  const [formData, setFormData] = useState({
    user_id: 'U_ANALYST',
    device_id: 'D_CORP_LAPTOP',
    session_id: 'sess_manual_101',
    event_type: 'api_access',
    resource: '/api/v1/customer-records',
    agent_id: '',
    tool_name: '',
    is_new_device: false,
    privilege_escalation: false,
  });

  const eventTypes = [
    'all',
    'login',
    'api_access',
    'agent_invocation',
    'tool_invocation',
    'database_access',
    'failed_login',
    'device_change',
    'privilege_change'
  ];

  // Helper to format uppercase event types as specified
  const formatEventType = (type = '') => {
    return type.replace(/_/g, ' ').toUpperCase();
  };

  // Helper to infer or display event risk/status
  const getEventRiskStatus = (evt) => {
    const isSuspicious = 
      evt.metadata?.is_new_device ||
      evt.metadata?.privilege_escalation ||
      evt.device_id?.startsWith('unknown') ||
      evt.event_type === 'failed_login' ||
      (evt.resource && (evt.resource.includes('credential') || evt.resource.includes('shadow') || evt.resource.includes('dump')));

    if (evt.metadata?.privilege_escalation || (evt.resource && evt.resource.includes('dump'))) {
      return { label: 'CRITICAL', color: 'bg-red-950/80 text-red-300 border-red-700' };
    }
    if (isSuspicious) {
      return { label: 'HIGH RISK', color: 'bg-orange-950/80 text-orange-300 border-orange-700' };
    }
    if (evt.agent_id || evt.tool_name) {
      return { label: 'MONITORED', color: 'bg-purple-950/60 text-purple-300 border-purple-800' };
    }
    return { label: 'NORMAL', color: 'bg-emerald-950/60 text-emerald-300 border-emerald-800' };
  };

  // Filtering
  const filteredEvents = events.filter((e) => {
    const matchesType = filterType === 'all' || e.event_type?.toLowerCase() === filterType.toLowerCase();
    const searchLower = searchTerm.toLowerCase();
    const matchesSearch = 
      !searchTerm ||
      e.id?.toLowerCase().includes(searchLower) ||
      e.user_id?.toLowerCase().includes(searchLower) ||
      e.device_id?.toLowerCase().includes(searchLower) ||
      e.resource?.toLowerCase().includes(searchLower) ||
      e.agent_id?.toLowerCase().includes(searchLower) ||
      e.tool_name?.toLowerCase().includes(searchLower) ||
      e.event_type?.toLowerCase().includes(searchLower);
    return matchesType && matchesSearch;
  });

  const handleIngestSubmit = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);
    setSubmitError(null);
    try {
      const payload = {
        user_id: formData.user_id || null,
        device_id: formData.device_id || null,
        session_id: formData.session_id || null,
        event_type: formData.event_type,
        resource: formData.resource || null,
        agent_id: formData.agent_id || null,
        tool_name: formData.tool_name || null,
        metadata: {
          is_new_device: formData.is_new_device,
          privilege_escalation: formData.privilege_escalation,
        }
      };
      const res = await ingestEvent(payload);
      setIsIngestModalOpen(false);
      setIngestSuccess({
        user_id: formData.user_id || 'Unknown',
        event_id: res?.event?.id || 'EVT-NEW',
        device_id: formData.device_id || 'Unknown Device'
      });
      if (onRefresh) onRefresh();
    } catch (err) {
      setSubmitError(err.message || 'Failed to ingest event');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header & Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            <Activity className="text-cyan-400" size={22} />
            Live Security Events Table
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Real-time feed showing timestamp, user, device, event type, resource, agent, tool, and risk/status.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={() => {
              setIngestSuccess(null);
              setIsIngestModalOpen(true);
            }}
            className="flex items-center gap-1.5 px-3.5 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-xl text-xs font-semibold shadow-lg shadow-cyan-950/40 transition-all cursor-pointer"
          >
            <Plus size={14} />
            Ingest Custom Event
          </button>
        </div>
      </div>

      {/* Ingest Success Banner with One-Click Graph Link */}
      {ingestSuccess && (
        <div className="p-4 rounded-xl bg-emerald-950/80 border border-emerald-700 text-emerald-200 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs font-mono shadow-lg animate-in fade-in slide-in-from-top-2 duration-300">
          <div className="flex items-center gap-2.5">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping shrink-0" />
            <span>
              ✓ Successfully ingested event <strong>{ingestSuccess.event_id}</strong> for user <strong className="text-white underline">{ingestSuccess.user_id}</strong> on device <strong>{ingestSuccess.device_id}</strong>.
            </span>
          </div>
          {onViewInGraph && (
            <button
              onClick={() => onViewInGraph(ingestSuccess.user_id)}
              className="px-3 py-1.5 rounded-lg bg-emerald-700 hover:bg-emerald-600 text-white font-bold text-xs flex items-center gap-1.5 transition-all cursor-pointer shrink-0 shadow-xs"
            >
              <span>View in Activity Graph</span>
              <span className="text-emerald-200">→</span>
            </button>
          )}
        </div>
      )}

      {/* Error State Banner */}
      {error && (
        <ErrorBanner
          title="Failed to Retrieve Live Events"
          message={error}
          onRetry={onRefresh}
        />
      )}

      {/* Filter Toolbar */}
      <Card className="p-4 flex flex-col sm:flex-row gap-3 items-center justify-between">
        <div className="relative w-full sm:w-80">
          <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            placeholder="Search user, device, resource, tool, event..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto overflow-x-auto">
          <Filter size={14} className="text-slate-500 shrink-0" />
          <span className="text-xs text-slate-400 shrink-0">Filter Event Type:</span>
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-cyan-500/50 cursor-pointer font-mono"
          >
            {eventTypes.map((type) => (
              <option key={type} value={type}>
                {type === 'all' ? 'ALL EVENT TYPES' : formatEventType(type)}
              </option>
            ))}
          </select>
        </div>
      </Card>

      {/* Live Events Table with exact required columns:
          1. Timestamp
          2. User
          3. Device
          4. Event Type
          5. Resource
          6. Agent
          7. Tool
          8. Risk/Status
      */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-950/90 text-[11px] uppercase tracking-wider text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-3.5 px-4 font-semibold">Timestamp</th>
                <th className="py-3.5 px-4 font-semibold">User</th>
                <th className="py-3.5 px-4 font-semibold">Device</th>
                <th className="py-3.5 px-4 font-semibold">Event Type</th>
                <th className="py-3.5 px-4 font-semibold">Resource</th>
                <th className="py-3.5 px-4 font-semibold">Agent</th>
                <th className="py-3.5 px-4 font-semibold">Tool</th>
                <th className="py-3.5 px-4 font-semibold">Risk / Status</th>
                <th className="py-3.5 px-3 font-semibold text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {isLoading && events.length === 0 ? (
                <tr>
                  <td colSpan={9} className="text-center py-16">
                    <LoadingSpinner text="Fetching security events from GET /api/events..." />
                  </td>
                </tr>
              ) : filteredEvents.length === 0 ? (
                /* Empty State */
                <tr>
                  <td colSpan={9} className="text-center py-16 text-slate-400 font-medium">
                    <div className="flex flex-col items-center justify-center gap-2">
                      <Activity size={24} className="text-slate-600" />
                      <span className="text-white font-semibold">No Security Events Found</span>
                      <span className="text-slate-500 max-w-sm text-[11px]">
                        {searchTerm || filterType !== 'all' 
                          ? 'No events match your search criteria. Clear filters to see all events.'
                          : 'No security events exist in the database. Use the button above to ingest a custom event or trigger an attack simulation.'}
                      </span>
                    </div>
                  </td>
                </tr>
              ) : (
                filteredEvents.map((evt) => {
                  const riskStatus = getEventRiskStatus(evt);
                  return (
                    <tr 
                      key={evt.id} 
                      className="hover:bg-slate-800/40 transition-colors cursor-pointer group"
                      onClick={() => onSelectEvent(evt)}
                    >
                      {/* 1. Timestamp */}
                      <td className="py-3.5 px-4 font-mono text-slate-400 whitespace-nowrap">
                        {new Date(evt.timestamp).toLocaleDateString([], { month: 'short', day: 'numeric' })}{' '}
                        <span className="text-slate-300">
                          {new Date(evt.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                        </span>
                      </td>

                      {/* 2. User */}
                      <td className="py-3.5 px-4 font-medium text-white whitespace-nowrap">
                        {evt.user_id ? (
                          <div className="flex items-center gap-1.5">
                            <User size={13} className="text-slate-500 group-hover:text-cyan-400 transition-colors" />
                            <span>{evt.user_id}</span>
                          </div>
                        ) : (
                          <span className="text-slate-600">-</span>
                        )}
                      </td>

                      {/* 3. Device */}
                      <td className="py-3.5 px-4 font-mono whitespace-nowrap">
                        {evt.device_id ? (
                          <div className="flex items-center gap-1.5">
                            <Laptop size={13} className="text-slate-500" />
                            <span className={evt.device_id.startsWith('unknown') || evt.metadata?.is_new_device ? 'text-amber-400 font-semibold' : 'text-slate-400'}>
                              {evt.device_id}
                            </span>
                          </div>
                        ) : (
                          <span className="text-slate-600">-</span>
                        )}
                      </td>

                      {/* 4. Event Type */}
                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <span className="inline-block px-2.5 py-1 rounded-md text-[11px] font-mono font-semibold tracking-wider uppercase bg-slate-800/90 text-cyan-300 border border-slate-700/60">
                          {formatEventType(evt.event_type)}
                        </span>
                      </td>

                      {/* 5. Resource */}
                      <td className="py-3.5 px-4 font-mono text-slate-300 max-w-[200px] truncate">
                        {evt.resource || <span className="text-slate-600">-</span>}
                      </td>

                      {/* 6. Agent */}
                      <td className="py-3.5 px-4 whitespace-nowrap font-mono text-purple-300">
                        {evt.agent_id ? (
                          <div className="flex items-center gap-1.5">
                            <Bot size={13} className="text-purple-400" />
                            <span>{evt.agent_id}</span>
                          </div>
                        ) : (
                          <span className="text-slate-600">-</span>
                        )}
                      </td>

                      {/* 7. Tool */}
                      <td className="py-3.5 px-4 whitespace-nowrap font-mono text-slate-300">
                        {evt.tool_name ? (
                          <div className="flex items-center gap-1.5">
                            <Wrench size={12} className="text-amber-400" />
                            <span className="text-amber-300/90 font-medium">{evt.tool_name}</span>
                          </div>
                        ) : (
                          <span className="text-slate-600">-</span>
                        )}
                      </td>

                      {/* 8. Risk / Status */}
                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-semibold tracking-wider uppercase border ${riskStatus.color}`}>
                          <span className="w-1.5 h-1.5 rounded-full bg-current"></span>
                          {riskStatus.label}
                        </span>
                      </td>

                      {/* Inspect */}
                      <td className="py-3.5 px-3 text-right whitespace-nowrap">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectEvent(evt);
                          }}
                          className="p-1.5 text-slate-400 hover:text-cyan-400 hover:bg-slate-800 rounded-lg transition-colors cursor-pointer"
                          title="Inspect raw JSON"
                        >
                          <Eye size={15} />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Ingest Custom Event Modal */}
      <Modal
        isOpen={isIngestModalOpen}
        onClose={() => setIsIngestModalOpen(false)}
        title="Ingest Custom Security Event (POST /api/events)"
      >
        <form onSubmit={handleIngestSubmit} className="space-y-4 text-xs">
          {submitError && (
            <div className="p-3 rounded-lg bg-red-950/60 border border-red-800 text-red-200">
              {submitError}
            </div>
          )}

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-slate-400 mb-1 font-semibold">User ID</label>
              <input
                type="text"
                value={formData.user_id}
                onChange={(e) => setFormData({ ...formData, user_id: e.target.value })}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white font-mono focus:border-cyan-500/50"
              />
            </div>
            <div>
              <label className="block text-slate-400 mb-1 font-semibold">Device ID</label>
              <input
                type="text"
                value={formData.device_id}
                onChange={(e) => setFormData({ ...formData, device_id: e.target.value })}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white font-mono focus:border-cyan-500/50"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-slate-400 mb-1 font-semibold">Event Type</label>
              <select
                value={formData.event_type}
                onChange={(e) => setFormData({ ...formData, event_type: e.target.value })}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white font-mono focus:border-cyan-500/50 uppercase"
              >
                {eventTypes.filter(t => t !== 'all').map(t => (
                  <option key={t} value={t}>{formatEventType(t)}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-slate-400 mb-1 font-semibold">Resource / Path</label>
              <input
                type="text"
                value={formData.resource}
                onChange={(e) => setFormData({ ...formData, resource: e.target.value })}
                placeholder="/api/v1/customer-records"
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white font-mono focus:border-cyan-500/50"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-slate-400 mb-1 font-semibold">Agent ID (Optional)</label>
              <input
                type="text"
                value={formData.agent_id}
                onChange={(e) => setFormData({ ...formData, agent_id: e.target.value })}
                placeholder="agent_copilot"
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white font-mono focus:border-cyan-500/50"
              />
            </div>
            <div>
              <label className="block text-slate-400 mb-1 font-semibold">Tool Name (Optional)</label>
              <input
                type="text"
                value={formData.tool_name}
                onChange={(e) => setFormData({ ...formData, tool_name: e.target.value })}
                placeholder="raw_sql_exec"
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white font-mono focus:border-cyan-500/50"
              />
            </div>
          </div>

          <div className="flex items-center gap-6 pt-2">
            <label className="flex items-center gap-2 cursor-pointer text-slate-300">
              <input
                type="checkbox"
                checked={formData.is_new_device}
                onChange={(e) => setFormData({ ...formData, is_new_device: e.target.checked })}
                className="rounded border-slate-700 text-cyan-500"
              />
              <span>Is Unknown/New Device</span>
            </label>
            <label className="flex items-center gap-2 cursor-pointer text-slate-300">
              <input
                type="checkbox"
                checked={formData.privilege_escalation}
                onChange={(e) => setFormData({ ...formData, privilege_escalation: e.target.checked })}
                className="rounded border-slate-700 text-cyan-500"
              />
              <span>Privilege Escalation</span>
            </label>
          </div>

          <div className="flex justify-end gap-3 pt-4 border-t border-slate-800">
            <button
              type="button"
              onClick={() => setIsIngestModalOpen(false)}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg font-medium cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white font-semibold rounded-lg flex items-center gap-2 cursor-pointer disabled:opacity-50"
            >
              <Send size={13} />
              {isSubmitting ? 'Ingesting via API...' : 'Ingest Event'}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
