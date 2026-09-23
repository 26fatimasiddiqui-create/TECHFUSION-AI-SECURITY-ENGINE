import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { 
  Network, 
  User as UserIcon, 
  Laptop, 
  Globe, 
  KeyRound, 
  Clock, 
  Bot, 
  Wrench, 
  Layers, 
  Database, 
  ShieldAlert, 
  AlertTriangle, 
  Flame, 
  ArrowRight, 
  RefreshCw, 
  Filter, 
  Eye, 
  Info, 
  CheckCircle2, 
  ExternalLink,
  Search,
  Sparkles,
  ShieldCheck,
  Radio,
  ChevronRight
} from 'lucide-react';
import { Card } from '../components/common/Card';
import { LoadingSpinner } from '../components/common/LoadingSpinner';
import { ErrorBanner } from '../components/common/ErrorBanner';
import { LiveSecurityGraph } from '../components/common/LiveSecurityGraph';
import { getUsers, getUserActivityGraph } from '../services/api';

// Icon and color mapping per node type
const NODE_TYPE_CONFIG = {
  User: { icon: UserIcon, color: 'text-cyan-400', bg: 'bg-cyan-950/40', border: 'border-cyan-700/60' },
  Login: { icon: KeyRound, color: 'text-emerald-400', bg: 'bg-emerald-950/40', border: 'border-emerald-700/60' },
  Session: { icon: Clock, color: 'text-purple-400', bg: 'bg-purple-950/40', border: 'border-purple-700/60' },
  Device: { icon: Laptop, color: 'text-blue-400', bg: 'bg-blue-950/40', border: 'border-blue-700/60' },
  IP: { icon: Globe, color: 'text-teal-400', bg: 'bg-teal-950/40', border: 'border-teal-700/60' },
  API: { icon: Network, color: 'text-sky-400', bg: 'bg-sky-950/40', border: 'border-sky-700/60' },
  'AI Agent': { icon: Bot, color: 'text-fuchsia-400', bg: 'bg-fuchsia-950/40', border: 'border-fuchsia-700/60' },
  Tool: { icon: Wrench, color: 'text-amber-400', bg: 'bg-amber-950/40', border: 'border-amber-700/60' },
  Resource: { icon: Layers, color: 'text-indigo-400', bg: 'bg-indigo-950/40', border: 'border-indigo-700/60' },
  Database: { icon: Database, color: 'text-rose-400', bg: 'bg-rose-950/40', border: 'border-rose-700/60' },
};

// Risk styling mapping
const RISK_CONFIG = {
  normal: {
    label: 'Normal',
    badgeBg: 'bg-emerald-950/80 text-emerald-300 border-emerald-800',
    ring: 'ring-emerald-500/30 border-emerald-600/40',
    edgeColor: '#10b981',
  },
  unusual: {
    label: 'Unusual',
    badgeBg: 'bg-sky-950/80 text-sky-300 border-sky-700',
    ring: 'ring-sky-500/40 border-sky-500/60 shadow-md shadow-sky-950/50',
    edgeColor: '#0ea5e9',
  },
  suspicious: {
    label: 'Suspicious',
    badgeBg: 'bg-amber-950/80 text-amber-300 border-amber-700',
    ring: 'ring-amber-500/40 border-amber-500/80 shadow-lg shadow-amber-950/60',
    edgeColor: '#f59e0b',
  },
  'high-risk': {
    label: 'High-Risk',
    badgeBg: 'bg-rose-950/90 text-rose-200 border-rose-700 animate-pulse',
    ring: 'ring-rose-500/60 border-rose-500 shadow-xl shadow-rose-950/80',
    edgeColor: '#f43f5e',
  },
};

export function UserActivityGraphPage({ 
  onSelectIncident, 
  onSelectEvent,
  onRunDemo,
  setTab,
}) {
  const [usersList, setUsersList] = useState([]);
  const [selectedUserId, setSelectedUserId] = useState('');
  const [graphData, setGraphData] = useState(null);
  const [isGraphLoading, setIsGraphLoading] = useState(false);
  const [error, setError] = useState(null);

  // View mode & Filter states
  const [graphMode, setGraphMode] = useState('live_security_graph'); // 'live_security_graph' | 'entity_tiers'
  const [riskFilter, setRiskFilter] = useState('all'); // 'all' | 'flagged_only'
  const [typeFilter, setTypeFilter] = useState('all');
  const [selectedNodeId, setSelectedNodeId] = useState(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState(null);
  const [selectedTimelineStep, setSelectedTimelineStep] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');

  // 1. Fetch available users list on mount
  const fetchUsers = useCallback(async (keepSelection = false) => {
    try {
      setError(null);
      const users = await getUsers();
      setUsersList(users);

      if (users.length > 0) {
        if (!keepSelection || !selectedUserId) {
          // Default to first user or demo user
          const demoUser = users.find(u => u.user_id.includes('DEMO') || u.user_id.includes('HACKATHON'));
          setSelectedUserId(demoUser ? demoUser.user_id : users[0].user_id);
        }
      }
    } catch (err) {
      console.error('Failed to load users:', err);
      setError(err.message || 'Error loading tracked users');
    }
  }, [selectedUserId]);

  useEffect(() => {
    fetchUsers();
  }, [fetchUsers]);

  // 2. Fetch User Activity Graph whenever selectedUserId changes
  const fetchGraph = useCallback(async (userId) => {
    if (!userId) return;
    setIsGraphLoading(true);
    setError(null);
    try {
      const data = await getUserActivityGraph(userId);
      setGraphData(data);
      // Auto-select first suspicious node or user node
      if (data.nodes && data.nodes.length > 0) {
        const suspiciousNode = data.nodes.find(n => n.risk_level === 'high-risk' || n.risk_level === 'suspicious');
        setSelectedNodeId(suspiciousNode ? suspiciousNode.id : data.nodes[0].id);
        setSelectedEdgeId(null);
        setSelectedTimelineStep(null);
      }
    } catch (err) {
      console.error(`Failed to fetch activity graph for ${userId}:`, err);
      setError(err.message || `Error loading activity graph for user ${userId}`);
    } finally {
      setIsGraphLoading(false);
    }
  }, []);

  useEffect(() => {
    if (selectedUserId) {
      fetchGraph(selectedUserId);
    }
  }, [selectedUserId, fetchGraph]);

  // Derived filtered nodes and edges
  const filteredNodes = useMemo(() => {
    if (!graphData?.nodes) return [];
    return graphData.nodes.filter(node => {
      // Risk filter
      if (riskFilter === 'flagged_only' && node.risk_level === 'normal') return false;
      // Type filter
      if (typeFilter !== 'all' && node.type !== typeFilter) return false;
      // Search
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        return (
          node.label.toLowerCase().includes(q) ||
          node.id.toLowerCase().includes(q) ||
          node.type.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [graphData, riskFilter, typeFilter, searchQuery]);

  const filteredNodeIds = useMemo(() => new Set(filteredNodes.map(n => n.id)), [filteredNodes]);

  const filteredEdges = useMemo(() => {
    if (!graphData?.edges) return [];
    return graphData.edges.filter(edge => {
      if (riskFilter === 'flagged_only' && edge.risk_level === 'normal') return false;
      return filteredNodeIds.has(edge.source) && filteredNodeIds.has(edge.target);
    });
  }, [graphData, riskFilter, filteredNodeIds]);

  // Inspection item derivation
  const inspectedNode = useMemo(() => {
    if (!selectedNodeId || !graphData?.nodes) return null;
    return graphData.nodes.find(n => n.id === selectedNodeId) || null;
  }, [selectedNodeId, graphData]);

  const inspectedEdge = useMemo(() => {
    if (!selectedEdgeId || !graphData?.edges) return null;
    return graphData.edges.find(e => e.id === selectedEdgeId) || null;
  }, [selectedEdgeId, graphData]);

  // Group nodes by entity tier for visual presentation
  const tierGroups = useMemo(() => {
    const tiers = {
      user: [],
      auth_session: [],
      device_ip: [],
      agent_api: [],
      tool: [],
      storage: []
    };

    filteredNodes.forEach(node => {
      switch (node.type) {
        case 'User':
          tiers.user.push(node);
          break;
        case 'Login':
        case 'Session':
          tiers.auth_session.push(node);
          break;
        case 'Device':
        case 'IP':
          tiers.device_ip.push(node);
          break;
        case 'API':
        case 'AI Agent':
          tiers.agent_api.push(node);
          break;
        case 'Tool':
          tiers.tool.push(node);
          break;
        case 'Resource':
        case 'Database':
          tiers.storage.push(node);
          break;
        default:
          tiers.storage.push(node);
      }
    });

    return tiers;
  }, [filteredNodes]);

  const summary = graphData?.summary;
  const overallRisk = summary?.risk_level || 'normal';
  const riskMeta = RISK_CONFIG[overallRisk] || RISK_CONFIG.normal;

  return (
    <div className="space-y-6">
      {/* Top Header & Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2.5">
            <div className="p-1.5 bg-gradient-to-tr from-cyan-600 to-blue-500 rounded-lg text-white shadow-md shadow-cyan-500/20">
              <Network size={20} />
            </div>
            User Activity Graph
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Connects individual user activities across auth, devices, network IPs, sessions, APIs, AI agents, tools, and databases with chronological behavioral context.
          </p>
        </div>

        {/* User Selector Dropdown & Refresh */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 bg-slate-900/90 border border-slate-800 rounded-xl px-3 py-1.5 shadow-sm">
            <UserIcon size={14} className="text-cyan-400" />
            <span className="text-[11px] text-slate-400 uppercase font-semibold">User:</span>
            <select
              value={selectedUserId}
              onChange={(e) => setSelectedUserId(e.target.value)}
              className="bg-transparent text-xs font-mono font-bold text-cyan-300 focus:outline-none cursor-pointer"
            >
              {usersList.length === 0 ? (
                <option value="">No users found</option>
              ) : (
                usersList.map((u) => (
                  <option key={u.user_id} value={u.user_id} className="bg-slate-950 text-slate-200">
                    {u.user_id} ({u.event_count} events)
                  </option>
                ))
              )}
            </select>
          </div>

          <button
            onClick={() => {
              fetchUsers(true);
              fetchGraph(selectedUserId);
            }}
            disabled={isGraphLoading}
            className="p-2 bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 hover:text-white rounded-xl transition-all cursor-pointer"
            title="Refresh User Graph"
          >
            <RefreshCw size={15} className={isGraphLoading ? 'animate-spin text-cyan-400' : ''} />
          </button>
        </div>
      </div>

      {/* Global Error Banner */}
      {error && (
        <ErrorBanner
          title="Activity Graph Error"
          message={error}
          onRetry={() => fetchGraph(selectedUserId)}
        />
      )}

      {/* Summary KPI Strip */}
      {summary && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          <Card className="p-3.5 bg-slate-900/80">
            <span className="text-[10px] uppercase font-semibold text-slate-400 tracking-wider block">Target User</span>
            <span className="text-xs font-mono font-bold text-white truncate block mt-0.5" title={summary.user_id}>
              {summary.user_id}
            </span>
          </Card>

          <Card className="p-3.5 bg-slate-900/80">
            <span className="text-[10px] uppercase font-semibold text-slate-400 tracking-wider block">User Risk Level</span>
            <div className="flex items-center gap-1.5 mt-0.5">
              <span className={`px-2 py-0.5 text-[11px] font-bold rounded-md uppercase border ${riskMeta.badgeBg}`}>
                {riskMeta.label}
              </span>
              <span className="text-xs font-mono text-slate-400">({summary.risk_score}/100)</span>
            </div>
          </Card>

          <Card className="p-3.5 bg-slate-900/80">
            <span className="text-[10px] uppercase font-semibold text-slate-400 tracking-wider block">Total Events</span>
            <span className="text-lg font-mono font-bold text-cyan-300 mt-0.5 block">
              {summary.total_events}
            </span>
          </Card>

          <Card className="p-3.5 bg-slate-900/80">
            <span className="text-[10px] uppercase font-semibold text-slate-400 tracking-wider block">Connected Nodes</span>
            <span className="text-lg font-mono font-bold text-purple-300 mt-0.5 block">
              {summary.node_count}
            </span>
          </Card>

          <Card className="p-3.5 bg-slate-900/80">
            <span className="text-[10px] uppercase font-semibold text-slate-400 tracking-wider block">Relationship Edges</span>
            <span className="text-lg font-mono font-bold text-teal-300 mt-0.5 block">
              {summary.edge_count}
            </span>
          </Card>

          <Card className="p-3.5 bg-slate-900/80">
            <span className="text-[10px] uppercase font-semibold text-slate-400 tracking-wider block">Linked Incidents</span>
            <div className="mt-0.5 flex items-center gap-1.5">
              {summary.incident_ids && summary.incident_ids.length > 0 ? (
                summary.incident_ids.map(incId => (
                  <button
                    key={incId}
                    onClick={() => onSelectIncident && onSelectIncident({ id: incId })}
                    className="text-xs font-mono font-bold text-rose-400 bg-rose-950/60 border border-rose-800/80 px-1.5 py-0.5 rounded hover:bg-rose-900/80 transition-all cursor-pointer flex items-center gap-1"
                  >
                    <Flame size={11} />
                    {incId}
                  </button>
                ))
              ) : (
                <span className="text-xs text-slate-500 font-mono">None</span>
              )}
            </div>
          </Card>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="bg-slate-950/90 border border-slate-800 rounded-xl p-3 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-slate-400 flex items-center gap-1 font-semibold uppercase text-[10px]">
            <Filter size={12} className="text-cyan-400" /> Filters:
          </span>

          {/* Risk Filter */}
          <div className="flex rounded-lg border border-slate-800 bg-slate-900 p-0.5">
            <button
              onClick={() => setRiskFilter('all')}
              className={`px-2.5 py-1 rounded text-[11px] font-medium transition-all cursor-pointer ${
                riskFilter === 'all' ? 'bg-cyan-950 text-cyan-300 font-bold border border-cyan-700/50' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              All Signals
            </button>
            <button
              onClick={() => setRiskFilter('flagged_only')}
              className={`px-2.5 py-1 rounded text-[11px] font-medium transition-all cursor-pointer ${
                riskFilter === 'flagged_only' ? 'bg-amber-950 text-amber-300 font-bold border border-amber-700/50' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Flagged Only
            </button>
          </div>

          {/* Node Type Filter */}
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="bg-slate-900 text-slate-300 border border-slate-800 rounded-lg px-2.5 py-1 text-[11px] focus:outline-none"
          >
            <option value="all">All Entity Types</option>
            {Object.keys(NODE_TYPE_CONFIG).map(t => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
        </div>

        {/* Search Input & View Mode Switcher */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex rounded-xl border border-slate-800 bg-slate-900/90 p-1">
            <button
              onClick={() => setGraphMode('live_security_graph')}
              className={`px-3 py-1 rounded-lg text-xs font-semibold transition-all cursor-pointer flex items-center gap-1.5 ${
                graphMode === 'live_security_graph'
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-700/60 shadow-md font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Sparkles size={13} className="text-cyan-400" />
              Live Security Graph
            </button>
            <button
              onClick={() => setGraphMode('entity_tiers')}
              className={`px-3 py-1 rounded-lg text-xs font-semibold transition-all cursor-pointer flex items-center gap-1.5 ${
                graphMode === 'entity_tiers'
                  ? 'bg-purple-950 text-purple-300 border border-purple-700/60 shadow-md font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Layers size={13} className="text-purple-400" />
              Entity Tiers Canvas
            </button>
          </div>

          <div className="relative min-w-[180px]">
            <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="Search entities..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-8 pr-3 py-1 text-slate-200 text-xs placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
            />
          </div>
        </div>
      </div>

      {/* Main Graph Content Area: Split 8 cols Graph & Timeline, 4 cols Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column (8 cols): Interactive Graph Canvas & Chronology */}
        <div className="lg:col-span-8 space-y-6">
          
          {/* VIEW MODE 1: LIVE SECURITY GRAPH (Exact Visual Layout from User Architecture) */}
          {graphMode === 'live_security_graph' && (
            <LiveSecurityGraph
              onInvestigate={() => {
                if (graphData?.incidents && graphData.incidents.length > 0 && onSelectIncident) {
                  onSelectIncident({ id: graphData.incidents[0].id });
                } else if (onSelectIncident) {
                  onSelectIncident({ id: 'INC-DEMO' });
                }
              }}
              onSelectNode={(node) => {
                if (graphData?.nodes) {
                  const match = graphData.nodes.find(n => 
                    n.type.toLowerCase() === node.type || 
                    n.label.toLowerCase().includes(node.name.toLowerCase())
                  );
                  if (match) setSelectedNodeId(match.id);
                }
              }}
            />
          )}

          {/* VIEW MODE 2: MULTI-TIER ENTITY CANVAS */}
          {graphMode === 'entity_tiers' && (
            <Card className="p-5 bg-slate-900/90 border border-slate-800 rounded-2xl shadow-xl">
              <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <Network size={16} className="text-cyan-400" />
                  <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200">
                    Connected Entity Activity Graph
                  </h3>
                </div>
                <span className="text-[11px] font-mono text-slate-500">
                  Interactive: Click any entity or relationship
                </span>
              </div>

            {isGraphLoading ? (
              <div className="py-24">
                <LoadingSpinner text={`Synthesizing Activity Graph for ${selectedUserId}...`} />
              </div>
            ) : !graphData || filteredNodes.length === 0 ? (
              <div className="py-16 text-center text-slate-400 space-y-3">
                <ShieldAlert size={32} className="mx-auto text-slate-600" />
                <div className="text-sm font-semibold text-white">No Activity Found for User</div>
                <p className="text-xs text-slate-500 max-w-sm mx-auto">
                  No security events or telemetry recorded for {selectedUserId}. You can run the attack scenario simulation to populate data.
                </p>
                {onRunDemo && (
                  <button
                    onClick={onRunDemo}
                    className="mt-2 px-3 py-1.5 bg-cyan-950 border border-cyan-700 text-cyan-300 rounded-xl text-xs font-semibold hover:bg-cyan-900 transition-all cursor-pointer inline-flex items-center gap-1.5"
                  >
                    <Sparkles size={13} /> Run Attack Demo Sequence
                  </button>
                )}
              </div>
            ) : (
              <div className="space-y-6">
                {/* Visual Entity Tiers Canvas */}
                <div className="bg-slate-950/80 border border-slate-800/90 rounded-xl p-4 overflow-x-auto min-h-[380px]">
                  <div className="flex flex-col md:flex-row items-start justify-between gap-6 min-w-[720px]">
                    
                    {/* Tier 0: USER */}
                    <div className="flex-1 space-y-2">
                      <div className="text-[10px] font-mono uppercase font-bold text-cyan-400 tracking-wider text-center border-b border-slate-800/80 pb-1">
                        1. User Entity
                      </div>
                      <div className="space-y-2">
                        {tierGroups.user.map(node => (
                          <NodeCard
                            key={node.id}
                            node={node}
                            isSelected={selectedNodeId === node.id}
                            onClick={() => {
                              setSelectedNodeId(node.id);
                              setSelectedEdgeId(null);
                            }}
                          />
                        ))}
                      </div>
                    </div>

                    <div className="self-center hidden md:block text-slate-700">
                      <ArrowRight size={16} />
                    </div>

                    {/* Tier 1: AUTH & SESSION */}
                    <div className="flex-1 space-y-2">
                      <div className="text-[10px] font-mono uppercase font-bold text-emerald-400 tracking-wider text-center border-b border-slate-800/80 pb-1">
                        2. Auth & Session
                      </div>
                      <div className="space-y-2 max-h-[340px] overflow-y-auto pr-1">
                        {tierGroups.auth_session.length === 0 ? (
                          <div className="text-[11px] text-slate-600 italic text-center py-4">No sessions</div>
                        ) : (
                          tierGroups.auth_session.map(node => (
                            <NodeCard
                              key={node.id}
                              node={node}
                              isSelected={selectedNodeId === node.id}
                              onClick={() => {
                                setSelectedNodeId(node.id);
                                setSelectedEdgeId(null);
                              }}
                            />
                          ))
                        )}
                      </div>
                    </div>

                    <div className="self-center hidden md:block text-slate-700">
                      <ArrowRight size={16} />
                    </div>

                    {/* Tier 2: DEVICE & IP */}
                    <div className="flex-1 space-y-2">
                      <div className="text-[10px] font-mono uppercase font-bold text-blue-400 tracking-wider text-center border-b border-slate-800/80 pb-1">
                        3. Device & IP
                      </div>
                      <div className="space-y-2 max-h-[340px] overflow-y-auto pr-1">
                        {tierGroups.device_ip.length === 0 ? (
                          <div className="text-[11px] text-slate-600 italic text-center py-4">No devices</div>
                        ) : (
                          tierGroups.device_ip.map(node => (
                            <NodeCard
                              key={node.id}
                              node={node}
                              isSelected={selectedNodeId === node.id}
                              onClick={() => {
                                setSelectedNodeId(node.id);
                                setSelectedEdgeId(null);
                              }}
                            />
                          ))
                        )}
                      </div>
                    </div>

                    <div className="self-center hidden md:block text-slate-700">
                      <ArrowRight size={16} />
                    </div>

                    {/* Tier 3: WORKFLOWS (API & AI AGENT) */}
                    <div className="flex-1 space-y-2">
                      <div className="text-[10px] font-mono uppercase font-bold text-fuchsia-400 tracking-wider text-center border-b border-slate-800/80 pb-1">
                        4. API & AI Agent
                      </div>
                      <div className="space-y-2 max-h-[340px] overflow-y-auto pr-1">
                        {tierGroups.agent_api.length === 0 ? (
                          <div className="text-[11px] text-slate-600 italic text-center py-4">No APIs/Agents</div>
                        ) : (
                          tierGroups.agent_api.map(node => (
                            <NodeCard
                              key={node.id}
                              node={node}
                              isSelected={selectedNodeId === node.id}
                              onClick={() => {
                                setSelectedNodeId(node.id);
                                setSelectedEdgeId(null);
                              }}
                            />
                          ))
                        )}
                      </div>
                    </div>

                    <div className="self-center hidden md:block text-slate-700">
                      <ArrowRight size={16} />
                    </div>

                    {/* Tier 4: TOOLS & STORAGE */}
                    <div className="flex-1 space-y-2">
                      <div className="text-[10px] font-mono uppercase font-bold text-rose-400 tracking-wider text-center border-b border-slate-800/80 pb-1">
                        5. Tool & Database
                      </div>
                      <div className="space-y-2 max-h-[340px] overflow-y-auto pr-1">
                        {[...tierGroups.tool, ...tierGroups.storage].length === 0 ? (
                          <div className="text-[11px] text-slate-600 italic text-center py-4">No tools/data</div>
                        ) : (
                          [...tierGroups.tool, ...tierGroups.storage].map(node => (
                            <NodeCard
                              key={node.id}
                              node={node}
                              isSelected={selectedNodeId === node.id}
                              onClick={() => {
                                setSelectedNodeId(node.id);
                                setSelectedEdgeId(null);
                              }}
                            />
                          ))
                        )}
                      </div>
                    </div>

                  </div>
                </div>

                {/* Relationships Strip */}
                <div className="space-y-2">
                  <div className="text-[11px] font-semibold uppercase text-slate-400 tracking-wider flex items-center justify-between">
                    <span>Connected Relationships ({filteredEdges.length})</span>
                    <span className="text-[10px] text-slate-500">Click edge to inspect</span>
                  </div>
                  <div className="flex flex-wrap gap-2 max-h-24 overflow-y-auto">
                    {filteredEdges.map((edge) => {
                      const isSelected = selectedEdgeId === edge.id;
                      const edgeRisk = RISK_CONFIG[edge.risk_level] || RISK_CONFIG.normal;
                      return (
                        <button
                          key={edge.id}
                          onClick={() => {
                            setSelectedEdgeId(edge.id);
                            setSelectedNodeId(null);
                          }}
                          className={`px-2.5 py-1 rounded-lg text-[11px] font-mono transition-all border cursor-pointer flex items-center gap-1.5 ${
                            isSelected
                              ? 'bg-cyan-950 border-cyan-500 text-cyan-200 shadow-md ring-1 ring-cyan-500'
                              : 'bg-slate-950 border-slate-800 text-slate-300 hover:border-slate-700'
                          }`}
                        >
                          <span className="text-[9px] px-1 py-0.2 rounded bg-slate-900 text-slate-400">
                            #{edge.sequence_order}
                          </span>
                          <span className="font-bold text-white">{edge.relationship}</span>
                          {edge.risk_level !== 'normal' && (
                            <span className={`px-1 py-0.2 text-[9px] rounded uppercase font-bold border ${edgeRisk.badgeBg}`}>
                              {edge.risk_level}
                            </span>
                          )}
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* Interactive Legend */}
                <div className="pt-3 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-3 text-[11px] text-slate-400">
                  <div className="flex flex-wrap items-center gap-3">
                    <span className="font-semibold text-slate-300 uppercase text-[10px]">Risk Indicators:</span>
                    <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-emerald-500"></span> Normal</span>
                    <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-sky-500"></span> Unusual Signal (New IP/Device)</span>
                    <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-amber-500"></span> Suspicious Anomaly</span>
                    <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse"></span> High-Risk Threat</span>
                  </div>
                  <div className="text-[10px] text-slate-500 font-mono">
                    Baseline: Cognee Knowledge Graph Active
                  </div>
                </div>
              </div>
            )}
          </Card>
        )}

          {/* 2. CHRONOLOGICAL TIMELINE (Requirement 3: First -> Next -> After) */}
          <Card className="p-5 bg-slate-900/90 border border-slate-800 rounded-2xl shadow-xl">
            <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Clock size={16} className="text-amber-400" />
                <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200">
                  Event Chronology Sequence
                </h3>
              </div>
              <span className="text-[11px] font-mono text-slate-400">
                What happened first → What happened next → What happened after that
              </span>
            </div>

            {graphData?.timeline?.length === 0 ? (
              <div className="text-center py-8 text-xs text-slate-500">No chronological timeline available</div>
            ) : (
              <div className="space-y-3">
                {graphData?.timeline?.map((step) => {
                  const stepRisk = RISK_CONFIG[step.risk_level] || RISK_CONFIG.normal;
                  const isSelected = selectedTimelineStep?.step === step.step;

                  return (
                    <div
                      key={step.step}
                      onClick={() => {
                        setSelectedTimelineStep(step);
                        if (step.target_node) setSelectedNodeId(step.target_node);
                      }}
                      className={`p-3.5 rounded-xl border transition-all cursor-pointer flex flex-col md:flex-row items-start md:items-center justify-between gap-3 ${
                        isSelected
                          ? 'bg-slate-950 border-cyan-500/80 shadow-md ring-1 ring-cyan-500/50'
                          : 'bg-slate-950/70 border-slate-800/80 hover:border-slate-700 hover:bg-slate-950'
                      }`}
                    >
                      <div className="flex items-start gap-3">
                        <div className="flex flex-col items-center">
                          <span className="w-6 h-6 rounded-full bg-slate-900 border border-slate-700 text-cyan-400 font-mono text-xs font-bold flex items-center justify-center">
                            {step.step}
                          </span>
                        </div>

                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-xs font-bold text-white uppercase">
                              {step.event_type}
                            </span>
                            <span className="text-[11px] font-mono text-slate-400">
                              ({step.relationship})
                            </span>
                            <span className={`px-2 py-0.2 text-[9px] rounded uppercase font-bold border ${stepRisk.badgeBg}`}>
                              {step.risk_level}
                            </span>
                          </div>

                          <p className="text-xs text-slate-300 mt-1">
                            {step.description}
                          </p>

                          {step.reasons && step.reasons.length > 0 && (
                            <div className="mt-1.5 flex flex-wrap gap-1">
                              {step.reasons.map((r, i) => (
                                <span key={i} className="text-[10px] bg-slate-900 text-amber-300 border border-amber-800/60 px-1.5 py-0.5 rounded">
                                  Reason: {r}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                      </div>

                      <div className="text-right shrink-0 self-end md:self-center">
                        <span className="text-[11px] font-mono text-slate-400 block">
                          {new Date(step.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                        </span>
                        {step.incident_id && (
                          <span className="text-[10px] font-mono text-rose-400 bg-rose-950/40 border border-rose-900/60 px-1.5 py-0.5 rounded mt-1 inline-block">
                            Incident: {step.incident_id}
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </Card>
        </div>

        {/* Right Column (4 cols): Context & Entity Detail Inspector */}
        <div className="lg:col-span-4 space-y-6">
          <Card className="p-5 bg-slate-900/90 border border-slate-800 rounded-2xl shadow-xl sticky top-6">
            <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-800">
              <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
                <Info size={15} className="text-cyan-400" />
                Inspector & Risk Context
              </h3>
              <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-slate-950 text-slate-400 border border-slate-800">
                {inspectedNode ? 'Node Details' : inspectedEdge ? 'Edge Details' : 'Select Item'}
              </span>
            </div>

            {inspectedNode ? (
              <div className="space-y-4 text-xs">
                {/* Header info */}
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-[10px] uppercase font-bold text-slate-400 font-mono">
                      {inspectedNode.type}
                    </span>
                    <span className={`px-2 py-0.2 text-[9px] uppercase font-bold rounded border ${
                      RISK_CONFIG[inspectedNode.risk_level]?.badgeBg || RISK_CONFIG.normal.badgeBg
                    }`}>
                      {inspectedNode.risk_level}
                    </span>
                  </div>
                  <h4 className="text-base font-bold text-white font-mono break-all">
                    {inspectedNode.label}
                  </h4>
                  <div className="text-[10px] font-mono text-slate-500 break-all mt-0.5">
                    ID: {inspectedNode.id}
                  </div>
                </div>

                {/* Risk Context & Reasons (Requirement 6) */}
                <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
                  <div className="text-[10px] uppercase font-bold text-cyan-400 tracking-wider flex items-center gap-1.5">
                    <AlertTriangle size={12} />
                    Risk Context & Signal Explanations
                  </div>
                  {inspectedNode.reasons && inspectedNode.reasons.length > 0 ? (
                    <ul className="space-y-1 mt-1">
                      {inspectedNode.reasons.map((r, i) => (
                        <li key={i} className="text-slate-200 flex items-start gap-1.5">
                          <span className="text-cyan-400 font-bold">•</span>
                          <span>{r}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <div className="text-emerald-400 text-[11px] flex items-center gap-1">
                      <CheckCircle2 size={12} />
                      Conforms to historical baseline entity profile.
                    </div>
                  )}

                  {inspectedNode.signals && inspectedNode.signals.length > 0 && (
                    <div className="pt-2 border-t border-slate-800/80 flex flex-wrap gap-1">
                      {inspectedNode.signals.map((sig, i) => (
                        <span key={i} className="text-[9px] font-mono uppercase px-1.5 py-0.5 rounded bg-amber-950/60 border border-amber-800 text-amber-300">
                          {sig}
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                {/* Timestamps & Events */}
                <div className="grid grid-cols-2 gap-2 p-3 bg-slate-950 rounded-xl border border-slate-800 text-[11px] font-mono">
                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase">First Seen</span>
                    <span className="text-slate-300">{new Date(inspectedNode.first_seen).toLocaleTimeString()}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase">Last Seen</span>
                    <span className="text-slate-300">{new Date(inspectedNode.last_seen).toLocaleTimeString()}</span>
                  </div>
                  <div className="col-span-2 pt-2 border-t border-slate-800">
                    <span className="text-slate-500 block text-[10px] uppercase">Event Types</span>
                    <span className="text-cyan-300">{inspectedNode.event_types?.join(', ') || 'N/A'}</span>
                  </div>
                </div>

                {/* Attack-Chain & Incident Linkage (Requirement 7) */}
                {graphData?.incidents && graphData.incidents.length > 0 && (
                  <div className="p-3 bg-rose-950/30 border border-rose-800/50 rounded-xl space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] uppercase font-bold text-rose-300 flex items-center gap-1">
                        <Flame size={12} /> Correlated Incident Link
                      </span>
                      <span className="text-[10px] font-mono font-bold text-rose-200">
                        Score: {graphData.incidents[0].risk_score}/100
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-300">
                      Connected to incident <strong className="text-white font-mono">{graphData.incidents[0].id}</strong>.
                    </p>
                    <button
                      onClick={() => onSelectIncident && onSelectIncident({ id: graphData.incidents[0].id })}
                      className="w-full mt-1 px-3 py-1.5 bg-rose-900/60 hover:bg-rose-900 border border-rose-700 text-rose-100 rounded-lg text-xs font-semibold transition-all cursor-pointer flex items-center justify-center gap-1.5"
                    >
                      <span>Open Incident Attack Chain</span>
                      <ExternalLink size={12} />
                    </button>
                  </div>
                )}

                {/* Raw Events Inspector Trigger */}
                {inspectedNode.event_ids && inspectedNode.event_ids.length > 0 && (
                  <button
                    onClick={() => onSelectEvent && onSelectEvent({ id: inspectedNode.event_ids[0] })}
                    className="w-full py-2 bg-slate-950 hover:bg-slate-800 border border-slate-800 text-slate-300 rounded-xl text-xs font-mono font-semibold transition-all cursor-pointer flex items-center justify-center gap-1.5"
                  >
                    <Eye size={13} className="text-cyan-400" />
                    <span>Inspect Raw Security Event</span>
                  </button>
                )}
              </div>
            ) : inspectedEdge ? (
              <div className="space-y-4 text-xs">
                {/* Edge Inspector info */}
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-[10px] uppercase font-bold text-cyan-400 font-mono">
                      Relationship
                    </span>
                    <span className={`px-2 py-0.2 text-[9px] uppercase font-bold rounded border ${
                      RISK_CONFIG[inspectedEdge.risk_level]?.badgeBg || RISK_CONFIG.normal.badgeBg
                    }`}>
                      {inspectedEdge.risk_level}
                    </span>
                  </div>
                  <h4 className="text-sm font-bold text-white font-mono break-all">
                    {inspectedEdge.relationship}
                  </h4>
                  <div className="text-[10px] font-mono text-slate-500 break-all mt-0.5">
                    Sequence Step: #{inspectedEdge.sequence_order}
                  </div>
                </div>

                <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 space-y-2 font-mono text-[11px]">
                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase">Source Entity</span>
                    <span className="text-cyan-300">{inspectedEdge.source}</span>
                  </div>
                  <div className="pt-2 border-t border-slate-800">
                    <span className="text-slate-500 block text-[10px] uppercase">Target Entity</span>
                    <span className="text-purple-300">{inspectedEdge.target}</span>
                  </div>
                  <div className="pt-2 border-t border-slate-800">
                    <span className="text-slate-500 block text-[10px] uppercase">Timestamp</span>
                    <span className="text-slate-300">{new Date(inspectedEdge.timestamp).toLocaleString()}</span>
                  </div>
                </div>

                {/* Risk Reasons */}
                <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 space-y-1.5">
                  <div className="text-[10px] uppercase font-bold text-amber-400 tracking-wider">
                    Contextual Reasons
                  </div>
                  {inspectedEdge.reasons && inspectedEdge.reasons.length > 0 ? (
                    <ul className="space-y-1">
                      {inspectedEdge.reasons.map((r, i) => (
                        <li key={i} className="text-slate-200 flex items-start gap-1">
                          <span className="text-cyan-400">•</span> {r}
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <span className="text-emerald-400 text-[11px]">Standard relationship sequence.</span>
                  )}
                </div>

                {inspectedEdge.event_id && (
                  <button
                    onClick={() => onSelectEvent && onSelectEvent({ id: inspectedEdge.event_id })}
                    className="w-full py-2 bg-slate-950 hover:bg-slate-800 border border-slate-800 text-slate-300 rounded-xl text-xs font-mono font-semibold transition-all cursor-pointer flex items-center justify-center gap-1.5"
                  >
                    <Eye size={13} className="text-cyan-400" />
                    <span>Inspect Linked Event ({inspectedEdge.event_id.slice(0, 8)})</span>
                  </button>
                )}
              </div>
            ) : (
              <div className="py-16 text-center text-slate-500 text-xs">
                Click any entity node or relationship edge in the graph to inspect contextual details.
              </div>
            )}
          </Card>
        </div>
      </div>

      {/* Risk-Adaptive Response & Automated Containment Policy Panel */}
      <Card className="p-5 bg-gradient-to-r from-slate-900 via-slate-900/90 to-cyan-950/30 border border-cyan-800/40 shadow-xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-lg bg-cyan-950/80 border border-cyan-800/60 text-cyan-400">
              <ShieldCheck size={18} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-bold text-white tracking-wide uppercase">
                  Risk-Adaptive Response & Automated Containment
                </h3>
                <span className="px-2 py-0.5 text-[10px] font-mono bg-cyan-950 text-cyan-300 border border-cyan-800/60 rounded">
                  SAFE SIMULATION ACTIVE
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Dynamic containment calibrated to threat severity: Threat → Detection → Correlation → Risk → Approval Gate → Containment → Audit Trail → Recovery.
              </p>
            </div>
          </div>

          {setTab && (
            <button
              onClick={() => setTab('incidents')}
              className="px-3 py-1.5 bg-cyan-950/60 hover:bg-cyan-900/80 text-cyan-300 border border-cyan-800/60 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer shrink-0"
            >
              <span>Review Approvals & Audit</span>
              <ChevronRight size={13} />
            </button>
          )}
        </div>

        {/* 4-Tier Adaptive Policy Matrix */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 font-mono text-xs">
          <div className="p-3 rounded-xl bg-slate-950/70 border border-emerald-900/40 space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="font-bold text-emerald-400">LOW RISK</span>
              <span className="text-[10px] text-slate-500">Score ≤ 25</span>
            </div>
            <div className="text-[11px] text-slate-300 font-sans">
              Passive monitoring & normal baseline logging. Unfamiliar IP is <strong className="text-emerald-300">never blocked</strong>.
            </div>
            <div className="text-[10px] text-emerald-400/90 pt-1 border-t border-slate-800/80">
              Action: MONITOR
            </div>
          </div>

          <div className="p-3 rounded-xl bg-slate-950/70 border border-amber-900/40 space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="font-bold text-amber-300">MODERATE RISK</span>
              <span className="text-[10px] text-slate-500">Score 26–59</span>
            </div>
            <div className="text-[11px] text-slate-300 font-sans">
              Increased telemetry frequency & automated rate limiting on anomaly endpoints.
            </div>
            <div className="text-[10px] text-amber-300/90 pt-1 border-t border-slate-800/80">
              Action: RATE_LIMIT, ALERT
            </div>
          </div>

          <div className="p-3 rounded-xl bg-slate-950/70 border border-orange-900/40 space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="font-bold text-orange-400">HIGH RISK</span>
              <span className="text-[10px] text-slate-500">Score 60–79</span>
            </div>
            <div className="text-[11px] text-slate-300 font-sans">
              Step-up MFA verification required & sensitive API endpoint access restricted.
            </div>
            <div className="text-[10px] text-orange-400/90 pt-1 border-t border-slate-800/80">
              Action: STEP_UP_AUTH, RESTRICT_API
            </div>
          </div>

          <div className="p-3 rounded-xl bg-slate-950/70 border border-red-900/50 space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="font-bold text-red-400">CRITICAL RISK</span>
              <span className="text-[10px] text-slate-500">Score ≥ 80</span>
            </div>
            <div className="text-[11px] text-slate-300 font-sans">
              Human approval gate enforced. Dispatches session suspension, agent containment & corroborated IP block.
            </div>
            <div className="text-[10px] text-red-400/90 pt-1 border-t border-slate-800/80">
              Gate: PENDING_APPROVAL
            </div>
          </div>
        </div>

        {/* Safeguard & Dry-Run Simulation Notice */}
        <div className="flex items-center justify-between p-3 rounded-lg bg-slate-950/90 border border-slate-800/80 text-[11px] text-slate-400">
          <div className="flex items-center gap-2">
            <Radio size={13} className="text-cyan-400 animate-pulse" />
            <span>
              <strong className="text-slate-200">Production Safeguard:</strong> All containment actions run in safe simulation mode (mock containment recorded; real traffic uninterrupted).
            </span>
          </div>
          <span className="text-cyan-400 font-mono text-[10px] hidden sm:inline">
            Audit Trail: Immutable
          </span>
        </div>
      </Card>
    </div>
  );
}

// Subcomponent: Individual Node Card in the Tier Canvas
function NodeCard({ node, isSelected, onClick }) {
  const config = NODE_TYPE_CONFIG[node.type] || NODE_TYPE_CONFIG.Resource;
  const Icon = config.icon;
  const riskMeta = RISK_CONFIG[node.risk_level] || RISK_CONFIG.normal;

  return (
    <div
      onClick={onClick}
      className={`p-2.5 rounded-xl border transition-all cursor-pointer relative group ${config.bg} ${
        isSelected
          ? `${riskMeta.ring} ring-2 scale-102 bg-slate-900 font-semibold shadow-lg`
          : `${config.border} hover:border-slate-600 hover:bg-slate-900/90`
      }`}
    >
      <div className="flex items-center justify-between gap-1 text-[9px] uppercase font-bold tracking-wider text-slate-400">
        <div className="flex items-center gap-1">
          <Icon size={12} className={config.color} />
          <span>{node.type}</span>
        </div>
        {node.risk_level !== 'normal' && (
          <span className={`px-1 py-0.2 text-[8px] rounded uppercase font-bold border ${riskMeta.badgeBg}`}>
            {node.risk_level}
          </span>
        )}
      </div>

      <div className="font-mono text-xs font-bold mt-1 text-white truncate" title={node.label}>
        {node.label}
      </div>

      {node.reasons && node.reasons.length > 0 && (
        <div className="text-[9px] text-amber-300/90 mt-1 truncate">
          {node.reasons[0]}
        </div>
      )}
    </div>
  );
}

export default UserActivityGraphPage;
