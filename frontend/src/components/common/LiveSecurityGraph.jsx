import React, { useState, useMemo } from 'react';
import { 
  User, 
  Monitor, 
  Bot, 
  Network as NetworkIcon, 
  Database, 
  AlertTriangle, 
  ArrowRight,
  Shield,
  Layers,
  ChevronRight,
  Sparkles,
  CheckCircle2,
  Info,
  Laptop
} from 'lucide-react';

// Default baseline nodes used if events are not yet loaded
const DEFAULT_NODES = {
  a_verma: {
    id: 'a_verma',
    name: 'A. Verma',
    role: 'Employee',
    status: 'normal',
    type: 'user',
    x: 70,
    y: 65,
    r: 24,
    icon: User,
    details: 'Standard employee authentication from verified corporate hardware. Normal baseline profile.',
  },
  j_singh: {
    id: 'j_singh',
    name: 'J. Singh',
    role: 'Analyst',
    status: 'malicious',
    type: 'user',
    x: 70,
    y: 180,
    r: 24,
    icon: User,
    details: 'Unusual login detected outside normal working hours from an unverified geographic location.',
  },
  r_khan: {
    id: 'r_khan',
    name: 'R. Khan',
    role: 'Contractor',
    status: 'normal',
    type: 'user',
    x: 70,
    y: 295,
    r: 24,
    icon: User,
    details: 'Verified contractor profile with standard scoped API tokens.',
  },
  laptop_win: {
    id: 'laptop_win',
    name: 'Laptop',
    role: 'Windows',
    status: 'normal',
    type: 'device',
    x: 235,
    y: 95,
    r: 24,
    icon: Monitor,
    details: 'Managed corporate workstation D_CORP_WIN_11. Fully compliant endpoint health.',
  },
  unknown_device: {
    id: 'unknown_device',
    name: 'Unknown Device',
    role: 'Linux',
    status: 'malicious',
    type: 'device',
    x: 235,
    y: 265,
    r: 24,
    icon: Laptop,
    details: 'Unrecognized Kali Linux box connecting via external IP 203.0.113.195 with forged headers.',
  },
  hr_agent: {
    id: 'hr_agent',
    name: 'HR_Agent',
    role: 'AI Agent',
    status: 'malicious',
    type: 'agent',
    x: 410,
    y: 180,
    r: 28,
    icon: Bot,
    details: 'Autonomous LLM agent copilot prompted with privileged jailbreak to dump customer credentials.',
  },
  hr_api: {
    id: 'hr_api',
    name: 'HR API',
    role: 'Gateway',
    status: 'suspicious',
    type: 'api',
    x: 580,
    y: 95,
    r: 24,
    icon: NetworkIcon,
    details: 'Standard HR REST gateway. High call frequency observed from autonomous orchestrator.',
  },
  payroll_api: {
    id: 'payroll_api',
    name: 'Payroll API',
    role: 'Privileged',
    status: 'malicious',
    type: 'api',
    x: 580,
    y: 265,
    r: 24,
    icon: Shield,
    details: 'Financial payroll endpoint invoked for bulk export bypassing standard rate limits.',
  },
  employee_db: {
    id: 'employee_db',
    name: 'Employee DB',
    role: 'PostgreSQL',
    status: 'normal',
    type: 'database',
    x: 755,
    y: 95,
    r: 24,
    icon: Database,
    details: 'Internal staff directory PostgreSQL cluster. Standard read operations.',
  },
  customer_db: {
    id: 'customer_db',
    name: 'Customer DB',
    role: 'PII Store',
    status: 'malicious',
    type: 'database',
    x: 755,
    y: 265,
    r: 24,
    icon: Database,
    details: 'Sensitive customer PII & credential database targeted for bulk table exfiltration.',
  },
};

const DEFAULT_PATHS = [
  { d: "M 94 65 C 165 65, 165 95, 211 95", color: "#10b981", strokeWidth: 2, filter: "url(#glow-green)" },
  { d: "M 94 295 C 165 295, 165 95, 211 95", color: "#10b981", strokeWidth: 1.5, opacity: 0.4 },
  { d: "M 94 180 C 165 180, 165 265, 211 265", color: "#f43f5e", strokeWidth: 2.5, filter: "url(#glow-red)", markerEnd: "url(#arrow-red)" },
  { d: "M 259 95 L 556 95", color: "#10b981", strokeWidth: 2, filter: "url(#glow-green)" },
  { d: "M 259 95 C 320 95, 320 180, 382 180", color: "#10b981", strokeWidth: 1.8, opacity: 0.6 },
  { d: "M 259 265 C 320 265, 320 180, 382 180", color: "#f43f5e", strokeWidth: 2.5, strokeDasharray: "6 4", filter: "url(#glow-red)", markerEnd: "url(#arrow-red)", animate: true },
  { d: "M 438 180 C 495 180, 495 95, 556 95", color: "#f59e0b", strokeWidth: 2, filter: "url(#glow-amber)", markerEnd: "url(#arrow-amber)" },
  { d: "M 438 180 C 495 180, 495 265, 556 265", color: "#f43f5e", strokeWidth: 2.5, strokeDasharray: "6 4", filter: "url(#glow-red)", markerEnd: "url(#arrow-red)", animate: true },
  { d: "M 604 95 L 731 95", color: "#10b981", strokeWidth: 2, filter: "url(#glow-green)", markerEnd: "url(#arrow-green)" },
  { d: "M 604 265 L 731 265", color: "#f43f5e", strokeWidth: 2.5, strokeDasharray: "6 4", filter: "url(#glow-red)", markerEnd: "url(#arrow-red)", animate: true },
  { d: "M 580 119 L 580 241", color: "#f59e0b", strokeWidth: 1.8, strokeDasharray: "4 3", opacity: 0.6 },
];

export function LiveSecurityGraph({ 
  events = [],
  onInvestigate,
  onSelectNode,
  className = "" 
}) {
  const [selectedNodeId, setSelectedNodeId] = useState(null);

  // Dynamic layout generator building nodes and links from real live events
  const { nodes, paths, attackChain } = useMemo(() => {
    if (!events || events.length === 0) {
      return {
        nodes: DEFAULT_NODES,
        paths: DEFAULT_PATHS,
        attackChain: [
          { label: 'J. Singh', type: 'user' },
          { label: 'Unknown Device', type: 'device' },
          { label: 'HR_Agent', type: 'agent' },
          { label: 'Payroll API', type: 'api' },
          { label: 'Customer DB', type: 'database' },
        ]
      };
    }

    // Helper to extract clean entity names and risk ratings
    const userMap = new Map();
    const deviceMap = new Map();
    const agentMap = new Map();
    const apiMap = new Map();
    const dbMap = new Map();

    const getRisk = (evt) => {
      if (evt.metadata?.privilege_escalation || evt.resource?.includes('dump') || evt.resource?.includes('credential')) return 'malicious';
      if (evt.metadata?.is_new_device || evt.event_type === 'failed_login' || evt.device_id?.startsWith('unknown')) return 'suspicious';
      return 'normal';
    };

    // Parse all events
    events.forEach((evt) => {
      const risk = getRisk(evt);

      // 1. User
      const uName = evt.user_id || 'U_ANALYST';
      const uKey = uName.toLowerCase().replace(/\s+/g, '_');
      if (!userMap.has(uKey)) {
        userMap.set(uKey, {
          id: uKey,
          name: uName,
          role: uName.includes('Singh') ? 'Analyst' : uName.includes('Fatima') ? 'Security' : 'Employee',
          status: risk,
          type: 'user',
          details: `User entity ${uName} active across event streams.`,
        });
      } else if (risk === 'malicious' || (risk === 'suspicious' && userMap.get(uKey).status === 'normal')) {
        userMap.get(uKey).status = risk;
      }

      // 2. Device
      const dName = evt.device_id || 'Laptop';
      const dKey = dName.toLowerCase().replace(/\s+/g, '_');
      if (!deviceMap.has(dKey)) {
        deviceMap.set(dKey, {
          id: dKey,
          name: dName.length > 18 ? dName.slice(0, 16) + '...' : dName,
          role: dName.includes('Tor') || dName.includes('Kali') ? 'Linux VM' : 'Corporate',
          status: risk,
          type: 'device',
          details: `Endpoint ${dName} verified in telemetry logs.`,
        });
      } else if (risk === 'malicious' || (risk === 'suspicious' && deviceMap.get(dKey).status === 'normal')) {
        deviceMap.get(dKey).status = risk;
      }

      // 3. Agent / Tool
      if (evt.agent_id || evt.tool_name) {
        const agName = evt.agent_id || evt.tool_name || 'HR_Agent';
        const agKey = agName.toLowerCase().replace(/\s+/g, '_');
        if (!agentMap.has(agKey)) {
          agentMap.set(agKey, {
            id: agKey,
            name: agName,
            role: evt.tool_name ? 'Tool' : 'AI Agent',
            status: risk,
            type: 'agent',
            details: `Autonomous worker ${agName} invoked in session ${evt.session_id || 'active'}.`,
          });
        }
      }

      // 4. API Endpoint / Gateway
      if (evt.resource && (evt.resource.includes('api') || evt.event_type?.includes('api') || evt.event_type?.includes('login'))) {
        const apiName = evt.resource.includes('api') ? evt.resource.split('/').pop() || 'API' : 'Auth Gateway';
        const apiKey = ('api_' + apiName).toLowerCase().replace(/[^a-z0-9]/g, '_');
        if (!apiMap.has(apiKey)) {
          apiMap.set(apiKey, {
            id: apiKey,
            name: apiName.toUpperCase(),
            role: evt.resource.includes('payroll') ? 'Privileged' : 'REST Gateway',
            status: risk,
            type: 'api',
            details: `API Endpoint resource: ${evt.resource}`,
          });
        }
      }

      // 5. Database / Data Store
      if (evt.resource && (evt.resource.includes('database') || evt.resource.includes('customer') || evt.resource.includes('dump') || evt.event_type?.includes('database'))) {
        const dbName = evt.resource.includes('customer') ? 'Customer DB' : 'Employee DB';
        const dbKey = ('db_' + dbName).toLowerCase().replace(/[^a-z0-9]/g, '_');
        if (!dbMap.has(dbKey)) {
          dbMap.set(dbKey, {
            id: dbKey,
            name: dbName,
            role: evt.resource.includes('credential') ? 'Credentials' : 'PII Store',
            status: risk,
            type: 'database',
            details: `Persistent store resource target: ${evt.resource}`,
          });
        }
      }
    });

    // Ensure default demo nodes are populated if lists are sparse
    if (userMap.size < 2 && DEFAULT_NODES.a_verma) userMap.set('a_verma', DEFAULT_NODES.a_verma);
    if (deviceMap.size < 2 && DEFAULT_NODES.laptop_win) deviceMap.set('laptop_win', DEFAULT_NODES.laptop_win);
    if (agentMap.size < 1 && DEFAULT_NODES.hr_agent) agentMap.set('hr_agent', DEFAULT_NODES.hr_agent);
    if (apiMap.size < 2 && DEFAULT_NODES.hr_api) apiMap.set('hr_api', DEFAULT_NODES.hr_api);
    if (dbMap.size < 2 && DEFAULT_NODES.customer_db) dbMap.set('customer_db', DEFAULT_NODES.customer_db);

    // Layout Columns: 5 Columns with vertical centering
    const dynamicNodes = {};
    const layoutCol = (mapObj, x, iconDefault) => {
      const items = Array.from(mapObj.values()).slice(0, 4);
      const count = items.length;
      const startY = count === 1 ? 180 : count === 2 ? 100 : count === 3 ? 65 : 45;
      const stepY = count === 1 ? 0 : count === 2 ? 160 : count === 3 ? 115 : 85;

      items.forEach((item, idx) => {
        const y = startY + idx * stepY;
        dynamicNodes[item.id] = {
          ...item,
          x,
          y,
          r: item.type === 'agent' ? 28 : 24,
          icon: iconDefault,
        };
      });
    };

    layoutCol(userMap, 70, User);
    layoutCol(deviceMap, 235, Laptop);
    layoutCol(agentMap, 410, Bot);
    layoutCol(apiMap, 580, NetworkIcon);
    layoutCol(dbMap, 755, Database);

    // Compute Dynamic Connector Paths between contiguous columns
    const dynamicPaths = [];
    const allUsers = Object.values(dynamicNodes).filter(n => n.type === 'user');
    const allDevices = Object.values(dynamicNodes).filter(n => n.type === 'device');
    const allAgents = Object.values(dynamicNodes).filter(n => n.type === 'agent');
    const allApis = Object.values(dynamicNodes).filter(n => n.type === 'api');
    const allDbs = Object.values(dynamicNodes).filter(n => n.type === 'database');

    // Link Users to Devices
    allUsers.forEach((u, uIdx) => {
      const targetDev = allDevices[uIdx % allDevices.length] || allDevices[0];
      if (targetDev) {
        const isMal = u.status === 'malicious' || targetDev.status === 'malicious';
        const isSusp = u.status === 'suspicious' || targetDev.status === 'suspicious';
        dynamicPaths.push({
          d: `M ${u.x + u.r} ${u.y} C ${(u.x + targetDev.x) / 2} ${u.y}, ${(u.x + targetDev.x) / 2} ${targetDev.y}, ${targetDev.x - targetDev.r} ${targetDev.y}`,
          color: isMal ? '#f43f5e' : isSusp ? '#f59e0b' : '#10b981',
          strokeWidth: isMal ? 2.5 : 2,
          filter: isMal ? 'url(#glow-red)' : isSusp ? 'url(#glow-amber)' : 'url(#glow-green)',
          markerEnd: isMal ? 'url(#arrow-red)' : isSusp ? 'url(#arrow-amber)' : 'url(#arrow-green)',
          strokeDasharray: isMal ? '6 4' : undefined,
          animate: isMal,
        });
      }
    });

    // Link Devices to Agents or APIs
    allDevices.forEach((dev, dIdx) => {
      const targetAgent = allAgents[dIdx % allAgents.length] || allAgents[0];
      if (targetAgent) {
        const isMal = dev.status === 'malicious' || targetAgent.status === 'malicious';
        const isSusp = dev.status === 'suspicious' || targetAgent.status === 'suspicious';
        dynamicPaths.push({
          d: `M ${dev.x + dev.r} ${dev.y} C ${(dev.x + targetAgent.x) / 2} ${dev.y}, ${(dev.x + targetAgent.x) / 2} ${targetAgent.y}, ${targetAgent.x - targetAgent.r} ${targetAgent.y}`,
          color: isMal ? '#f43f5e' : isSusp ? '#f59e0b' : '#10b981',
          strokeWidth: isMal ? 2.5 : 2,
          filter: isMal ? 'url(#glow-red)' : isSusp ? 'url(#glow-amber)' : 'url(#glow-green)',
          markerEnd: isMal ? 'url(#arrow-red)' : isSusp ? 'url(#arrow-amber)' : 'url(#arrow-green)',
          strokeDasharray: isMal ? '6 4' : undefined,
          animate: isMal,
        });
      }
    });

    // Link Agents to APIs
    allAgents.forEach((ag, aIdx) => {
      allApis.forEach((api) => {
        const isMal = ag.status === 'malicious' || api.status === 'malicious';
        const isSusp = ag.status === 'suspicious' || api.status === 'suspicious';
        dynamicPaths.push({
          d: `M ${ag.x + ag.r} ${ag.y} C ${(ag.x + api.x) / 2} ${ag.y}, ${(ag.x + api.x) / 2} ${api.y}, ${api.x - api.r} ${api.y}`,
          color: isMal ? '#f43f5e' : isSusp ? '#f59e0b' : '#10b981',
          strokeWidth: isMal ? 2.5 : 1.8,
          filter: isMal ? 'url(#glow-red)' : isSusp ? 'url(#glow-amber)' : 'url(#glow-green)',
          markerEnd: isMal ? 'url(#arrow-red)' : isSusp ? 'url(#arrow-amber)' : 'url(#arrow-green)',
          strokeDasharray: isMal ? '6 4' : undefined,
          animate: isMal,
        });
      });
    });

    // Link APIs to Databases
    allApis.forEach((api, pIdx) => {
      const targetDb = allDbs[pIdx % allDbs.length] || allDbs[0];
      if (targetDb) {
        const isMal = api.status === 'malicious' || targetDb.status === 'malicious';
        const isSusp = api.status === 'suspicious' || targetDb.status === 'suspicious';
        dynamicPaths.push({
          d: `M ${api.x + api.r} ${api.y} L ${targetDb.x - targetDb.r} ${targetDb.y}`,
          color: isMal ? '#f43f5e' : isSusp ? '#f59e0b' : '#10b981',
          strokeWidth: isMal ? 2.5 : 2,
          filter: isMal ? 'url(#glow-red)' : isSusp ? 'url(#glow-amber)' : 'url(#glow-green)',
          markerEnd: isMal ? 'url(#arrow-red)' : isSusp ? 'url(#arrow-amber)' : 'url(#arrow-green)',
          strokeDasharray: isMal ? '6 4' : undefined,
          animate: isMal,
        });
      }
    });

    // Derive Attack Chain for Bottom Banner
    const topThreatUser = allUsers.find(u => u.status === 'malicious') || allUsers[0];
    const topThreatDev = allDevices.find(d => d.status === 'malicious') || allDevices[0];
    const topThreatAgent = allAgents[0];
    const topThreatApi = allApis.find(a => a.status === 'malicious') || allApis[0];
    const topThreatDb = allDbs.find(d => d.status === 'malicious') || allDbs[0];

    const chain = [];
    if (topThreatUser) chain.push({ label: topThreatUser.name, type: 'user' });
    if (topThreatDev) chain.push({ label: topThreatDev.name, type: 'device' });
    if (topThreatAgent) chain.push({ label: topThreatAgent.name, type: 'agent' });
    if (topThreatApi) chain.push({ label: topThreatApi.name, type: 'api' });
    if (topThreatDb) chain.push({ label: topThreatDb.name, type: 'database' });

    return {
      nodes: dynamicNodes,
      paths: dynamicPaths,
      attackChain: chain
    };
  }, [events]);

  const activeSelectedKey = selectedNodeId || Object.keys(nodes)[0] || 'j_singh';
  const selectedNode = nodes[activeSelectedKey] || Object.values(nodes)[0];

  const handleNodeClick = (nodeKey) => {
    setSelectedNodeId(nodeKey);
    if (onSelectNode && nodes[nodeKey]) onSelectNode(nodes[nodeKey]);
  };

  return (
    <div className={`bg-slate-950/95 border border-slate-800/90 rounded-2xl p-6 shadow-2xl relative overflow-hidden font-sans ${className}`}>
      {/* Background ambient cybersecurity glows */}
      <div className="absolute top-1/4 left-1/4 w-72 h-72 bg-rose-950/15 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute bottom-1/4 right-1/4 w-72 h-72 bg-emerald-950/10 rounded-full blur-3xl pointer-events-none" />

      {/* Header & Legend */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800/80 relative z-10">
        <div>
          <h3 className="text-xl font-bold text-white tracking-tight">
            Live Security Graph
          </h3>
          <p className="text-xs text-slate-400 mt-1">
            Real-time view of users, devices, APIs, AI agents and data flow.
          </p>
        </div>

        {/* Legend */}
        <div className="flex items-center gap-5 text-xs font-medium font-mono">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-sm bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]" />
            <span className="text-slate-300">Normal</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-sm bg-amber-400 shadow-[0_0_8px_rgba(251,191,36,0.8)]" />
            <span className="text-slate-300">Suspicious</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-sm bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.8)]" />
            <span className="text-slate-300">Malicious</span>
          </div>
        </div>
      </div>

      {/* Interactive Visual Graph Canvas (Fully responsive SVG) */}
      <div className="relative w-full py-4 overflow-hidden">
        <div className="w-full max-w-[880px] mx-auto select-none">
          
          <svg className="w-full h-auto" viewBox="0 0 880 360">
            <defs>
              {/* Arrow markers */}
              <marker
                id="arrow-red"
                viewBox="0 0 10 10"
                refX="8"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#f43f5e" />
              </marker>
              <marker
                id="arrow-green"
                viewBox="0 0 10 10"
                refX="8"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#10b981" />
              </marker>
              <marker
                id="arrow-amber"
                viewBox="0 0 10 10"
                refX="8"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#f59e0b" />
              </marker>

              {/* Glowing filters */}
              <filter id="glow-red" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation="3" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
              <filter id="glow-green" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation="3" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
              <filter id="glow-amber" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation="3" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>

            {/* Dynamic Connecting Paths */}
            {paths.map((p, idx) => (
              <path
                key={idx}
                d={p.d}
                fill="none"
                stroke={p.color}
                strokeWidth={p.strokeWidth || 2}
                strokeDasharray={p.strokeDasharray}
                filter={p.filter}
                markerEnd={p.markerEnd}
                className={`transition-all duration-500 ${p.animate ? 'animate-pulse' : ''} ${p.opacity ? `opacity-${Math.round(p.opacity * 100)}` : ''}`}
              />
            ))}

            {/* Dynamic Graph Nodes */}
            {Object.entries(nodes).map(([nodeKey, node]) => {
              const isSelected = activeSelectedKey === nodeKey;
              const isMal = node.status === 'malicious';
              const isSusp = node.status === 'suspicious';
              const strokeColor = isMal ? '#f43f5e' : isSusp ? '#f59e0b' : '#34d399';
              const filterUrl = isMal ? 'url(#glow-red)' : isSusp ? 'url(#glow-amber)' : 'url(#glow-green)';
              const IconComp = node.icon || (node.type === 'user' ? User : node.type === 'device' ? Laptop : node.type === 'agent' ? Bot : node.type === 'api' ? NetworkIcon : Database);

              return (
                <g 
                  key={nodeKey}
                  onClick={() => handleNodeClick(nodeKey)}
                  className="cursor-pointer group"
                  transform={`translate(${node.x}, ${node.y})`}
                >
                  <circle
                    r={node.r || 24}
                    fill="#090d16"
                    stroke={strokeColor}
                    strokeWidth={isSelected ? 3.5 : isMal ? 2.5 : 2}
                    filter={filterUrl}
                    className={`transition-all duration-300 ${isSelected ? 'stroke-white' : ''}`}
                  />
                  <foreignObject x={-(node.r || 24) / 2} y={-(node.r || 24) / 2} width={node.r || 24} height={node.r || 24} className="pointer-events-none flex items-center justify-center">
                    <IconComp size={(node.r || 24) - 2} className={isMal ? 'text-rose-400' : isSusp ? 'text-amber-400' : 'text-emerald-400'} />
                  </foreignObject>

                  {/* Label Text below node or side */}
                  {node.type === 'user' ? (
                    <>
                      <text x="32" y="-3" fill="#ffffff" fontSize="12" fontWeight="700" fontFamily="sans-serif">
                        {node.name}
                      </text>
                      <text x="32" y="13" fill="#94a3b8" fontSize="10" fontFamily="sans-serif">
                        ({node.role || 'User'})
                      </text>
                    </>
                  ) : (
                    <>
                      <text x="0" y={(node.r || 24) + 14} textAnchor="middle" fill="#ffffff" fontSize="11" fontWeight="700" fontFamily="sans-serif">
                        {node.name}
                      </text>
                      <text x="0" y={(node.r || 24) + 26} textAnchor="middle" fill={isMal ? '#fda4af' : isSusp ? '#fcd34d' : '#94a3b8'} fontSize="9.5" fontFamily="sans-serif">
                        ({node.role || node.type})
                      </text>
                    </>
                  )}
                </g>
              );
            })}

          </svg>

        </div>
      </div>

      {/* Node Inspector Callout if selected */}
      {selectedNode && (
        <div className="mb-4 p-3.5 bg-slate-900/90 border border-slate-800 rounded-xl flex items-center justify-between text-xs font-mono shadow-md">
          <div className="flex items-center gap-2.5">
            <Info size={15} className="text-cyan-400" />
            <span className="text-white font-bold">{selectedNode.name}</span>
            {selectedNode.role && <span className="text-slate-400">({selectedNode.role})</span>}
            <span className="text-slate-600">|</span>
            <span className="text-slate-300">{selectedNode.details}</span>
          </div>
          <span className={`px-2.5 py-0.5 rounded text-[10px] uppercase font-bold border ${
            selectedNode.status === 'malicious' 
              ? 'bg-rose-950/80 text-rose-300 border-rose-800' 
              : selectedNode.status === 'suspicious'
              ? 'bg-amber-950/80 text-amber-300 border-amber-800'
              : 'bg-emerald-950/80 text-emerald-300 border-emerald-800'
          }`}>
            {selectedNode.status}
          </span>
        </div>
      )}

      {/* Bottom Banner: Attack Path Detected */}
      <div className="bg-gradient-to-r from-rose-950/40 via-slate-900/90 to-rose-950/30 border border-rose-900/50 rounded-2xl p-5 shadow-lg relative">
        <div className="flex items-center justify-between gap-4 mb-3.5">
          <div className="flex items-center gap-2.5">
            <div className="w-6 h-6 rounded-md bg-rose-900/60 border border-rose-700 flex items-center justify-center text-rose-300">
              <AlertTriangle size={15} />
            </div>
            <h4 className="text-sm font-bold text-rose-400 tracking-wide">
              Correlated Vector Progression
            </h4>
          </div>

          <button
            onClick={() => onInvestigate && onInvestigate()}
            className="px-3.5 py-1.5 rounded-lg border border-rose-800/80 bg-rose-950/50 hover:bg-rose-900/60 text-rose-300 hover:text-white text-xs font-semibold transition-all cursor-pointer flex items-center gap-1.5 shadow-sm"
          >
            <span>Investigate Incident</span>
            <ArrowRight size={13} />
          </button>
        </div>

        {/* Breadcrumb Steps Row */}
        <div className="flex flex-wrap items-center gap-2 mb-2.5 font-mono text-xs">
          {attackChain.map((step, idx) => (
            <React.Fragment key={idx}>
              <span className={`px-3 py-1.5 rounded-lg border text-xs font-bold ${
                idx === attackChain.length - 1
                  ? 'bg-rose-950/80 border-rose-700 text-rose-200'
                  : 'bg-slate-900/90 border-slate-800 text-slate-200'
              }`}>
                {step.label}
              </span>
              {idx < attackChain.length - 1 && (
                <ArrowRight size={13} className="text-rose-500 shrink-0" />
              )}
            </React.Fragment>
          ))}
        </div>

        {/* Explanatory Behavior Sequence Row */}
        <div className="text-[11px] font-mono text-slate-400 flex flex-wrap items-center gap-2">
          <span>Authentication</span>
          <span className="text-rose-500">→</span>
          <span>Endpoint Device</span>
          <span className="text-rose-500">→</span>
          <span>Tool/Agent Invocation</span>
          <span className="text-rose-500">→</span>
          <span>API Access</span>
          <span className="text-rose-500">→</span>
          <span className="text-rose-300 font-semibold">Sensitive Store Access</span>
        </div>
      </div>
    </div>
  );
}

export default LiveSecurityGraph;
