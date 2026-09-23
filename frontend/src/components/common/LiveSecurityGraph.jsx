import React, { useState } from 'react';
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
  Info
} from 'lucide-react';

export function LiveSecurityGraph({ 
  onInvestigate,
  onSelectNode,
  className = "" 
}) {
  const [selectedNode, setSelectedNode] = useState('j_singh');

  // Exact 5-Column Grid Node Definitions with Amber for Suspicious
  const nodes = {
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
      icon: Bot,
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
      status: 'suspicious', // Yellow / Amber
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

  const handleNodeClick = (nodeId) => {
    setSelectedNode(nodeId);
    if (onSelectNode) onSelectNode(nodes[nodeId]);
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
        <div className="flex items-center gap-5 text-xs font-medium">
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

      {/* Interactive Visual Graph Canvas (Fully responsive SVG without scrollbar) */}
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

            {/* Path 1: A. Verma (70, 65) -> Laptop (235, 95) [Normal Green Curve] */}
            <path
              d="M 94 65 C 165 65, 165 95, 211 95"
              fill="none"
              stroke="#10b981"
              strokeWidth="2"
              filter="url(#glow-green)"
              className="opacity-80"
            />

            {/* Path 2: R. Khan (70, 295) -> Laptop (235, 95) [Baseline Green Curve] */}
            <path
              d="M 94 295 C 165 295, 165 95, 211 95"
              fill="none"
              stroke="#10b981"
              strokeWidth="1.5"
              className="opacity-40"
            />

            {/* Path 3: J. Singh (70, 180) -> Unknown Device (235, 265) [Malicious Solid Red Vector] */}
            <path
              d="M 94 180 C 165 180, 165 265, 211 265"
              fill="none"
              stroke="#f43f5e"
              strokeWidth="2.5"
              filter="url(#glow-red)"
              markerEnd="url(#arrow-red)"
            />

            {/* Path 4: Laptop (235, 95) -> HR API (580, 95) [Normal Traffic Across Top] */}
            <path
              d="M 259 95 L 556 95"
              fill="none"
              stroke="#10b981"
              strokeWidth="2"
              filter="url(#glow-green)"
              className="opacity-80"
            />

            {/* Path 5: Laptop (235, 95) -> HR_Agent (410, 180) [Normal Agent Interaction] */}
            <path
              d="M 259 95 C 320 95, 320 180, 382 180"
              fill="none"
              stroke="#10b981"
              strokeWidth="1.8"
              className="opacity-60"
            />

            {/* Path 6: Unknown Device (235, 265) -> HR_Agent (410, 180) [Red Dashed Attack Vector] */}
            <path
              d="M 259 265 C 320 265, 320 180, 382 180"
              fill="none"
              stroke="#f43f5e"
              strokeWidth="2.5"
              strokeDasharray="6 4"
              filter="url(#glow-red)"
              markerEnd="url(#arrow-red)"
              className="animate-pulse"
            />

            {/* Path 7: HR_Agent (410, 180) -> HR API (580, 95) [Amber Suspicious Interconnect] */}
            <path
              d="M 438 180 C 495 180, 495 95, 556 95"
              fill="none"
              stroke="#f59e0b"
              strokeWidth="2"
              filter="url(#glow-amber)"
              markerEnd="url(#arrow-amber)"
            />

            {/* Path 8: HR_Agent (410, 180) -> Payroll API (580, 265) [Red Dashed Exploit Vector] */}
            <path
              d="M 438 180 C 495 180, 495 265, 556 265"
              fill="none"
              stroke="#f43f5e"
              strokeWidth="2.5"
              strokeDasharray="6 4"
              filter="url(#glow-red)"
              markerEnd="url(#arrow-red)"
              className="animate-pulse"
            />

            {/* Path 9: HR API (580, 95) -> Employee DB (755, 95) [Green DB Query] */}
            <path
              d="M 604 95 L 731 95"
              fill="none"
              stroke="#10b981"
              strokeWidth="2"
              filter="url(#glow-green)"
              markerEnd="url(#arrow-green)"
              className="opacity-80"
            />

            {/* Path 10: Payroll API (580, 265) -> Customer DB (755, 265) [Red Dashed Exfiltration Vector] */}
            <path
              d="M 604 265 L 731 265"
              fill="none"
              stroke="#f43f5e"
              strokeWidth="2.5"
              strokeDasharray="6 4"
              filter="url(#glow-red)"
              markerEnd="url(#arrow-red)"
              className="animate-pulse"
            />

            {/* Path 11: HR API (580, 95) <-> Payroll API (580, 265) [Suspicious Bridge] */}
            <path
              d="M 580 119 L 580 241"
              fill="none"
              stroke="#f59e0b"
              strokeWidth="1.8"
              strokeDasharray="4 3"
              className="opacity-60"
            />

            {/* Node 1: A. Verma */}
            <g 
              onClick={() => handleNodeClick('a_verma')}
              className="cursor-pointer group"
              transform={`translate(${nodes.a_verma.x}, ${nodes.a_verma.y})`}
            >
              <circle
                r="24"
                fill="#090d16"
                stroke="#34d399"
                strokeWidth="2"
                filter="url(#glow-green)"
                className={`transition-all ${selectedNode === 'a_verma' ? 'stroke-white stroke-[3]' : ''}`}
              />
              <foreignObject x="-12" y="-12" width="24" height="24" className="pointer-events-none">
                <User size={24} className="text-emerald-400" />
              </foreignObject>
              <text x="32" y="-3" fill="#ffffff" fontSize="12" fontWeight="700" fontFamily="sans-serif">
                A. Verma
              </text>
              <text x="32" y="13" fill="#94a3b8" fontSize="10" fontFamily="sans-serif">
                (Employee)
              </text>
            </g>

            {/* Node 2: J. Singh (Malicious) */}
            <g 
              onClick={() => handleNodeClick('j_singh')}
              className="cursor-pointer group"
              transform={`translate(${nodes.j_singh.x}, ${nodes.j_singh.y})`}
            >
              <circle
                r="24"
                fill="#090d16"
                stroke="#f43f5e"
                strokeWidth="2.5"
                filter="url(#glow-red)"
                className={`transition-all ${selectedNode === 'j_singh' ? 'stroke-white stroke-[3]' : ''}`}
              />
              <foreignObject x="-12" y="-12" width="24" height="24" className="pointer-events-none">
                <User size={24} className="text-rose-400" />
              </foreignObject>
              <text x="32" y="-3" fill="#ffffff" fontSize="12" fontWeight="700" fontFamily="sans-serif">
                J. Singh
              </text>
              <text x="32" y="13" fill="#94a3b8" fontSize="10" fontFamily="sans-serif">
                (Analyst)
              </text>
            </g>

            {/* Node 3: R. Khan */}
            <g 
              onClick={() => handleNodeClick('r_khan')}
              className="cursor-pointer group"
              transform={`translate(${nodes.r_khan.x}, ${nodes.r_khan.y})`}
            >
              <circle
                r="24"
                fill="#090d16"
                stroke="#34d399"
                strokeWidth="2"
                filter="url(#glow-green)"
                className={`transition-all ${selectedNode === 'r_khan' ? 'stroke-white stroke-[3]' : ''}`}
              />
              <foreignObject x="-12" y="-12" width="24" height="24" className="pointer-events-none">
                <User size={24} className="text-emerald-400" />
              </foreignObject>
              <text x="32" y="-3" fill="#ffffff" fontSize="12" fontWeight="700" fontFamily="sans-serif">
                R. Khan
              </text>
              <text x="32" y="13" fill="#94a3b8" fontSize="10" fontFamily="sans-serif">
                (Contractor)
              </text>
            </g>

            {/* Node 4: Laptop (Windows) */}
            <g 
              onClick={() => handleNodeClick('laptop_win')}
              className="cursor-pointer group"
              transform={`translate(${nodes.laptop_win.x}, ${nodes.laptop_win.y})`}
            >
              <circle
                r="24"
                fill="#090d16"
                stroke="#34d399"
                strokeWidth="2"
                filter="url(#glow-green)"
                className={`transition-all ${selectedNode === 'laptop_win' ? 'stroke-white stroke-[3]' : ''}`}
              />
              <foreignObject x="-12" y="-12" width="24" height="24" className="pointer-events-none">
                <Monitor size={24} className="text-emerald-400" />
              </foreignObject>
              <text x="0" y="38" textAnchor="middle" fill="#ffffff" fontSize="12" fontWeight="700" fontFamily="sans-serif">
                Laptop
              </text>
              <text x="0" y="52" textAnchor="middle" fill="#94a3b8" fontSize="10" fontFamily="sans-serif">
                (Windows)
              </text>
            </g>

            {/* Node 5: Unknown Device (Linux) */}
            <g 
              onClick={() => handleNodeClick('unknown_device')}
              className="cursor-pointer group"
              transform={`translate(${nodes.unknown_device.x}, ${nodes.unknown_device.y})`}
            >
              <circle
                r="24"
                fill="#090d16"
                stroke="#f43f5e"
                strokeWidth="2.5"
                filter="url(#glow-red)"
                className={`transition-all ${selectedNode === 'unknown_device' ? 'stroke-white stroke-[3]' : ''}`}
              />
              <foreignObject x="-12" y="-12" width="24" height="24" className="pointer-events-none">
                <Bot size={24} className="text-rose-400" />
              </foreignObject>
              <text x="0" y="38" textAnchor="middle" fill="#ffffff" fontSize="12" fontWeight="700" fontFamily="sans-serif">
                Unknown Device
              </text>
              <text x="0" y="52" textAnchor="middle" fill="#94a3b8" fontSize="10" fontFamily="sans-serif">
                (Linux)
              </text>
            </g>

            {/* Node 6: HR_Agent (AI Agent) */}
            <g 
              onClick={() => handleNodeClick('hr_agent')}
              className="cursor-pointer group"
              transform={`translate(${nodes.hr_agent.x}, ${nodes.hr_agent.y})`}
            >
              <circle
                r="28"
                fill="#090d16"
                stroke="#f43f5e"
                strokeWidth="3"
                filter="url(#glow-red)"
                className={`transition-all ${selectedNode === 'hr_agent' ? 'stroke-white stroke-[4]' : ''}`}
              />
              <foreignObject x="-14" y="-14" width="28" height="28" className="pointer-events-none">
                <Bot size={28} className="text-rose-400" />
              </foreignObject>
              <text x="0" y="44" textAnchor="middle" fill="#ffffff" fontSize="12" fontWeight="700" fontFamily="sans-serif">
                HR_Agent
              </text>
              <text x="0" y="58" textAnchor="middle" fill="#94a3b8" fontSize="10" fontFamily="sans-serif">
                (AI Agent)
              </text>
            </g>

            {/* Node 7: HR API (Suspicious Yellow/Amber) */}
            <g 
              onClick={() => handleNodeClick('hr_api')}
              className="cursor-pointer group"
              transform={`translate(${nodes.hr_api.x}, ${nodes.hr_api.y})`}
            >
              <circle
                r="24"
                fill="#090d16"
                stroke="#f59e0b"
                strokeWidth="2.5"
                filter="url(#glow-amber)"
                className={`transition-all ${selectedNode === 'hr_api' ? 'stroke-white stroke-[3]' : ''}`}
              />
              <foreignObject x="-12" y="-12" width="24" height="24" className="pointer-events-none">
                <NetworkIcon size={24} className="text-amber-400" />
              </foreignObject>
              <text x="0" y="38" textAnchor="middle" fill="#ffffff" fontSize="12" fontWeight="700" fontFamily="sans-serif">
                HR API
              </text>
              <text x="0" y="52" textAnchor="middle" fill="#fcd34d" fontSize="10" fontFamily="sans-serif">
                (REST)
              </text>
            </g>

            {/* Node 8: Payroll API (Malicious Target) */}
            <g 
              onClick={() => handleNodeClick('payroll_api')}
              className="cursor-pointer group"
              transform={`translate(${nodes.payroll_api.x}, ${nodes.payroll_api.y})`}
            >
              <circle
                r="24"
                fill="#090d16"
                stroke="#f43f5e"
                strokeWidth="2.5"
                filter="url(#glow-red)"
                className={`transition-all ${selectedNode === 'payroll_api' ? 'stroke-white stroke-[3]' : ''}`}
              />
              <foreignObject x="-12" y="-12" width="24" height="24" className="pointer-events-none">
                <Shield size={24} className="text-rose-400" />
              </foreignObject>
              <text x="0" y="38" textAnchor="middle" fill="#ffffff" fontSize="12" fontWeight="700" fontFamily="sans-serif">
                Payroll API
              </text>
              <text x="0" y="52" textAnchor="middle" fill="#fda4af" fontSize="10" fontFamily="sans-serif">
                (Privileged)
              </text>
            </g>

            {/* Node 9: Employee DB */}
            <g 
              onClick={() => handleNodeClick('employee_db')}
              className="cursor-pointer group"
              transform={`translate(${nodes.employee_db.x}, ${nodes.employee_db.y})`}
            >
              <circle
                r="24"
                fill="#090d16"
                stroke="#34d399"
                strokeWidth="2"
                filter="url(#glow-green)"
                className={`transition-all ${selectedNode === 'employee_db' ? 'stroke-white stroke-[3]' : ''}`}
              />
              <foreignObject x="-12" y="-12" width="24" height="24" className="pointer-events-none">
                <Database size={24} className="text-emerald-400" />
              </foreignObject>
              <text x="0" y="38" textAnchor="middle" fill="#ffffff" fontSize="12" fontWeight="700" fontFamily="sans-serif">
                Employee DB
              </text>
              <text x="0" y="52" textAnchor="middle" fill="#94a3b8" fontSize="10" fontFamily="sans-serif">
                (PostgreSQL)
              </text>
            </g>

            {/* Node 10: Customer DB (Malicious Breach Target) */}
            <g 
              onClick={() => handleNodeClick('customer_db')}
              className="cursor-pointer group"
              transform={`translate(${nodes.customer_db.x}, ${nodes.customer_db.y})`}
            >
              <circle
                r="24"
                fill="#090d16"
                stroke="#f43f5e"
                strokeWidth="2.5"
                filter="url(#glow-red)"
                className={`transition-all ${selectedNode === 'customer_db' ? 'stroke-white stroke-[3]' : ''}`}
              />
              <foreignObject x="-12" y="-12" width="24" height="24" className="pointer-events-none">
                <Database size={24} className="text-rose-400" />
              </foreignObject>
              <text x="0" y="38" textAnchor="middle" fill="#ffffff" fontSize="12" fontWeight="700" fontFamily="sans-serif">
                Customer DB
              </text>
              <text x="0" y="52" textAnchor="middle" fill="#fda4af" fontSize="10" fontFamily="sans-serif">
                (Credentials)
              </text>
            </g>

          </svg>

        </div>
      </div>

      {/* Node Inspector Callout if selected */}
      {selectedNode && nodes[selectedNode] && (
        <div className="mb-4 p-3.5 bg-slate-900/90 border border-slate-800 rounded-xl flex items-center justify-between text-xs font-mono">
          <div className="flex items-center gap-2.5">
            <Info size={15} className="text-cyan-400" />
            <span className="text-white font-bold">{nodes[selectedNode].name}</span>
            {nodes[selectedNode].role && <span className="text-slate-400">({nodes[selectedNode].role})</span>}
            <span className="text-slate-600">|</span>
            <span className="text-slate-300">{nodes[selectedNode].details}</span>
          </div>
          <span className={`px-2.5 py-0.5 rounded text-[10px] uppercase font-bold border ${
            nodes[selectedNode].status === 'malicious' 
              ? 'bg-rose-950/80 text-rose-300 border-rose-800' 
              : nodes[selectedNode].status === 'suspicious'
              ? 'bg-amber-950/80 text-amber-300 border-amber-800'
              : 'bg-emerald-950/80 text-emerald-300 border-emerald-800'
          }`}>
            {nodes[selectedNode].status}
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
              Attack Path Detected
            </h4>
          </div>

          <button
            onClick={() => onInvestigate && onInvestigate()}
            className="px-3.5 py-1.5 rounded-lg border border-rose-800/80 bg-rose-950/50 hover:bg-rose-900/60 text-rose-300 hover:text-white text-xs font-semibold transition-all cursor-pointer flex items-center gap-1.5 shadow-sm"
          >
            <span>Investigate</span>
            <ArrowRight size={13} />
          </button>
        </div>

        {/* Breadcrumb Steps Row */}
        <div className="flex flex-wrap items-center gap-2 mb-2.5">
          <span className="px-3 py-1.5 bg-slate-900/90 border border-slate-800 rounded-lg text-xs font-mono text-slate-200">
            J. Singh
          </span>
          <ArrowRight size={13} className="text-rose-500 shrink-0" />

          <span className="px-3 py-1.5 bg-slate-900/90 border border-slate-800 rounded-lg text-xs font-mono text-slate-200">
            Unknown Device
          </span>
          <ArrowRight size={13} className="text-rose-500 shrink-0" />

          <span className="px-3 py-1.5 bg-slate-900/90 border border-slate-800 rounded-lg text-xs font-mono text-slate-200">
            HR_Agent
          </span>
          <ArrowRight size={13} className="text-rose-500 shrink-0" />

          <span className="px-3 py-1.5 bg-slate-900/90 border border-slate-800 rounded-lg text-xs font-mono text-slate-200">
            Payroll API
          </span>
          <ArrowRight size={13} className="text-rose-500 shrink-0" />

          <span className="px-3 py-1.5 bg-slate-900/90 border border-rose-800/80 text-rose-300 font-mono text-xs rounded-lg bg-rose-950/30">
            Customer DB
          </span>
        </div>

        {/* Explanatory Behavior Sequence Row */}
        <div className="text-[11px] font-mono text-slate-400 flex flex-wrap items-center gap-2">
          <span>Unusual login</span>
          <span className="text-rose-500">→</span>
          <span>Abnormal API calls</span>
          <span className="text-rose-500">→</span>
          <span>Possible prompt injection</span>
          <span className="text-rose-500">→</span>
          <span className="text-rose-300 font-semibold">Sensitive data access</span>
        </div>
      </div>
    </div>
  );
}

export default LiveSecurityGraph;
