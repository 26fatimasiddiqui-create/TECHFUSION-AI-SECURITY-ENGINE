import React from 'react';
import { 
  ShieldAlert, 
  AlertTriangle, 
  CheckCircle2, 
  Clock, 
  User, 
  Laptop, 
  Bot, 
  Database, 
  Globe, 
  UploadCloud, 
  ArrowRight, 
  ArrowDown, 
  ShieldCheck, 
  Lightbulb, 
  Users, 
  Volume2, 
  Check, 
  FileText,
  Lock,
  Zap,
  Info
} from 'lucide-react';
import { Card } from '../common/Card';
import { 
  buildEasyNarrativeStory, 
  getEasyRiskDisplay, 
  translateTechnicalTerm 
} from '../../utils/easyLanguage';

export function EasyIncidentStory({ 
  incident, 
  onOpenActionCenter, 
  onReplayVoice,
  isPlayingVoice = false,
  onViewProDetails
}) {
  if (!incident) return null;

  const story = buildEasyNarrativeStory(incident);
  const score = incident.risk_assessment?.risk_score ?? 100;
  const level = incident.risk_assessment?.risk_level || 'CRITICAL';
  const riskDisplay = getEasyRiskDisplay(level, score);
  const approvalState = incident.approval_state || 'APPROVER_2_REQUIRED';
  const isDryRun = true; // Backend simulation containment mode

  return (
    <div className="space-y-6 max-w-5xl mx-auto font-sans">
      
      {/* 1. EASY MODE INCIDENT HEADER: High-level Critical Alert Banner */}
      <div className="rounded-2xl p-6 sm:p-8 bg-rose-50 dark:bg-gradient-to-r dark:from-rose-950/80 dark:via-red-950/60 dark:to-slate-900 border border-rose-200 dark:border-rose-800/80 shadow-sm dark:shadow-2xl transition-colors">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
          
          <div className="flex items-start gap-4">
            <div className="w-14 h-14 rounded-2xl bg-rose-600 dark:bg-rose-600 text-white flex items-center justify-center shrink-0 shadow-md shadow-rose-600/30">
              <AlertTriangle size={32} className="stroke-[2.2]" />
            </div>
            
            <div className="space-y-1.5">
              <div className="flex flex-wrap items-center gap-2">
                <span className="px-2.5 py-0.5 rounded-full bg-rose-100 dark:bg-rose-900/90 text-rose-800 dark:text-rose-200 text-xs font-bold uppercase tracking-wider border border-rose-300 dark:border-rose-700">
                  Critical Security Alert
                </span>
                <span className="text-xs font-semibold text-slate-600 dark:text-slate-400">
                  Incident ID: <strong className="text-slate-900 dark:text-white font-mono">{incident.id}</strong>
                </span>
              </div>
              
              <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 dark:text-white tracking-tight">
                Suspicious activity was detected involving a sensitive resource.
              </h1>
              
              <p className="text-sm text-slate-600 dark:text-slate-300 font-medium">
                Multiple correlated suspicious actions were identified and grouped into this active incident.
              </p>
            </div>
          </div>

          {/* Quick Metrics Pills */}
          <div className="flex sm:flex-col items-center sm:items-end gap-3 shrink-0 w-full sm:w-auto justify-between border-t md:border-t-0 pt-4 md:pt-0 border-rose-200 dark:border-rose-900/60">
            <div className="text-left sm:text-right">
              <div className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                Risk Level
              </div>
              <div className="text-xl sm:text-2xl font-black text-rose-600 dark:text-rose-400 flex items-center gap-1.5">
                <span>{riskDisplay.label}</span>
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-rose-100 dark:bg-rose-950 text-rose-800 dark:text-rose-300 border border-rose-200 dark:border-rose-800">
                  {riskDisplay.scoreText}
                </span>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-600 animate-pulse"></span>
              <span className="text-xs font-bold uppercase tracking-wider text-rose-700 dark:text-rose-300 font-mono">
                Status: ACTIVE
              </span>
            </div>
          </div>

        </div>

        {/* Quick Voice & Action Toolbar */}
        <div className="mt-6 pt-4 border-t border-rose-200 dark:border-rose-900/50 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            {onReplayVoice && (
              <button
                onClick={onReplayVoice}
                disabled={isPlayingVoice}
                className="px-3.5 py-1.5 rounded-xl bg-white dark:bg-slate-900 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-200 border border-slate-200 dark:border-slate-700 text-xs font-medium flex items-center gap-2 shadow-sm transition-all cursor-pointer"
              >
                <Volume2 size={15} className={`text-rose-500 ${isPlayingVoice ? 'animate-bounce' : ''}`} />
                <span>{isPlayingVoice ? 'Reading alert...' : 'Listen to summary'}</span>
              </button>
            )}
            
            {onViewProDetails && (
              <button
                onClick={onViewProDetails}
                className="px-3.5 py-1.5 rounded-xl bg-white dark:bg-slate-900 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-200 border border-slate-200 dark:border-slate-700 text-xs font-medium flex items-center gap-1.5 shadow-sm transition-all cursor-pointer"
              >
                <span>View technical details</span>
                <ArrowRight size={13} className="text-cyan-500" />
              </button>
            )}
          </div>

          {onOpenActionCenter && (
            <button
              onClick={onOpenActionCenter}
              className="px-4 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold flex items-center gap-2 shadow-md shadow-rose-600/30 transition-all cursor-pointer"
            >
              <span>Take Action Now</span>
              <ArrowRight size={14} />
            </button>
          )}
        </div>
      </div>

      {/* 2. SIMPLE NARRATIVE ATTACK FLOW: "What happened?" */}
      <Card className="p-6 sm:p-8 space-y-6">
        <div className="flex items-center gap-3 border-b border-slate-100 dark:border-slate-800 pb-4">
          <div className="w-9 h-9 rounded-xl bg-blue-100 dark:bg-blue-950 text-blue-600 dark:text-blue-400 flex items-center justify-center font-bold text-base">
            1
          </div>
          <div>
            <h2 className="text-lg sm:text-xl font-extrabold text-slate-900 dark:text-white tracking-tight">
              What happened?
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              The detected sequence of events from external source to data access:
            </p>
          </div>
        </div>

        {/* 6 Step Visual Flow Card Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          
          {/* Step 1: Threat Source */}
          <div className="p-4 rounded-2xl bg-slate-50 dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 space-y-2 flex flex-col justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-rose-100 dark:bg-rose-950/80 text-rose-600 dark:text-rose-400 flex items-center justify-center shrink-0 border border-rose-200 dark:border-rose-800">
                <Globe size={20} />
              </div>
              <div>
                <div className="text-[11px] font-bold text-slate-400 dark:text-slate-500 uppercase tracking-wider">
                  Step 1 • Threat Source
                </div>
                <div className="text-xs font-extrabold text-slate-900 dark:text-white">
                  Suspicious External Network
                </div>
              </div>
            </div>
            <p className="text-xs text-slate-600 dark:text-slate-300 pt-1 font-mono">
              IP: {story.threatSource}
            </p>
          </div>

          {/* Step 2: Device */}
          <div className="p-4 rounded-2xl bg-slate-50 dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 space-y-2 flex flex-col justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-purple-100 dark:bg-purple-950/80 text-purple-600 dark:text-purple-400 flex items-center justify-center shrink-0 border border-purple-200 dark:border-purple-800">
                <Laptop size={20} />
              </div>
              <div>
                <div className="text-[11px] font-bold text-slate-400 dark:text-slate-500 uppercase tracking-wider">
                  Step 2 • Device
                </div>
                <div className="text-xs font-extrabold text-slate-900 dark:text-white">
                  Unrecognized Machine
                </div>
              </div>
            </div>
            <p className="text-xs text-slate-600 dark:text-slate-300 pt-1 font-mono">
              {story.device}
            </p>
          </div>

          {/* Step 3: User */}
          <div className="p-4 rounded-2xl bg-slate-50 dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 space-y-2 flex flex-col justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-blue-100 dark:bg-blue-950/80 text-blue-600 dark:text-blue-400 flex items-center justify-center shrink-0 border border-blue-200 dark:border-blue-800">
                <User size={20} />
              </div>
              <div>
                <div className="text-[11px] font-bold text-slate-400 dark:text-slate-500 uppercase tracking-wider">
                  Step 3 • User Account
                </div>
                <div className="text-xs font-extrabold text-slate-900 dark:text-white">
                  Target Identity
                </div>
              </div>
            </div>
            <p className="text-xs text-slate-600 dark:text-slate-300 pt-1 font-mono">
              Account: {story.user}
            </p>
          </div>

          {/* Step 4: AI Agent */}
          <div className="p-4 rounded-2xl bg-slate-50 dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 space-y-2 flex flex-col justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-teal-100 dark:bg-teal-950/80 text-teal-600 dark:text-teal-400 flex items-center justify-center shrink-0 border border-teal-200 dark:border-teal-800">
                <Bot size={20} />
              </div>
              <div>
                <div className="text-[11px] font-bold text-slate-400 dark:text-slate-500 uppercase tracking-wider">
                  Step 4 • AI Assistant
                </div>
                <div className="text-xs font-extrabold text-slate-900 dark:text-white">
                  Automated Agent
                </div>
              </div>
            </div>
            <p className="text-xs text-slate-600 dark:text-slate-300 pt-1 font-mono">
              {story.agent}
            </p>
          </div>

          {/* Step 5: Activity */}
          <div className="p-4 rounded-2xl bg-slate-50 dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 space-y-2 flex flex-col justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-amber-100 dark:bg-amber-950/80 text-amber-600 dark:text-amber-400 flex items-center justify-center shrink-0 border border-amber-200 dark:border-amber-800">
                <Database size={20} />
              </div>
              <div>
                <div className="text-[11px] font-bold text-slate-400 dark:text-slate-500 uppercase tracking-wider">
                  Step 5 • Database Accessed
                </div>
                <div className="text-xs font-extrabold text-slate-900 dark:text-white">
                  Sensitive Customer Data
                </div>
              </div>
            </div>
            <p className="text-xs text-slate-600 dark:text-slate-300 pt-1">
              {story.activity}
            </p>
          </div>

          {/* Step 6: Result */}
          <div className="p-4 rounded-2xl bg-rose-50 dark:bg-rose-950/30 border border-rose-200 dark:border-rose-900/60 space-y-2 flex flex-col justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-rose-200 dark:bg-rose-900 text-rose-800 dark:text-rose-200 flex items-center justify-center shrink-0 border border-rose-300 dark:border-rose-700">
                <UploadCloud size={20} />
              </div>
              <div>
                <div className="text-[11px] font-bold text-rose-500 dark:text-rose-400 uppercase tracking-wider">
                  Step 6 • Threat Result
                </div>
                <div className="text-xs font-extrabold text-rose-900 dark:text-rose-100">
                  Data Exposure Risk
                </div>
              </div>
            </div>
            <p className="text-xs font-semibold text-rose-700 dark:text-rose-200 pt-1">
              {story.result}
            </p>
          </div>

        </div>
      </Card>

      {/* 3. 2-COLUMN SECTION: "What has AI done?" (Left) + "What should I do?" (Right) */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        
        {/* Left Column: What has AI done? */}
        <Card className="p-6 space-y-5">
          <div className="flex items-center gap-3 border-b border-slate-100 dark:border-slate-800 pb-3">
            <div className="w-9 h-9 rounded-xl bg-teal-100 dark:bg-teal-950 text-teal-600 dark:text-teal-400 flex items-center justify-center font-bold text-base">
              2
            </div>
            <div>
              <h3 className="text-base sm:text-lg font-bold text-slate-900 dark:text-white">
                What has AI done?
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Autonomous detection & containment pipeline
              </p>
            </div>
          </div>

          <div className="space-y-3 font-medium text-xs">
            <div className="flex items-center gap-3 text-emerald-700 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/40 p-2.5 rounded-xl border border-emerald-200 dark:border-emerald-800/60">
              <CheckCircle2 size={16} className="shrink-0" />
              <span>✓ Threat detected across event streams</span>
            </div>

            <div className="flex items-center gap-3 text-emerald-700 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/40 p-2.5 rounded-xl border border-emerald-200 dark:border-emerald-800/60">
              <CheckCircle2 size={16} className="shrink-0" />
              <span>✓ Related activity connected into attack sequence</span>
            </div>

            <div className="flex items-center gap-3 text-emerald-700 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/40 p-2.5 rounded-xl border border-emerald-200 dark:border-emerald-800/60">
              <CheckCircle2 size={16} className="shrink-0" />
              <span>✓ Risk assessed as {riskDisplay.label}</span>
            </div>

            <div className="flex items-center gap-3 text-emerald-700 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/40 p-2.5 rounded-xl border border-emerald-200 dark:border-emerald-800/60">
              <CheckCircle2 size={16} className="shrink-0" />
              <span>✓ High-priority security alert created</span>
            </div>

            <div className="flex items-center gap-3 text-emerald-700 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/40 p-2.5 rounded-xl border border-emerald-200 dark:border-emerald-800/60">
              <CheckCircle2 size={16} className="shrink-0" />
              <span>✓ Containment action plan prepared</span>
            </div>

            <div className="flex items-center gap-3 text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/40 p-2.5 rounded-xl border border-amber-200 dark:border-amber-800/60 font-semibold">
              <Clock size={16} className="shrink-0 text-amber-500 animate-spin" />
              <span>⏳ Waiting for human approval</span>
            </div>
          </div>

          {/* Explicit Dry Run / Simulation Notice */}
          <div className="p-3.5 rounded-xl bg-blue-50 dark:bg-slate-900 border border-blue-200 dark:border-slate-800 flex items-start gap-2.5 text-xs text-slate-700 dark:text-slate-300">
            <Info size={16} className="text-blue-500 shrink-0 mt-0.5" />
            <p className="leading-relaxed">
              <strong className="text-slate-900 dark:text-white font-semibold">Safety note:</strong> AI has prepared the action. It has <strong>NOT</strong> executed a real containment action yet without your authorization.
            </p>
          </div>
        </Card>

        {/* Right Column: What should I do? */}
        <Card className="p-6 space-y-5 flex flex-col justify-between">
          <div className="space-y-4">
            <div className="flex items-center gap-3 border-b border-slate-100 dark:border-slate-800 pb-3">
              <div className="w-9 h-9 rounded-xl bg-rose-100 dark:bg-rose-950 text-rose-600 dark:text-rose-400 flex items-center justify-center font-bold text-base">
                3
              </div>
              <div>
                <h3 className="text-base sm:text-lg font-bold text-slate-900 dark:text-white">
                  What should I do?
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Required steps to secure your environment
                </p>
              </div>
            </div>

            <div className="p-3 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-900/50 text-xs text-rose-800 dark:text-rose-300 font-bold uppercase tracking-wide">
              Action Required • Critical Security Incident
            </div>

            <ol className="space-y-2.5 text-xs text-slate-700 dark:text-slate-300">
              <li className="flex items-start gap-2.5">
                <span className="w-5 h-5 rounded-full bg-blue-600 text-white font-bold text-[11px] flex items-center justify-center shrink-0 mt-0.5">
                  1
                </span>
                <span>Review the affected user (<strong className="text-slate-900 dark:text-white font-mono">{story.user}</strong>) and machine.</span>
              </li>
              <li className="flex items-start gap-2.5">
                <span className="w-5 h-5 rounded-full bg-blue-600 text-white font-bold text-[11px] flex items-center justify-center shrink-0 mt-0.5">
                  2
                </span>
                <span>Verify whether the 15,000 records export was an authorized task.</span>
              </li>
              <li className="flex items-start gap-2.5">
                <span className="w-5 h-5 rounded-full bg-blue-600 text-white font-bold text-[11px] flex items-center justify-center shrink-0 mt-0.5">
                  3
                </span>
                <span>Approve the containment to restrict the copilot agent.</span>
              </li>
              <li className="flex items-start gap-2.5">
                <span className="w-5 h-5 rounded-full bg-blue-600 text-white font-bold text-[11px] flex items-center justify-center shrink-0 mt-0.5">
                  4
                </span>
                <span>Have a second authorized administrator co-sign the approval.</span>
              </li>
            </ol>
          </div>

          {/* Primary Action Button */}
          <div className="pt-4 border-t border-slate-100 dark:border-slate-800">
            {onOpenActionCenter && (
              <button
                onClick={onOpenActionCenter}
                className="w-full py-3 px-4 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs tracking-wide flex items-center justify-center gap-2 shadow-lg shadow-blue-600/30 transition-all cursor-pointer"
              >
                <span>Open Action Center</span>
                <ArrowRight size={14} />
              </button>
            )}
          </div>
        </Card>

      </div>

      {/* 4. KEY DETAILS & TWO-PERSON RULE EXPLANATION */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
        
        {/* Left 7 cols: Key Details Grid */}
        <div className="md:col-span-7">
          <Card className="p-6 space-y-4 h-full">
            <div className="flex items-center gap-2 border-b border-slate-100 dark:border-slate-800 pb-3">
              <FileText size={16} className="text-cyan-600 dark:text-cyan-400" />
              <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider">
                Essential Incident Summary
              </h3>
            </div>

            <div className="grid grid-cols-2 gap-4 text-xs">
              <div className="space-y-1">
                <span className="text-[11px] text-slate-400 font-medium">Threat Source</span>
                <div className="font-semibold text-slate-900 dark:text-white font-mono">{story.threatSource}</div>
              </div>

              <div className="space-y-1">
                <span className="text-[11px] text-slate-400 font-medium">Device</span>
                <div className="font-semibold text-slate-900 dark:text-white font-mono">{story.device}</div>
              </div>

              <div className="space-y-1">
                <span className="text-[11px] text-slate-400 font-medium">User Account</span>
                <div className="font-semibold text-slate-900 dark:text-white font-mono">{story.user}</div>
              </div>

              <div className="space-y-1">
                <span className="text-[11px] text-slate-400 font-medium">AI Agent</span>
                <div className="font-semibold text-slate-900 dark:text-white font-mono">{story.agent}</div>
              </div>

              <div className="space-y-1">
                <span className="text-[11px] text-slate-400 font-medium">Data Accessed</span>
                <div className="font-semibold text-slate-900 dark:text-white">{story.activity}</div>
              </div>

              <div className="space-y-1">
                <span className="text-[11px] text-slate-400 font-medium">Records Involved</span>
                <div className="font-bold text-rose-600 dark:text-rose-400 font-mono">15,000</div>
              </div>

              <div className="space-y-1">
                <span className="text-[11px] text-slate-400 font-medium">Risk Assessment</span>
                <div className="font-bold text-rose-600 dark:text-rose-400">{riskDisplay.label}</div>
              </div>

              <div className="space-y-1">
                <span className="text-[11px] text-slate-400 font-medium">Incident Status</span>
                <div className="font-bold text-emerald-600 dark:text-emerald-400">ACTIVE</div>
              </div>
            </div>
          </Card>
        </div>

        {/* Right 5 cols: Why Two-Person Rule? Callout */}
        <div className="md:col-span-5">
          <Card className="p-6 space-y-4 bg-slate-50 dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 h-full flex flex-col justify-between">
            <div className="space-y-3">
              <div className="flex items-center gap-2 text-cyan-700 dark:text-cyan-400 font-bold text-xs uppercase tracking-wider">
                <Users size={16} />
                <span>Why do I need another person?</span>
              </div>

              <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                Critical containment actions require <strong>two independent authorized people</strong>. This protects the system if one approval account is compromised or acting under duress.
              </p>

              <div className="space-y-2 pt-2 text-xs font-mono">
                <div className="flex items-center justify-between p-2 rounded-lg bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/60">
                  <span>Approval 1 (Lead Analyst)</span>
                  <span className="font-bold">✓ Approved</span>
                </div>
                <div className="flex items-center justify-between p-2 rounded-lg bg-amber-100 dark:bg-amber-950/60 text-amber-800 dark:text-amber-300 border border-amber-200 dark:border-amber-800/60">
                  <span>Approval 2 (Admin)</span>
                  <span className="font-bold">⏳ Required</span>
                </div>
              </div>
            </div>

            <div className="pt-2 text-[11px] text-slate-500 dark:text-slate-400">
              Two-Person Rule Safeguard Active
            </div>
          </Card>
        </div>

      </div>

    </div>
  );
}

export default EasyIncidentStory;
