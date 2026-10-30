/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { 
  ShieldAlert, 
  Activity, 
  FileText, 
  Sparkles, 
  RotateCcw, 
  Terminal, 
  Cpu, 
  HelpCircle 
} from 'lucide-react';
import { InvestigationCase } from '../types/forensics';

interface NavbarProps {
  currentTab: string;
  onSelectTab: (tab: string) => void;
  investigationCase: InvestigationCase;
  onResetDemo: () => void;
  onRunAiAnalysis: () => void;
  isAiAnalyzing: boolean;
  onOpenReport: () => void;
  onToggleCopilot: () => void;
  isCopilotOpen: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentTab,
  onSelectTab,
  investigationCase,
  onResetDemo,
  onRunAiAnalysis,
  isAiAnalyzing,
  onOpenReport,
  onToggleCopilot,
  isCopilotOpen
}) => {
  const tabs = [
    { id: 'overview', label: 'Overview', icon: Activity },
    { id: 'evidence', label: 'Evidence Collection', count: investigationCase.artifacts.length },
    { id: 'anti-forensics', label: 'Anti-Forensics Engine', badge: `${investigationCase.findings.length} Flagged`, badgeColor: 'bg-rose-500/20 text-rose-300 border-rose-500/30' },
    { id: 'timeline', label: 'Timeline Reconstruction', count: investigationCase.artifacts.length },
    { id: 'correlation', label: 'Evidence Correlation' },
    { id: 'ai-analysis', label: 'AI Forensic Core', icon: Sparkles, highlight: true },
    { id: 'report', label: 'Forensic Report', icon: FileText }
  ];

  return (
    <header className="sticky top-0 z-40 border-b border-cyan-950/70 bg-[#050814]/90 backdrop-blur-md">
      {/* Top Utility Bar */}
      <div className="flex flex-wrap items-center justify-between px-4 py-2 border-b border-slate-900/80 text-xs">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 px-2 py-0.5 rounded bg-emerald-950/50 border border-emerald-500/30 text-emerald-400 font-mono">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            SOC LEVEL 3 INVESTIGATION
          </div>
          <span className="text-slate-500 font-mono hidden md:inline">|</span>
          <div className="text-slate-400 font-mono hidden md:flex items-center gap-2">
            <span className="text-slate-500">CASE ID:</span>
            <span className="text-cyan-300 font-semibold">{investigationCase.caseId}</span>
          </div>
          <span className="text-slate-500 font-mono hidden lg:inline">|</span>
          <div className="text-slate-400 font-mono hidden lg:flex items-center gap-1">
            <span className="text-slate-500">TARGET:</span>
            <span className="text-slate-200">{investigationCase.targetHost}</span>
          </div>
        </div>

        <div className="flex items-center gap-2 ml-auto">
          <button
            onClick={onResetDemo}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900/80 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 text-xs transition"
            title="Reset to the synthetic employee data theft case"
          >
            <RotateCcw className="w-3.5 h-3.5 text-cyan-400" />
            <span className="hidden sm:inline">Reset Demo Case</span>
          </button>

          <button
            onClick={onToggleCopilot}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-xs transition border font-mono ${
              isCopilotOpen
                ? 'bg-cyan-500/20 text-cyan-200 border-cyan-500/50 shadow-[0_0_12px_rgba(6,182,212,0.25)]'
                : 'bg-slate-900 hover:bg-slate-800 text-slate-300 border-slate-800'
            }`}
          >
            <Terminal className="w-3.5 h-3.5 text-cyan-400" />
            <span>AI Copilot</span>
          </button>

          <button
            onClick={onOpenReport}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900/90 hover:bg-cyan-950/60 text-slate-200 hover:text-cyan-300 border border-slate-800 hover:border-cyan-700/50 text-xs transition"
          >
            <FileText className="w-3.5 h-3.5 text-cyan-400" />
            <span className="hidden sm:inline">Export Report</span>
          </button>

          <button
            onClick={onRunAiAnalysis}
            disabled={isAiAnalyzing}
            className="flex items-center gap-1.5 px-3 py-1 rounded bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-medium text-xs shadow-[0_0_15px_rgba(6,182,212,0.3)] transition disabled:opacity-50"
          >
            <Sparkles className={`w-3.5 h-3.5 ${isAiAnalyzing ? 'animate-spin' : ''}`} />
            <span>{isAiAnalyzing ? 'Analyzing...' : 'Run Gemini DFIR'}</span>
          </button>
        </div>
      </div>

      {/* Main Branding & Navigation Tabs */}
      <div className="flex flex-col md:flex-row md:items-center justify-between px-4 py-2.5 gap-2">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500/20 to-blue-600/30 border border-cyan-500/40 flex items-center justify-center shadow-[0_0_15px_rgba(6,182,212,0.2)]">
            <ShieldAlert className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-display text-lg font-bold tracking-wider text-white">
                TRACE<span className="text-cyan-400">X</span>
              </span>
              <span className="px-1.5 py-0.2 rounded text-[10px] font-mono tracking-tight bg-cyan-950/80 text-cyan-300 border border-cyan-800/40">
                v2.6 SOC
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-mono tracking-tight">
              AI-Assisted Anti-Forensics Detection & Timeline Reconstruction
            </p>
          </div>
        </div>

        {/* Tab Navigation */}
        <nav className="flex items-center gap-1 overflow-x-auto py-1 scrollbar-none">
          {tabs.map(tab => {
            const active = currentTab === tab.id;
            const Icon = tab.icon;

            return (
              <button
                key={tab.id}
                onClick={() => onSelectTab(tab.id)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium whitespace-nowrap transition-all ${
                  active
                    ? 'bg-gradient-to-r from-cyan-950/90 to-blue-950/70 text-cyan-300 border border-cyan-500/40 shadow-[0_0_12px_rgba(6,182,212,0.15)] font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 border border-transparent'
                }`}
              >
                {Icon && <Icon className={`w-3.5 h-3.5 ${active ? 'text-cyan-400' : 'text-slate-400'}`} />}
                <span>{tab.label}</span>
                {tab.count !== undefined && (
                  <span className={`px-1.5 py-0.2 text-[10px] rounded-full font-mono ${
                    active ? 'bg-cyan-500/20 text-cyan-200' : 'bg-slate-800 text-slate-400'
                  }`}>
                    {tab.count}
                  </span>
                )}
                {tab.badge && (
                  <span className={`px-1.5 py-0.2 text-[10px] rounded font-mono border ${tab.badgeColor}`}>
                    {tab.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>
    </header>
  );
};
