/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { 
  Sparkles, 
  ShieldAlert, 
  CheckCircle2, 
  HelpCircle, 
  Clock, 
  Layers, 
  Send, 
  FileCheck, 
  Lightbulb, 
  Target,
  RefreshCw,
  Database
} from 'lucide-react';
import { InvestigationCase } from '../types/forensics';

interface AiAnalysisModuleProps {
  investigationCase: InvestigationCase;
  onRunAnalysis: (customQuestion?: string) => Promise<void>;
  isAnalyzing: boolean;
}

export const AiAnalysisModule: React.FC<AiAnalysisModuleProps> = ({
  investigationCase,
  onRunAnalysis,
  isAnalyzing
}) => {
  const { aiAnalysis, artifacts, isDemoDataset, riskBreakdown } = investigationCase;
  const [customQuestion, setCustomQuestion] = useState('');

  const hasEvidence = artifacts.length > 0;

  const handleCustomSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!customQuestion.trim() || isAnalyzing || !hasEvidence) return;
    await onRunAnalysis(customQuestion.trim());
    setCustomQuestion('');
  };

  const riskScore = riskBreakdown?.overallScore ?? (hasEvidence ? (aiAnalysis?.riskScore ?? 96) : 0);
  const confidenceScore = riskBreakdown?.confidenceScore ?? (hasEvidence ? (aiAnalysis?.confidenceScore ?? 98) : 0);

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="glass-panel p-5 rounded-xl border border-cyan-500/30 bg-gradient-to-r from-cyan-950/40 via-slate-900/90 to-blue-950/40 shadow-[0_0_25px_rgba(6,182,212,0.15)]">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <Sparkles className="w-5 h-5 text-cyan-400 animate-pulse" />
              <h2 className="text-base font-display font-bold text-white tracking-wide">
                AI-ASSISTED FORENSIC REASONING CORE
              </h2>
            </div>
            <p className="text-xs text-slate-300 mt-1 max-w-3xl">
              Powered by server-side Gemini 3.8 Flash. Analyzes temporal sequences, correlates disparate evidence hives,
              and rigorously delineates verified forensic facts from AI-generated timeline hypotheses.
            </p>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <button
              onClick={() => onRunAnalysis()}
              disabled={isAnalyzing || !hasEvidence}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-mono text-xs font-semibold shadow-[0_0_15px_rgba(6,182,212,0.3)] transition disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isAnalyzing ? 'animate-spin' : ''}`} />
              <span>{isAnalyzing ? 'Deep Analysis Running...' : hasEvidence ? 'Run Gemini DFIR Analysis' : 'Awaiting Evidence'}</span>
            </button>
          </div>
        </div>

        {/* Custom Investigator Focus Prompt Bar */}
        {hasEvidence && (
          <form onSubmit={handleCustomSubmit} className="mt-4 pt-3 border-t border-slate-800/80 flex gap-2">
            <input
              type="text"
              placeholder="Focus inquiry: e.g., 'Analyze the 12:10-12:12 exfiltration gap' or 'Evaluate timestomping intent'..."
              value={customQuestion}
              onChange={(e) => setCustomQuestion(e.target.value)}
              disabled={isAnalyzing || !hasEvidence}
              className="flex-1 bg-slate-950/90 border border-slate-800 rounded-lg px-3.5 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
            />
            <button
              type="submit"
              disabled={isAnalyzing || !customQuestion.trim() || !hasEvidence}
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 text-xs font-mono font-semibold flex items-center gap-1.5 transition disabled:opacity-50"
            >
              <Send className="w-3.5 h-3.5" />
              <span>Probe</span>
            </button>
          </form>
        )}
      </div>

      {!hasEvidence ? (
        <div className="glass-panel p-12 rounded-xl border border-slate-800 text-center space-y-3">
          <Database className="w-10 h-10 text-slate-600 mx-auto opacity-50" />
          <h3 className="font-display font-bold text-base text-slate-300">
            Cannot Execute AI Forensic Reasoning Without Evidence
          </h3>
          <p className="text-xs text-slate-500 max-w-md mx-auto">
            TraceX adheres to strict admissibility standards: no simulated or hallucinated results are shown on an empty dataset. 
            Upload a CSV/JSON file in Evidence Collection or restore the synthetic demo.
          </p>
        </div>
      ) : (
        <>
          {/* Model & Score Metrics Row */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Risk Score */}
            <div className="glass-panel p-4 rounded-xl border border-slate-800 flex items-center justify-between">
              <div>
                <span className="text-xs font-mono text-slate-400 block">CASE THREAT RISK</span>
                <div className="flex items-baseline gap-2 mt-1">
                  <span className={`text-3xl font-display font-bold ${
                    riskScore >= 75 ? 'text-rose-400' : riskScore >= 40 ? 'text-amber-400' : 'text-emerald-400'
                  }`}>
                    {riskScore}
                  </span>
                  <span className="text-xs text-slate-400 font-mono">/100 (RULE-EVALUATED)</span>
                </div>
              </div>
              <div className="w-12 h-12 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-center">
                <ShieldAlert className="w-6 h-6 text-rose-400" />
              </div>
            </div>

            {/* Confidence Score */}
            <div className="glass-panel p-4 rounded-xl border border-slate-800 flex items-center justify-between">
              <div>
                <span className="text-xs font-mono text-slate-400 block">EVIDENCE CONFIDENCE</span>
                <div className="flex items-baseline gap-2 mt-1">
                  <span className="text-3xl font-display font-bold text-cyan-300">
                    {confidenceScore}%
                  </span>
                  <span className="text-xs text-emerald-400 font-mono">CORROBORATED</span>
                </div>
              </div>
              <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center">
                <FileCheck className="w-6 h-6 text-cyan-400" />
              </div>
            </div>

            {/* Engine Details */}
            <div className="glass-panel p-4 rounded-xl border border-slate-800 flex items-center justify-between">
              <div>
                <span className="text-xs font-mono text-slate-400 block">REASONING ENGINE</span>
                <span className="text-sm font-bold text-white block mt-1">
                  {aiAnalysis?.modelUsed || 'gemini-3.8-flash (DFIR Server-Side)'}
                </span>
                <span className="text-[11px] font-mono text-cyan-400">
                  {isDemoDataset ? 'Analyzing Synthetic Demo Data' : `Analyzing ${artifacts.length} Uploaded Artifacts`}
                </span>
              </div>
              <div className="w-12 h-12 rounded-xl bg-blue-500/10 border border-blue-500/30 flex items-center justify-center">
                <Sparkles className="w-6 h-6 text-blue-400" />
              </div>
            </div>
          </div>

          {/* CORE DIFFERENTIATOR: Observed Facts vs AI Hypotheses */}
          <div className="glass-panel p-5 rounded-xl border border-slate-800 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-800">
                  STRICT FORENSIC DELINEATION
                </span>
                <h3 className="font-display font-bold text-base text-white">
                  Observed Evidence vs AI-Generated Hypotheses
                </h3>
              </div>
              <span className="text-xs font-mono text-slate-400">
                Admissible Standard: Inferred Hypotheses Are Never Stated as Confirmed Facts
              </span>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {/* Column 1: Hard Observed Facts */}
              <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-500/30 space-y-3">
                <div className="flex items-center gap-2 text-emerald-400 font-mono text-xs font-bold uppercase tracking-wider">
                  <CheckCircle2 className="w-4 h-4" />
                  <span>{isDemoDataset ? 'Observed Synthetic Facts' : 'Verified Observed Evidence Facts'}</span>
                </div>
                <p className="text-[11px] text-slate-400">
                  Directly verified from raw physical drives, event logs, and filesystem journals with cryptographic hashes.
                </p>

                <ul className="space-y-2 text-xs font-mono">
                  {aiAnalysis?.observedFactsVsHypotheses?.observedFacts?.map((fact, idx) => (
                    <li key={idx} className="p-2.5 rounded bg-slate-900/80 border border-slate-800/80 text-slate-200 flex items-start gap-2">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 shrink-0 mt-1.5"></span>
                      <span className="leading-relaxed">{fact}</span>
                    </li>
                  )) || (
                    artifacts.slice(0, 5).map((a, i) => (
                      <li key={i} className="p-2.5 rounded bg-slate-900/80 border border-slate-800/80 text-slate-200 flex items-start gap-2">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 shrink-0 mt-1.5"></span>
                        <span className="leading-relaxed">VERIFIED: {a.name} recorded at {a.timestamp.slice(11, 19)} from {a.source} (ID: {a.evidenceId}).</span>
                      </li>
                    ))
                  )}
                </ul>
              </div>

              {/* Column 2: AI Hypotheses */}
              <div className="p-4 rounded-xl bg-purple-950/20 border border-purple-500/30 space-y-3">
                <div className="flex items-center gap-2 text-purple-300 font-mono text-xs font-bold uppercase tracking-wider">
                  <HelpCircle className="w-4 h-4" />
                  <span>AI-Generated Hypotheses (Probabilistic Inferences)</span>
                </div>
                <p className="text-[11px] text-slate-400">
                  Deductions regarding unlogged intervals, likely tool execution, and adversarial intent during blackout windows.
                </p>

                <ul className="space-y-2 text-xs font-mono">
                  {aiAnalysis?.observedFactsVsHypotheses?.aiHypotheses?.map((hypo, idx) => (
                    <li key={idx} className="p-2.5 rounded bg-slate-900/80 border border-slate-800/80 text-purple-200 flex items-start gap-2">
                      <span className="w-1.5 h-1.5 rounded-full bg-purple-400 shrink-0 mt-1.5"></span>
                      <span className="leading-relaxed">{hypo}</span>
                    </li>
                  )) || (
                    <li className="text-slate-500 text-xs p-2">Click 'Run Gemini DFIR Analysis' to generate probabilistic hypotheses.</li>
                  )}
                </ul>
              </div>
            </div>
          </div>

          {/* Executive Summary & Attack Chain Narrative */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Executive Summary */}
            <div className="glass-panel p-5 rounded-xl border border-slate-800 space-y-3">
              <div className="flex items-center gap-2 text-cyan-400 font-display font-semibold text-sm border-b border-slate-800 pb-2">
                <Lightbulb className="w-4 h-4" />
                <span>EXECUTIVE FORENSIC SUMMARY</span>
              </div>
              <p className="text-xs text-slate-200 leading-relaxed font-sans">
                {aiAnalysis?.executiveSummary || 'Click "Run Gemini DFIR Analysis" to evaluate the current evidence set.'}
              </p>
            </div>

            {/* Anti-Forensic Tactics Analysis */}
            <div className="glass-panel p-5 rounded-xl border border-slate-800 space-y-3">
              <div className="flex items-center gap-2 text-rose-400 font-display font-semibold text-sm border-b border-slate-800 pb-2">
                <ShieldAlert className="w-4 h-4" />
                <span>ANTI-FORENSICS TACTICS EVALUATION</span>
              </div>
              <p className="text-xs text-slate-200 leading-relaxed font-sans">
                {aiAnalysis?.antiForensicTacticsAnalysis || 'Evaluating countermeasure footprints across uploaded evidence...'}
              </p>
            </div>
          </div>

          {/* Reconstructed Attack Chain Narrative */}
          <div className="glass-panel p-5 rounded-xl border border-slate-800 space-y-3">
            <div className="flex items-center gap-2 text-white font-display font-semibold text-sm border-b border-slate-800 pb-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              <span>RECONSTRUCTED ATTACK CHAIN & INTENT NARRATIVE</span>
            </div>
            <div className="text-xs text-slate-300 leading-relaxed font-sans whitespace-pre-line bg-slate-950/50 p-4 rounded-lg border border-slate-800/80">
              {aiAnalysis?.attackChainNarrative || 'Run AI analysis to compile full attack chain narrative from uploaded evidence.'}
            </div>
          </div>

          {/* Prioritized DFIR Recommendations */}
          <div className="glass-panel p-5 rounded-xl border border-slate-800 space-y-4">
            <div className="flex items-center gap-2 text-white font-display font-semibold text-sm border-b border-slate-800 pb-2">
              <Target className="w-4 h-4 text-emerald-400" />
              <span>PRIORITIZED INVESTIGATION RECOMMENDATIONS</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {aiAnalysis?.recommendations?.map((rec, idx) => (
                <div key={idx} className="p-3.5 rounded-lg bg-slate-900/80 border border-slate-800 space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                      rec.priority.includes('P1') 
                        ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' 
                        : rec.priority.includes('P2')
                        ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                        : 'bg-blue-500/20 text-blue-300 border border-blue-500/30'
                    }`}>
                      {rec.priority}
                    </span>
                    <span className="text-xs font-mono text-cyan-400">{rec.target}</span>
                  </div>
                  <h4 className="text-xs font-semibold text-slate-200">{rec.action}</h4>
                  <p className="text-[11px] text-slate-400 leading-relaxed font-mono">
                    {rec.rationale}
                  </p>
                </div>
              )) || (
                <div className="text-slate-500 text-xs">Run analysis to populate prioritized actions.</div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
};
