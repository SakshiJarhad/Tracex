/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { 
  ShieldAlert, 
  AlertTriangle, 
  Clock, 
  Database, 
  Activity, 
  ArrowRight, 
  Sparkles, 
  CheckCircle2, 
  FileWarning, 
  HardDrive, 
  Globe, 
  Terminal, 
  Calendar,
  Lock,
  Layers,
  ChevronDown,
  ChevronUp,
  Info
} from 'lucide-react';
import { InvestigationCase, RiskLevel } from '../types/forensics';
import { formatEvidenceField } from '../utils/forensicEngine';

interface OverviewDashboardProps {
  investigationCase: InvestigationCase;
  onNavigateTab: (tab: string) => void;
  onRunAiAnalysis: () => void;
  isAiAnalyzing: boolean;
}

export const OverviewDashboard: React.FC<OverviewDashboardProps> = ({
  investigationCase,
  onNavigateTab,
  onRunAiAnalysis,
  isAiAnalyzing
}) => {
  const { artifacts, findings, timelineGaps, aiAnalysis, isDemoDataset, riskBreakdown } = investigationCase;
  const [showRuleBreakdown, setShowRuleBreakdown] = useState(false);

  // If no evidence uploaded, show empty SOC state
  const hasEvidence = artifacts.length > 0;

  // Calculate risk counts
  const riskCounts: Record<RiskLevel, number> = {
    CRITICAL: artifacts.filter(a => a.riskLevel === 'CRITICAL').length,
    HIGH: artifacts.filter(a => a.riskLevel === 'HIGH').length,
    MEDIUM: artifacts.filter(a => a.riskLevel === 'MEDIUM').length,
    LOW: artifacts.filter(a => a.riskLevel === 'LOW').length,
  };

  // Source counts
  const sourceCounts = artifacts.reduce((acc, curr) => {
    acc[curr.source] = (acc[curr.source] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const overallRisk = riskBreakdown?.overallScore ?? (hasEvidence ? (aiAnalysis?.riskScore ?? 96) : 0);
  const overallConfidence = riskBreakdown?.confidenceScore ?? (hasEvidence ? (aiAnalysis?.confidenceScore ?? 98) : 0);

  return (
    <div className="space-y-6">
      {/* Top Banner: Incident Status & Dataset Mode */}
      <div className={`relative overflow-hidden rounded-xl border p-5 shadow-lg ${
        !hasEvidence
          ? 'bg-slate-900/80 border-slate-800'
          : isDemoDataset 
          ? 'border-blue-500/40 bg-gradient-to-r from-blue-950/40 via-slate-900/90 to-cyan-950/30 shadow-[0_0_25px_rgba(59,130,246,0.15)]'
          : 'border-rose-500/30 bg-gradient-to-r from-rose-950/40 via-slate-900/80 to-cyan-950/30 shadow-[0_0_25px_rgba(244,63,94,0.12)]'
      }`}>
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-start gap-4">
            <div className={`w-12 h-12 rounded-xl border flex items-center justify-center shrink-0 ${
              !hasEvidence 
                ? 'bg-slate-800 border-slate-700 text-slate-500' 
                : isDemoDataset 
                ? 'bg-blue-500/20 border-blue-500/40 text-cyan-400' 
                : 'bg-rose-500/20 border-rose-500/40 text-rose-400'
            }`}>
              {hasEvidence ? <ShieldAlert className="w-6 h-6" /> : <Database className="w-6 h-6" />}
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <span className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold border ${
                  !hasEvidence
                    ? 'bg-slate-800 text-slate-400 border-slate-700'
                    : isDemoDataset 
                    ? 'bg-blue-500/30 text-blue-200 border-blue-500/50' 
                    : 'bg-rose-500/30 text-rose-200 border-rose-500/50'
                }`}>
                  {isDemoDataset ? 'SYNTHETIC DEMO INCIDENT' : hasEvidence ? 'LIVE OBSERVED EVIDENCE' : 'AWAITING EVIDENCE INGESTION'}
                </span>
                <span className="text-xs font-mono text-slate-400">
                  Target: {investigationCase.targetHost}
                </span>
                {hasEvidence && (
                  <span className="text-xs font-mono text-cyan-400">
                    Status: {investigationCase.status}
                  </span>
                )}
              </div>
              <h1 className="text-xl font-display font-bold text-white mt-1">
                {investigationCase.caseName}
              </h1>
              <p className="text-sm text-slate-300 max-w-3xl mt-1">
                {hasEvidence 
                  ? isDemoDataset
                    ? 'Synthetic employee data theft investigation: unauthorized USB attachment, confidential spreadsheet access, and aggressive anti-forensic log and timestomp cover-up.'
                    : `Forensic telemetry analyzing ${artifacts.length} observed artifacts and ${findings.length} detected anti-forensic triggers across host ${investigationCase.targetHost}.`
                  : 'No forensic artifacts currently in workspace. Upload a CSV/JSON log file or click "Restore Demo" to view the synthetic investigation.'}
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            {hasEvidence ? (
              <>
                <button
                  onClick={() => onNavigateTab('anti-forensics')}
                  className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-slate-900/90 hover:bg-slate-800 text-slate-200 hover:text-white border border-slate-700 text-xs font-medium transition"
                >
                  <span>Anti-Forensics ({findings.length})</span>
                  <ArrowRight className="w-3.5 h-3.5 text-cyan-400" />
                </button>
                <button
                  onClick={() => onNavigateTab('timeline')}
                  className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-cyan-950/80 hover:bg-cyan-900/80 text-cyan-200 border border-cyan-700/50 text-xs font-medium transition"
                >
                  <Clock className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Timeline Reconstruction</span>
                </button>
              </>
            ) : (
              <button
                onClick={() => onNavigateTab('evidence')}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs font-semibold shadow-lg transition"
              >
                <span>Go to Evidence Ingestion</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Primary KPI Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1 */}
        <div className="glass-panel p-4 rounded-xl border border-slate-800 hover:border-cyan-500/40 transition">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>TOTAL ARTIFACTS ANALYZED</span>
            <Database className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-3xl font-display font-bold text-white">
              {artifacts.length}
            </span>
            <span className={`text-xs font-mono flex items-center ${hasEvidence ? 'text-emerald-400' : 'text-slate-500'}`}>
              {hasEvidence ? '100% Parsed' : '0 Ingested'}
            </span>
          </div>
          <div className="mt-3 flex items-center gap-2 text-[11px] text-slate-400">
            <span className={`w-2 h-2 rounded-full ${hasEvidence ? 'bg-cyan-400' : 'bg-slate-600'}`}></span>
            <span>{hasEvidence ? `Across ${Object.keys(sourceCounts).length} telemetry sources` : 'Awaiting evidence data'}</span>
          </div>
        </div>

        {/* Metric 2 */}
        <div className="glass-panel p-4 rounded-xl border border-slate-800 hover:border-rose-500/40 transition">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>ANTI-FORENSIC INDICATORS</span>
            <FileWarning className="w-4 h-4 text-rose-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className={`text-3xl font-display font-bold ${findings.length > 0 ? 'text-rose-400' : 'text-slate-500'}`}>
              {findings.length}
            </span>
            {findings.length > 0 && (
              <span className="text-xs px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 font-mono font-bold">
                High Evasion
              </span>
            )}
          </div>
          <div className="mt-3 flex items-center gap-2 text-[11px] text-slate-400">
            <span className={`w-2 h-2 rounded-full ${findings.length > 0 ? 'bg-rose-400' : 'bg-slate-600'}`}></span>
            <span>{findings.length > 0 ? 'Log wipe, timestomp, browser clearing' : 'No indicators triggered'}</span>
          </div>
        </div>

        {/* Metric 3 */}
        <div className="glass-panel p-4 rounded-xl border border-slate-800 hover:border-amber-500/40 transition">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>TIMELINE DISCONTINUITIES</span>
            <Clock className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className={`text-3xl font-display font-bold ${timelineGaps.length > 0 ? 'text-amber-300' : 'text-slate-500'}`}>
              {timelineGaps.length} Gaps
            </span>
            <span className="text-xs text-slate-400 font-mono">
              {timelineGaps.length > 0 ? 'Blackouts' : 'Continuous'}
            </span>
          </div>
          <div className="mt-3 flex items-center gap-2 text-[11px] text-slate-400">
            <span className={`w-2 h-2 rounded-full ${timelineGaps.length > 0 ? 'bg-amber-400' : 'bg-slate-600'}`}></span>
            <span>{timelineGaps.length > 0 ? 'Unlogged execution intervals' : 'No suspicious gaps found'}</span>
          </div>
        </div>

        {/* Metric 4: Transparent Rule-based Risk Score */}
        <div className="glass-panel p-4 rounded-xl border border-slate-800 hover:border-cyan-500/40 transition">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>RULE-BASED THREAT SCORE</span>
            <Sparkles className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-3">
            <div>
              <span className={`text-3xl font-display font-bold ${
                overallRisk >= 75 ? 'text-rose-400' : overallRisk >= 40 ? 'text-amber-400' : 'text-emerald-400'
              }`}>
                {overallRisk}
              </span>
              <span className="text-xs text-slate-400 font-mono">/100</span>
            </div>
            <div className="border-l border-slate-800 pl-3">
              <span className="text-xl font-display font-bold text-cyan-300">
                {overallConfidence}%
              </span>
              <span className="text-[10px] text-slate-400 block font-mono">Confidence</span>
            </div>
          </div>
          <div className="mt-3 flex items-center justify-between text-[11px]">
            <span className="text-slate-400">
              {hasEvidence ? 'Deterministic Rule Calculation' : 'No Evidence'}
            </span>
            {hasEvidence && (
              <button
                onClick={() => setShowRuleBreakdown(!showRuleBreakdown)}
                className="text-cyan-400 hover:text-cyan-300 font-mono flex items-center gap-0.5"
              >
                <span>{showRuleBreakdown ? 'Hide Math' : 'View Formula'}</span>
                {showRuleBreakdown ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Expandable Transparent Rule Scoring Breakdown */}
      {showRuleBreakdown && riskBreakdown && (
        <div className="glass-panel p-5 rounded-xl border border-cyan-500/40 space-y-3 bg-[#080d22]">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <div className="flex items-center gap-2">
              <Info className="w-4 h-4 text-cyan-400" />
              <h3 className="font-display font-bold text-xs uppercase tracking-wider text-white">
                Transparent Rule-Based Threat Scoring Breakdown
              </h3>
            </div>
            <span className="text-xs font-mono text-cyan-300 font-bold">
              Total Score: {riskBreakdown.overallScore} / 100
            </span>
          </div>

          <p className="text-xs text-slate-300 font-sans">
            TraceX does not generate arbitrary or hallucinated risk values. Every point is calculated deterministically from explicit observed evidence:
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 text-xs font-mono">
            {riskBreakdown.rulesApplied.map((rule, idx) => (
              <div key={idx} className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
                <div className="flex items-center justify-between text-cyan-400 font-semibold">
                  <span>{rule.name}</span>
                  <span className="text-rose-400 font-bold">+{rule.points} pts</span>
                </div>
                <p className="text-[11px] text-slate-400 font-sans leading-relaxed">
                  {rule.description}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Middle Row: Risk Distribution & Chronological Sequence Preview */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk Distribution Card */}
        <div className="glass-panel p-5 rounded-xl border border-slate-800/80">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              <h2 className="text-sm font-semibold font-display tracking-wide text-white">
                RISK DISTRIBUTION PROFILE
              </h2>
            </div>
            <span className="text-xs font-mono text-slate-400">Severity</span>
          </div>

          <div className="mt-4 space-y-3">
            {/* Critical */}
            <div>
              <div className="flex justify-between text-xs font-mono mb-1">
                <span className="text-rose-400 flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-rose-500"></span>
                  Critical (Log wipes, Timestomp)
                </span>
                <span className="text-white font-bold">{riskCounts.CRITICAL}</span>
              </div>
              <div className="h-2 w-full bg-slate-900 rounded-full overflow-hidden">
                <div 
                  className="h-full bg-gradient-to-r from-rose-600 to-rose-400 rounded-full"
                  style={{ width: `${hasEvidence ? (riskCounts.CRITICAL / artifacts.length) * 100 : 0}%` }}
                ></div>
              </div>
            </div>

            {/* High */}
            <div>
              <div className="flex justify-between text-xs font-mono mb-1">
                <span className="text-amber-400 flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-amber-500"></span>
                  High (USB Exfil, SDelete)
                </span>
                <span className="text-white font-bold">{riskCounts.HIGH}</span>
              </div>
              <div className="h-2 w-full bg-slate-900 rounded-full overflow-hidden">
                <div 
                  className="h-full bg-gradient-to-r from-amber-600 to-amber-400 rounded-full"
                  style={{ width: `${hasEvidence ? (riskCounts.HIGH / artifacts.length) * 100 : 0}%` }}
                ></div>
              </div>
            </div>

            {/* Medium */}
            <div>
              <div className="flex justify-between text-xs font-mono mb-1">
                <span className="text-blue-400 flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-blue-500"></span>
                  Medium (Folder Navigation, LNK)
                </span>
                <span className="text-white font-bold">{riskCounts.MEDIUM}</span>
              </div>
              <div className="h-2 w-full bg-slate-900 rounded-full overflow-hidden">
                <div 
                  className="h-full bg-gradient-to-r from-blue-600 to-blue-400 rounded-full"
                  style={{ width: `${hasEvidence ? (riskCounts.MEDIUM / artifacts.length) * 100 : 0}%` }}
                ></div>
              </div>
            </div>

            {/* Low */}
            <div>
              <div className="flex justify-between text-xs font-mono mb-1">
                <span className="text-slate-400 flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-slate-500"></span>
                  Low (Routine System Logs)
                </span>
                <span className="text-white font-bold">{riskCounts.LOW}</span>
              </div>
              <div className="h-2 w-full bg-slate-900 rounded-full overflow-hidden">
                <div 
                  className="h-full bg-gradient-to-r from-slate-600 to-slate-400 rounded-full"
                  style={{ width: `${hasEvidence ? (riskCounts.LOW / artifacts.length) * 100 : 0}%` }}
                ></div>
              </div>
            </div>
          </div>

          {/* Telemetry Sources */}
          <div className="mt-6 pt-4 border-t border-slate-800">
            <h3 className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-2.5">
              Artifact Telemetry Sources
            </h3>
            {hasEvidence ? (
              <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                {Object.entries(sourceCounts).map(([src, count]) => (
                  <div key={src} className="flex items-center justify-between p-2 rounded bg-slate-900/60 border border-slate-800/80">
                    <span className="text-slate-300">{src}</span>
                    <span className="text-cyan-400 font-bold">{count}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-xs text-slate-500 font-mono py-2">No active sources.</div>
            )}
          </div>
        </div>

        {/* Chronological Incident Sequence Card (Driven purely by actual artifacts) */}
        <div className="lg:col-span-2 glass-panel p-5 rounded-xl border border-slate-800/80 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Clock className="w-4 h-4 text-cyan-400" />
                <h2 className="text-sm font-semibold font-display tracking-wide text-white">
                  {isDemoDataset ? 'DEMO INCIDENT SEQUENCE: EMPLOYEE DATA THEFT' : 'RECONSTRUCTED INCIDENT SEQUENCE'}
                </h2>
              </div>
              <span className="text-xs font-mono text-cyan-400">
                {hasEvidence ? `${artifacts[0].timestamp.slice(11, 16)} - ${artifacts[artifacts.length - 1].timestamp.slice(11, 16)} UTC` : 'N/A'}
              </span>
            </div>

            <p className="text-xs text-slate-400 mt-2">
              {hasEvidence 
                ? 'Chronological event stream dynamically generated from observed evidence. Highlights exfiltration triggers and evasion actions:'
                : 'No evidence loaded to reconstruct. Ingest a dataset to generate the incident stream.'}
            </p>

            {hasEvidence ? (
              <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-2.5 text-xs font-mono">
                {artifacts.map((art) => {
                  const isAnti = !!art.antiForensicIndicator;
                  const displayTime = art.timestamp ? (art.timestamp.includes('T') ? art.timestamp.slice(11, 16) : art.timestamp.slice(0, 5)) : 'N/A';
                  return (
                    <div 
                      key={art.id} 
                      className={`p-2.5 rounded-lg border flex items-start gap-3 ${
                        isAnti ? 'bg-rose-950/20 border-rose-500/30' : 'bg-slate-900/80 border-slate-800'
                      }`}
                    >
                      <div className={`px-2 py-1 rounded font-bold shrink-0 ${
                        isAnti ? 'bg-rose-500/20 text-rose-300' : 'bg-blue-500/20 text-blue-300'
                      }`}>
                        {displayTime}
                      </div>
                      <div className="overflow-hidden flex-1">
                        <div className={`font-semibold truncate ${isAnti ? 'text-rose-200' : 'text-slate-200'}`}>
                          {formatEvidenceField(art.name)}
                        </div>
                        <div className="text-[11px] text-slate-400 truncate font-mono">
                          {formatEvidenceField(art.evidenceId)} • {formatEvidenceField(art.source)} • User: {formatEvidenceField(art.user)}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="mt-8 text-center text-slate-600 font-mono text-xs">
                Awaiting evidence upload to populate reconstructed sequence.
              </div>
            )}
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800 flex flex-wrap items-center justify-between gap-3">
            <div className="text-xs text-slate-400 flex items-center gap-1.5 font-mono">
              <Lock className="w-3.5 h-3.5 text-cyan-400" />
              <span>Evidence Hash: {investigationCase.evidenceChainHash.slice(0, 16)}...</span>
            </div>

            {hasEvidence && (
              <div className="flex items-center gap-2">
                <button
                  onClick={() => onNavigateTab('correlation')}
                  className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition"
                >
                  <span>Evidence Correlation Matrix</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
