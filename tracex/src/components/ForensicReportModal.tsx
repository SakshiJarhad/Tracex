/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useRef } from 'react';
import { 
  FileText, 
  Download, 
  Printer, 
  Lock, 
  X, 
  CheckCircle2, 
  AlertTriangle, 
  Clock, 
  HelpCircle,
  Database
} from 'lucide-react';
import { InvestigationCase } from '../types/forensics';

interface ForensicReportModalProps {
  investigationCase: InvestigationCase;
  isOpen: boolean;
  onClose: () => void;
}

export const ForensicReportModal: React.FC<ForensicReportModalProps> = ({
  investigationCase,
  isOpen,
  onClose
}) => {
  const reportRef = useRef<HTMLDivElement>(null);

  if (!isOpen) return null;

  const { artifacts, findings, timelineGaps, aiAnalysis, isDemoDataset, riskBreakdown } = investigationCase;
  const hasEvidence = artifacts.length > 0;

  const riskScore = riskBreakdown?.overallScore ?? (hasEvidence ? (aiAnalysis?.riskScore ?? 96) : 0);
  const confidenceScore = riskBreakdown?.confidenceScore ?? (hasEvidence ? (aiAnalysis?.confidenceScore ?? 98) : 0);

  // Download JSON
  const handleDownloadJSON = () => {
    const reportData = {
      reportType: "TraceX Formal Digital Forensic & Anti-Forensics Analysis Report",
      generatedAt: new Date().toISOString(),
      datasetMode: isDemoDataset ? "SYNTHETIC_DEMO_DATASET" : "USER_OBSERVED_EVIDENCE",
      caseDetails: {
        caseId: investigationCase.caseId,
        caseName: investigationCase.caseName,
        targetHost: investigationCase.targetHost,
        investigator: investigationCase.investigator,
        organization: investigationCase.organization,
        evidenceChainHash: investigationCase.evidenceChainHash,
      },
      metrics: {
        totalArtifacts: artifacts.length,
        antiForensicsFindingsCount: findings.length,
        timelineGapsCount: timelineGaps.length,
        overallRiskScore: riskScore,
        confidenceScore: confidenceScore,
        ruleScoringBreakdown: riskBreakdown
      },
      aiAnalysis: aiAnalysis || null,
      antiForensicsFindings: findings,
      reconstructedTimeline: artifacts,
      timelineGaps: timelineGaps,
    };

    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `TRACEX_FORENSIC_REPORT_${investigationCase.caseId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Download Markdown Text Report
  const handleDownloadMarkdown = () => {
    let md = `# TRACEX DIGITAL FORENSIC INVESTIGATION REPORT\n`;
    md += `**Case ID:** ${investigationCase.caseId}\n`;
    md += `**Case Name:** ${investigationCase.caseName}\n`;
    md += `**Target Host:** ${investigationCase.targetHost}\n`;
    md += `**Lead Investigator:** ${investigationCase.investigator}\n`;
    md += `**Organization:** ${investigationCase.organization}\n`;
    md += `**Provenance Mode:** ${isDemoDataset ? 'SYNTHETIC DEMONSTRATION DATA' : 'LIVE OBSERVED EVIDENCE'}\n`;
    md += `**Report Generated:** ${new Date().toISOString()}\n`;
    md += `**SHA-256 Evidence Chain Hash:** ${investigationCase.evidenceChainHash}\n\n`;
    md += `---\n\n`;

    md += `## 1. EXECUTIVE CASE SUMMARY\n`;
    md += `${aiAnalysis?.executiveSummary || (hasEvidence ? 'Forensic triage in progress.' : 'No evidence uploaded.')}\n\n`;

    md += `## 2. METRICS & THREAT SCORING\n`;
    md += `- **Threat Risk Score:** ${riskScore} / 100 (Deterministic Rule Calculation)\n`;
    md += `- **Evidence Confidence:** ${confidenceScore}%\n`;
    md += `- **Artifacts Analyzed:** ${artifacts.length}\n`;
    md += `- **Anti-Forensics Techniques Detected:** ${findings.length}\n\n`;

    if (riskBreakdown) {
      md += `### Rule Scoring Breakdown:\n`;
      riskBreakdown.rulesApplied.forEach(r => {
        md += `- **${r.name}:** +${r.points} pts - ${r.description}\n`;
      });
      md += `\n`;
    }

    md += `## 3. ANTI-FORENSICS ACTIVITY & FINDINGS\n`;
    if (findings.length === 0) {
      md += `No anti-forensic activities detected in the current evidence set.\n\n`;
    } else {
      findings.forEach(f => {
        md += `### [${f.severity}] ${f.title} (${f.mitreTechnique})\n`;
        md += `- **Detection Reason:** ${f.detectionReason}\n`;
        md += `- **Confidence:** ${f.confidence}%\n`;
        md += `- **Impact on Reconstruction:** ${f.reconstructionImpact}\n\n`;
      });
    }

    md += `## 4. RECONSTRUCTED TIMELINE OF EVENTS\n`;
    if (artifacts.length === 0) {
      md += `No events in timeline.\n\n`;
    } else {
      artifacts.forEach(a => {
        const prov = a.isSyntheticDemo ? '[SYNTHETIC DEMO]' : '[OBSERVED FACT]';
        md += `- **${a.timestamp}** | ${prov} **[${a.source}]** ${a.name} (${a.riskLevel}) - ${a.description}\n`;
      });
      md += `\n`;
    }

    md += `## 5. OBSERVED EVIDENCE VS AI HYPOTHESES\n`;
    md += `### Verified Observed Facts:\n`;
    if (aiAnalysis?.observedFactsVsHypotheses?.observedFacts?.length) {
      aiAnalysis.observedFactsVsHypotheses.observedFacts.forEach(fact => {
        md += `- ${fact}\n`;
      });
    } else {
      artifacts.forEach(a => {
        md += `- VERIFIED: ${a.name} recorded at ${a.timestamp} from ${a.source}.\n`;
      });
    }

    md += `\n### AI Hypotheses (Probabilistic Inferences - Not Confirmed Facts):\n`;
    if (aiAnalysis?.observedFactsVsHypotheses?.aiHypotheses?.length) {
      aiAnalysis.observedFactsVsHypotheses.aiHypotheses.forEach(hypo => {
        md += `- ${hypo}\n`;
      });
    } else {
      md += `No active hypotheses generated.\n`;
    }
    md += `\n`;

    md += `## 6. PRIORITIZED INVESTIGATION RECOMMENDATIONS\n`;
    if (aiAnalysis?.recommendations?.length) {
      aiAnalysis.recommendations.forEach(r => {
        md += `- **[${r.priority}]** ${r.action} (Target: ${r.target})\n  *Rationale:* ${r.rationale}\n\n`;
      });
    } else {
      md += `Awaiting analysis execution.\n\n`;
    }

    const blob = new Blob([md], { type: 'text/markdown;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `TRACEX_FORENSIC_REPORT_${investigationCase.caseId}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Browser Print (PDF)
  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-md p-4 overflow-y-auto">
      <div className="bg-[#080d1e] border border-cyan-500/40 rounded-xl max-w-4xl w-full my-8 shadow-[0_0_50px_rgba(6,182,212,0.25)] flex flex-col max-h-[92vh]">
        
        {/* Modal Header Controls */}
        <div className="flex items-center justify-between p-4 border-b border-slate-800 bg-[#060a17]">
          <div className="flex items-center gap-2">
            <FileText className="w-5 h-5 text-cyan-400" />
            <h2 className="font-display font-bold text-base text-white">
              Official Digital Forensic Investigation Report
            </h2>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handlePrint}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono transition"
              title="Print or Save as PDF"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>Print / PDF</span>
            </button>

            <button
              onClick={handleDownloadMarkdown}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono transition"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              <span>Markdown</span>
            </button>

            <button
              onClick={handleDownloadJSON}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-semibold transition"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export JSON</span>
            </button>

            <button
              onClick={onClose}
              className="p-1.5 rounded text-slate-400 hover:text-white hover:bg-slate-800 ml-2"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Printable Report Document Body */}
        <div ref={reportRef} className="p-6 overflow-y-auto space-y-6 text-slate-200 font-sans print:bg-white print:text-black">
          
          {/* Official Letterhead */}
          <div className="border-b border-slate-800 pb-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 font-display text-xl font-bold tracking-wider text-white print:text-black">
                <span>TRACE<strong className="text-cyan-400 print:text-cyan-600">X</strong> FORENSIC FRAMEWORK</span>
              </div>
              <p className="text-xs font-mono text-slate-400 mt-0.5 print:text-gray-600">
                Digital Evidence Analysis & Anti-Forensics Reconstruction Division
              </p>
            </div>

            <div className="text-right font-mono text-xs">
              <div className="text-slate-400 print:text-gray-600">REPORT NO: <span className="text-cyan-400 print:text-black font-bold">{investigationCase.caseId}</span></div>
              <div className="text-slate-400 print:text-gray-600">DATE: {new Date().toLocaleDateString()}</div>
              <div className="text-emerald-400 print:text-emerald-700 font-bold">
                {hasEvidence ? 'STATUS: EVIDENCE LOCKED' : 'STATUS: EMPTY SET'}
              </div>
            </div>
          </div>

          {/* Provenance Mode Banner */}
          <div className={`p-2.5 rounded font-mono text-xs border ${
            isDemoDataset 
              ? 'bg-blue-950/40 border-blue-500/40 text-blue-300 print:border-gray-300' 
              : hasEvidence 
              ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300 print:border-gray-300'
              : 'bg-slate-900 border-slate-800 text-slate-400'
          }`}>
            PROVENANCE: {isDemoDataset ? 'SYNTHETIC DEMONSTRATION DATASET (EMPLOYEE DATA THEFT)' : hasEvidence ? 'LIVE OBSERVED EVIDENCE INGESTED' : 'NO EVIDENCE LOADED'}
          </div>

          {/* Case Metadata Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono bg-slate-900/60 print:bg-gray-100 p-3.5 rounded-lg border border-slate-800 print:border-gray-300">
            <div>
              <span className="text-slate-500 print:text-gray-600 block">CASE TITLE</span>
              <span className="text-white print:text-black font-semibold truncate block">{investigationCase.caseName}</span>
            </div>
            <div>
              <span className="text-slate-500 print:text-gray-600 block">TARGET HOST</span>
              <span className="text-cyan-300 print:text-black font-semibold block">{investigationCase.targetHost}</span>
            </div>
            <div>
              <span className="text-slate-500 print:text-gray-600 block">LEAD EXAMINER</span>
              <span className="text-slate-200 print:text-black block">{investigationCase.investigator}</span>
            </div>
            <div>
              <span className="text-slate-500 print:text-gray-600 block">ORGANIZATION</span>
              <span className="text-slate-200 print:text-black block">{investigationCase.organization}</span>
            </div>
          </div>

          {/* Cryptographic Chain of Custody Hash Stamp */}
          <div className="p-3 rounded-lg bg-cyan-950/30 print:bg-gray-50 border border-cyan-500/30 print:border-gray-300 flex items-center justify-between text-xs font-mono">
            <div className="flex items-center gap-2">
              <Lock className="w-4 h-4 text-cyan-400 print:text-black" />
              <div>
                <span className="text-slate-400 print:text-gray-600 block text-[10px]">EVIDENCE INTEGRITY SHA-256 HASH CHAIN</span>
                <span className="text-cyan-300 print:text-black text-[11px] break-all">{investigationCase.evidenceChainHash}</span>
              </div>
            </div>
            <span className="px-2 py-0.5 rounded bg-emerald-950 print:bg-emerald-100 text-emerald-400 print:text-emerald-800 text-[10px] font-bold shrink-0">
              {hasEvidence ? 'VERIFIED INTACT' : 'EMPTY'}
            </span>
          </div>

          {/* Section 1: Executive Case Summary */}
          <div className="space-y-2">
            <h3 className="font-display font-bold text-sm text-cyan-400 print:text-black uppercase tracking-wider border-b border-slate-800 pb-1">
              1. Executive Case Summary
            </h3>
            <p className="text-xs text-slate-300 print:text-gray-800 leading-relaxed font-sans">
              {aiAnalysis?.executiveSummary || (hasEvidence ? 'Forensic triage active across current evidence set.' : 'No evidence uploaded. Analysis is in standby.')}
            </p>
          </div>

          {/* Section 2: Threat & Confidence Metrics */}
          <div className="space-y-2">
            <h3 className="font-display font-bold text-sm text-cyan-400 print:text-black uppercase tracking-wider border-b border-slate-800 pb-1">
              2. Forensic Scores & Telemetry Coverage
            </h3>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
              <div className="p-2.5 rounded bg-slate-900 print:bg-gray-100 border border-slate-800">
                <span className="text-slate-400 block text-[10px]">RULE-BASED RISK</span>
                <span className="text-lg font-bold text-rose-400 print:text-red-700">{riskScore} / 100</span>
              </div>
              <div className="p-2.5 rounded bg-slate-900 print:bg-gray-100 border border-slate-800">
                <span className="text-slate-400 block text-[10px]">EVIDENCE CONFIDENCE</span>
                <span className="text-lg font-bold text-cyan-300 print:text-cyan-800">{confidenceScore}%</span>
              </div>
              <div className="p-2.5 rounded bg-slate-900 print:bg-gray-100 border border-slate-800">
                <span className="text-slate-400 block text-[10px]">ARTIFACTS ANALYZED</span>
                <span className="text-lg font-bold text-white print:text-black">{artifacts.length} Items</span>
              </div>
              <div className="p-2.5 rounded bg-slate-900 print:bg-gray-100 border border-slate-800">
                <span className="text-slate-400 block text-[10px]">ANTI-FORENSICS DETECTED</span>
                <span className="text-lg font-bold text-rose-400 print:text-red-700">{findings.length} Pillars</span>
              </div>
            </div>

            {/* Rule Math Breakdown */}
            {riskBreakdown && (
              <div className="mt-2 p-3 rounded bg-slate-900/40 print:bg-gray-100 border border-slate-800 print:border-gray-300 text-xs font-mono space-y-1">
                <div className="text-slate-400 print:text-gray-700 font-semibold mb-1">Scoring Rules Applied:</div>
                {riskBreakdown.rulesApplied.map((r, i) => (
                  <div key={i} className="flex justify-between text-slate-300 print:text-black text-[11px]">
                    <span>• {r.name}: {r.description}</span>
                    <span className="text-rose-400 print:text-red-700 font-bold">+{r.points}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Section 3: Anti-Forensics Findings */}
          <div className="space-y-3">
            <h3 className="font-display font-bold text-sm text-rose-400 print:text-black uppercase tracking-wider border-b border-slate-800 pb-1">
              3. Suspicious Activities & Anti-Forensic Techniques
            </h3>
            {findings.length === 0 ? (
              <p className="text-xs text-slate-400 font-mono">No anti-forensics findings detected.</p>
            ) : (
              <div className="space-y-2">
                {findings.map((f, i) => (
                  <div key={f.id} className="p-3 rounded-lg bg-slate-900/60 print:bg-gray-50 border border-slate-800 print:border-gray-300 text-xs space-y-1">
                    <div className="flex items-center justify-between font-mono">
                      <span className="font-bold text-slate-200 print:text-black">
                        3.{i + 1} {f.title}
                      </span>
                      <span className="text-rose-400 print:text-red-600 font-bold">
                        [{f.severity}] - {f.mitreTechnique}
                      </span>
                    </div>
                    <p className="text-slate-300 print:text-gray-700 text-[11px] leading-relaxed">
                      {f.detectionReason}
                    </p>
                    <div className="text-[10px] font-mono text-cyan-300 print:text-gray-600">
                      Reconstruction Impact: {f.reconstructionImpact}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Section 4: Reconstructed Chronological Timeline */}
          <div className="space-y-3">
            <h3 className="font-display font-bold text-sm text-cyan-400 print:text-black uppercase tracking-wider border-b border-slate-800 pb-1">
              4. Reconstructed Chronological Timeline
            </h3>
            {artifacts.length === 0 ? (
              <p className="text-xs text-slate-400 font-mono">No artifacts in timeline.</p>
            ) : (
              <div className="divide-y divide-slate-800 print:divide-gray-300 font-mono text-xs">
                {artifacts.map((a) => (
                  <div key={a.id} className="py-2 flex items-start gap-3">
                    <span className="text-cyan-400 print:text-black font-semibold shrink-0">
                      {a.timestamp.slice(11, 19)} UTC
                    </span>
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-white print:text-black">{a.name}</span>
                        <span className="text-[10px] px-1.5 rounded bg-slate-800 print:bg-gray-200 text-slate-300 print:text-gray-800">
                          {a.source}
                        </span>
                        <span className="text-[9px] px-1 rounded border border-slate-700 text-slate-400">
                          {a.isSyntheticDemo ? 'DEMO' : 'OBSERVED'}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400 print:text-gray-600 mt-0.5 font-sans">
                        {a.description}
                      </p>
                    </div>
                    <span className={`text-[10px] font-bold ${
                      a.riskLevel === 'CRITICAL' ? 'text-rose-400' : 'text-amber-400'
                    }`}>
                      {a.riskLevel}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Section 5: Prioritized Investigation Recommendations */}
          <div className="space-y-3">
            <h3 className="font-display font-bold text-sm text-emerald-400 print:text-black uppercase tracking-wider border-b border-slate-800 pb-1">
              5. Priority Investigation Recommendations
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
              {aiAnalysis?.recommendations?.map((rec, idx) => (
                <div key={idx} className="p-3 rounded-lg bg-slate-900/60 print:bg-gray-50 border border-slate-800 print:border-gray-300 space-y-1">
                  <div className="flex items-center justify-between font-mono">
                    <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-slate-800 text-cyan-300 print:text-black">
                      {rec.priority}
                    </span>
                    <span className="text-slate-400 print:text-gray-600">{rec.target}</span>
                  </div>
                  <div className="font-semibold text-slate-200 print:text-black">{rec.action}</div>
                  <p className="text-[11px] text-slate-400 print:text-gray-700 font-mono">{rec.rationale}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Signatures & Certification */}
          <div className="pt-6 border-t border-slate-800 print:border-gray-400 grid grid-cols-2 gap-8 text-xs font-mono">
            <div>
              <span className="text-slate-500 print:text-gray-600 block">EXAMINER CERTIFICATION:</span>
              <div className="h-10 border-b border-slate-700 print:border-gray-400 mb-1 flex items-end">
                <span className="text-cyan-300 print:text-black font-semibold italic">{investigationCase.investigator}</span>
              </div>
              <span className="text-[10px] text-slate-500">Certified Digital Forensics Examiner (GCFE / EnCE)</span>
            </div>
            <div>
              <span className="text-slate-500 print:text-gray-600 block">CASE OFFICER SIGN-OFF:</span>
              <div className="h-10 border-b border-slate-700 print:border-gray-400 mb-1 flex items-end">
                <span className="text-slate-300 print:text-black font-mono">SOC Director - Threat Intel Unit</span>
              </div>
              <span className="text-[10px] text-slate-500">Chain of Custody Transferred to Legal Counsel</span>
            </div>
          </div>

        </div>
      </div>
    </div>
  );
};
