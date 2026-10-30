/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { DEMO_CASE_EMPLOYEE_THEFT } from './data/forensicDatasets';
import { InvestigationCase, ForensicArtifact } from './types/forensics';
import { 
  detectAntiForensics, 
  reconstructTimelineGaps, 
  computeHash, 
  correlateEvidence, 
  calculateTransparentRiskScore 
} from './utils/forensicEngine';

import { Navbar } from './components/Navbar';
import { OverviewDashboard } from './components/OverviewDashboard';
import { EvidenceCollection } from './components/EvidenceCollection';
import { AntiForensicsModule } from './components/AntiForensicsModule';
import { TimelineReconstruction } from './components/TimelineReconstruction';
import { EvidenceCorrelation } from './components/EvidenceCorrelation';
import { AiAnalysisModule } from './components/AiAnalysisModule';
import { ForensicReportModal } from './components/ForensicReportModal';
import { AiCopilotDrawer } from './components/AiCopilotDrawer';

export default function App() {
  const [currentTab, setCurrentTab] = useState<string>('overview');
  
  // Initialize case with dynamically calculated findings, gaps, correlations, and transparent risk breakdown
  const [investigationCase, setInvestigationCase] = useState<InvestigationCase>(() => {
    const demo = DEMO_CASE_EMPLOYEE_THEFT;
    const dynamicFindings = detectAntiForensics(demo.artifacts);
    const dynamicGaps = reconstructTimelineGaps(demo.artifacts);
    const { links, phases } = correlateEvidence(demo.artifacts, dynamicFindings);
    const riskBreakdown = calculateTransparentRiskScore(demo.artifacts, dynamicFindings, dynamicGaps);
    return {
      ...demo,
      findings: dynamicFindings,
      timelineGaps: dynamicGaps,
      correlations: links,
      phases: phases,
      riskBreakdown: riskBreakdown
    };
  });

  const [isAiAnalyzing, setIsAiAnalyzing] = useState(false);
  const [isReportModalOpen, setIsReportModalOpen] = useState(false);
  const [isCopilotOpen, setIsCopilotOpen] = useState(false);

  // When artifacts are uploaded or modified, recalculate findings, gaps, correlations, risk breakdown, and hash
  const handleUpdateArtifacts = async (newArtifacts: ForensicArtifact[], isDemo: boolean = false) => {
    const updatedFindings = detectAntiForensics(newArtifacts);
    const updatedGaps = reconstructTimelineGaps(newArtifacts);
    const { links, phases } = correlateEvidence(newArtifacts, updatedFindings);
    const riskBreakdown = calculateTransparentRiskScore(newArtifacts, updatedFindings, updatedGaps);
    const newHash = await computeHash(JSON.stringify(newArtifacts));

    setInvestigationCase(prev => ({
      ...prev,
      isDemoDataset: isDemo,
      status: newArtifacts.length === 0 ? 'AWAITING_EVIDENCE' : updatedFindings.length > 0 ? 'ANTI_FORENSICS_FLAGGED' : 'IN_PROGRESS',
      artifacts: newArtifacts,
      findings: updatedFindings,
      timelineGaps: updatedGaps,
      correlations: links,
      phases: phases,
      riskBreakdown: riskBreakdown,
      evidenceChainHash: newHash,
      // If dataset changed and is not the demo, reset previous AI analysis so fake results aren't shown
      aiAnalysis: isDemo ? prev.aiAnalysis : undefined
    }));
  };

  // Reset to default Demo Scenario (Employee data theft)
  const handleResetDemo = () => {
    const demo = DEMO_CASE_EMPLOYEE_THEFT;
    const dynamicFindings = detectAntiForensics(demo.artifacts);
    const dynamicGaps = reconstructTimelineGaps(demo.artifacts);
    const { links, phases } = correlateEvidence(demo.artifacts, dynamicFindings);
    const riskBreakdown = calculateTransparentRiskScore(demo.artifacts, dynamicFindings, dynamicGaps);
    setInvestigationCase({
      ...demo,
      findings: dynamicFindings,
      timelineGaps: dynamicGaps,
      correlations: links,
      phases: phases,
      riskBreakdown: riskBreakdown
    });
  };

  // Clear all evidence to allow starting from scratch
  const handleClearEvidence = async () => {
    const emptyHash = await computeHash('[]');
    const riskBreakdown = calculateTransparentRiskScore([], [], []);
    setInvestigationCase({
      caseId: `TRACEX-${Date.now().toString().slice(-4)}`,
      caseName: "New Workspace Investigation",
      targetHost: "AWAITING-HOST",
      investigator: "Forensic Analyst",
      organization: "Enterprise Cyber SOC",
      status: "AWAITING_EVIDENCE",
      evidenceChainHash: emptyHash,
      createdAt: new Date().toISOString(),
      isDemoDataset: false,
      artifacts: [],
      findings: [],
      timelineGaps: [],
      correlations: [],
      phases: [],
      riskBreakdown: riskBreakdown,
      aiAnalysis: undefined
    });
  };

  // Run AI-assisted analysis via server-side Gemini endpoint using actual current evidence
  const handleRunAiAnalysis = async (focusQuestion?: string) => {
    if (investigationCase.artifacts.length === 0) return;

    setIsAiAnalyzing(true);
    try {
      const response = await fetch('/api/gemini/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          caseData: {
            caseId: investigationCase.caseId,
            caseName: investigationCase.caseName,
            targetHost: investigationCase.targetHost,
            isDemoDataset: investigationCase.isDemoDataset
          },
          artifacts: investigationCase.artifacts,
          findings: investigationCase.findings,
          timelineGaps: investigationCase.timelineGaps,
          focusQuestion
        })
      });

      if (!response.ok) {
        throw new Error(`Server returned HTTP ${response.status}`);
      }

      const result = await response.json();
      setInvestigationCase(prev => ({
        ...prev,
        aiAnalysis: result
      }));

      // If user invoked from overview or header button, navigate to AI tab
      if (currentTab !== 'ai-analysis' && !focusQuestion) {
        setCurrentTab('ai-analysis');
      }
    } catch (err: any) {
      console.error('Failed to run AI analysis:', err);
    } finally {
      setIsAiAnalyzing(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#050814] text-slate-100 cyber-grid flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top Navbar */}
      <Navbar
        currentTab={currentTab}
        onSelectTab={setCurrentTab}
        investigationCase={investigationCase}
        onResetDemo={handleResetDemo}
        onRunAiAnalysis={() => handleRunAiAnalysis()}
        isAiAnalyzing={isAiAnalyzing}
        onOpenReport={() => setIsReportModalOpen(true)}
        onToggleCopilot={() => setIsCopilotOpen(!isCopilotOpen)}
        isCopilotOpen={isCopilotOpen}
      />

      {/* Main Forensic Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8 space-y-6">
        {currentTab === 'overview' && (
          <OverviewDashboard
            investigationCase={investigationCase}
            onNavigateTab={setCurrentTab}
            onRunAiAnalysis={() => handleRunAiAnalysis()}
            isAiAnalyzing={isAiAnalyzing}
          />
        )}

        {currentTab === 'evidence' && (
          <EvidenceCollection
            artifacts={investigationCase.artifacts}
            isDemoDataset={investigationCase.isDemoDataset}
            caseDate={investigationCase.createdAt}
            onUpdateArtifacts={handleUpdateArtifacts}
            onResetDemo={handleResetDemo}
            onClearEvidence={handleClearEvidence}
          />
        )}

        {currentTab === 'anti-forensics' && (
          <AntiForensicsModule
            findings={investigationCase.findings}
            artifacts={investigationCase.artifacts}
            isDemoDataset={investigationCase.isDemoDataset}
          />
        )}

        {currentTab === 'timeline' && (
          <TimelineReconstruction
            artifacts={investigationCase.artifacts}
            timelineGaps={investigationCase.timelineGaps}
            isDemoDataset={investigationCase.isDemoDataset}
          />
        )}

        {currentTab === 'correlation' && (
          <EvidenceCorrelation
            artifacts={investigationCase.artifacts}
            findings={investigationCase.findings}
            correlations={investigationCase.correlations}
            phases={investigationCase.phases}
          />
        )}

        {currentTab === 'ai-analysis' && (
          <AiAnalysisModule
            investigationCase={investigationCase}
            onRunAnalysis={handleRunAiAnalysis}
            isAnalyzing={isAiAnalyzing}
          />
        )}

        {currentTab === 'report' && (
          <div className="space-y-4">
            <div className="glass-panel p-6 rounded-xl border border-cyan-500/30 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <h2 className="text-lg font-display font-bold text-white">
                  Formal Investigation Forensic Report
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  Ready to review, export, and print the legal-grade digital forensics analysis document based on {investigationCase.artifacts.length} active artifacts.
                </p>
              </div>
              <button
                onClick={() => setIsReportModalOpen(true)}
                className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs font-semibold shadow-[0_0_15px_rgba(6,182,212,0.3)] transition"
              >
                Launch Document Viewer & Export
              </button>
            </div>
            
            {/* Embedded summary preview */}
            <div className="glass-panel p-6 rounded-xl border border-slate-800 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <span className="font-mono text-xs text-cyan-400">CASE ID: {investigationCase.caseId}</span>
                <span className="font-mono text-xs text-emerald-400">
                  {investigationCase.artifacts.length > 0 ? 'CHAIN INTEGRITY VERIFIED' : 'AWAITING EVIDENCE'}
                </span>
              </div>
              <p className="text-xs text-slate-300 font-sans leading-relaxed">
                {investigationCase.aiAnalysis?.executiveSummary || 
                  (investigationCase.artifacts.length > 0 
                    ? `Workspace contains ${investigationCase.artifacts.length} observed forensic events and ${investigationCase.findings.length} anti-forensic triggers. Click "Launch Document Viewer & Export" to generate the report.` 
                    : 'No evidence loaded yet. Ingest forensic evidence or restore the demo dataset to generate a report.')}
              </p>
              <div className="pt-2 flex gap-3">
                <button
                  onClick={() => setIsReportModalOpen(true)}
                  className="px-4 py-2 rounded bg-slate-900 border border-cyan-700/60 hover:bg-slate-800 text-cyan-300 font-mono text-xs"
                >
                  Open Full Printable Report
                </button>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Forensic Report Modal */}
      <ForensicReportModal
        investigationCase={investigationCase}
        isOpen={isReportModalOpen}
        onClose={() => setIsReportModalOpen(false)}
      />

      {/* Interactive AI Copilot Slide-out Drawer */}
      <AiCopilotDrawer
        isOpen={isCopilotOpen}
        onClose={() => setIsCopilotOpen(false)}
        investigationCase={investigationCase}
      />

      {/* Bottom Forensic Telemetry Status Bar */}
      <footer className="border-t border-slate-900 bg-[#04060f]/95 px-4 py-2 text-[11px] font-mono text-slate-500 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1.5 text-emerald-400">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
            TRACEX RECONSTRUCTION CORE: ONLINE
          </span>
          <span className="hidden sm:inline text-slate-700">|</span>
          <span className="hidden sm:inline text-slate-400">
            CORRELATION ENGINE: {investigationCase.correlations?.length || 0} VECTORS
          </span>
          <span className="hidden md:inline text-slate-700">|</span>
          <span className="hidden md:inline text-slate-400">
            PROVENANCE: {investigationCase.isDemoDataset ? 'DEMO CASE' : 'USER EVIDENCE'}
          </span>
        </div>

        <div className="flex items-center gap-3">
          <span className="text-slate-400">
            SHA-256: <code className="text-cyan-400">{investigationCase.evidenceChainHash.slice(0, 16)}...</code>
          </span>
        </div>
      </footer>
    </div>
  );
}
