/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { 
  GitCommit, 
  Layers, 
  ArrowRight, 
  Link2, 
  ShieldAlert, 
  HardDrive, 
  FileText, 
  Globe, 
  Trash2, 
  Clock, 
  Sparkles,
  Info,
  CheckCircle2,
  Database
} from 'lucide-react';
import { ForensicArtifact, AntiForensicsFinding, EvidenceCorrelationLink, AttackChainPhase } from '../types/forensics';

interface EvidenceCorrelationProps {
  artifacts: ForensicArtifact[];
  findings: AntiForensicsFinding[];
  correlations?: EvidenceCorrelationLink[];
  phases?: AttackChainPhase[];
}

export const EvidenceCorrelation: React.FC<EvidenceCorrelationProps> = ({
  artifacts,
  findings,
  correlations = [],
  phases = []
}) => {
  const [activeNode, setActiveNode] = useState<string | null>(null);

  const hasEvidence = artifacts.length > 0;

  // Filter correlations if a node is selected
  const activeLinks = activeNode
    ? correlations.filter(c => c.sourceArtifactId === activeNode || c.targetArtifactId === activeNode)
    : correlations;

  return (
    <div className="space-y-6">
      {/* Banner */}
      <div className="glass-panel p-5 rounded-xl border border-slate-800">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <Link2 className="w-5 h-5 text-cyan-400" />
              <h2 className="text-base font-display font-bold text-white tracking-wide">
                MULTI-SOURCE EVIDENCE CORRELATION MATRIX
              </h2>
            </div>
            <p className="text-xs text-slate-400 mt-1 max-w-3xl">
              Connects related events dynamically using timestamps, artifact IDs, device IDs, volume mounts, and event descriptions.
              Reconstructs the full chain from access to anti-forensic destruction.
            </p>
          </div>

          <div className="flex items-center gap-2 text-xs font-mono shrink-0">
            {hasEvidence && (
              <span className="px-3 py-1.5 rounded bg-emerald-950/60 border border-emerald-500/30 text-emerald-300 font-bold flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5" />
                {correlations.length} Correlated Vectors Found
              </span>
            )}
          </div>
        </div>
      </div>

      {!hasEvidence ? (
        <div className="glass-panel p-12 rounded-xl border border-slate-800 text-center space-y-3">
          <Database className="w-10 h-10 text-slate-600 mx-auto opacity-50" />
          <h3 className="font-display font-bold text-base text-slate-300">
            No Events to Correlate
          </h3>
          <p className="text-xs text-slate-500 max-w-md mx-auto">
            Ingest forensic logs in Evidence Collection or load the synthetic demo to compute dynamic relationships between USB, file, browser, and log events.
          </p>
        </div>
      ) : (
        <>
          {/* Visual Attack Chain Flow Diagram */}
          <div className="glass-panel p-6 rounded-xl border border-slate-800 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-cyan-400" />
                <h3 className="font-display font-bold text-sm text-white">
                  DYNAMIC INCIDENT ATTACK PHASES
                </h3>
              </div>
              <div className="flex items-center gap-2">
                {activeNode && (
                  <button
                    onClick={() => setActiveNode(null)}
                    className="text-xs text-cyan-400 hover:underline font-mono"
                  >
                    Clear Filter
                  </button>
                )}
                <span className="text-xs font-mono text-slate-400">
                  Click any node to isolate its correlation links
                </span>
              </div>
            </div>

            {/* Attack Chain Phases (computed from actual evidence) */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {phases.map((phase) => {
                const phaseArtifacts = artifacts.filter(a => phase.nodeIds.includes(a.id));

                return (
                  <div
                    key={phase.id}
                    className={`p-4 rounded-xl border bg-gradient-to-b ${phase.color} space-y-3 relative`}
                  >
                    <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
                      <span className="font-display font-bold text-xs uppercase tracking-wide">
                        {phase.title}
                      </span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-black/40 border border-white/10">
                        {phase.badge}
                      </span>
                    </div>

                    <p className="text-[11px] text-slate-300 leading-relaxed font-sans">
                      {phase.description}
                    </p>

                    {/* Nodes in this phase */}
                    <div className="space-y-2 pt-1">
                      {phaseArtifacts.map((node) => {
                        const isNodeActive = activeNode === node.id;
                        const isAnti = !!node.antiForensicIndicator;

                        return (
                          <div
                            key={node.id}
                            onClick={() => setActiveNode(isNodeActive ? null : node.id)}
                            className={`p-3 rounded-lg border cursor-pointer transition text-xs font-mono ${
                              isNodeActive
                                ? 'bg-cyan-950 border-cyan-400 text-cyan-200 shadow-[0_0_15px_rgba(6,182,212,0.4)]'
                                : 'bg-slate-900/90 border-slate-800 hover:border-slate-700 text-slate-200'
                            }`}
                          >
                            <div className="flex items-center justify-between text-[10px] text-slate-400 mb-1">
                              <span className="text-cyan-400 font-bold">{node.id}</span>
                              <span>{node.timestamp.slice(11, 19)} UTC</span>
                            </div>
                            <div className="font-semibold text-white flex items-center justify-between">
                              <span className="truncate">{node.name}</span>
                              {isAnti && (
                                <span className="w-2 h-2 rounded-full bg-rose-500 shrink-0 ml-1"></span>
                              )}
                            </div>
                            <div className="text-[10px] text-slate-400 mt-1 uppercase flex items-center justify-between">
                              <span>Source: {node.source}</span>
                              <span className={node.riskLevel === 'CRITICAL' ? 'text-rose-400' : 'text-slate-400'}>{node.riskLevel}</span>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Correlation Connections & Forensic Proofs */}
          <div className="glass-panel p-5 rounded-xl border border-slate-800 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <GitCommit className="w-4 h-4 text-cyan-400" />
                <h3 className="font-display font-bold text-sm text-white">
                  VERIFIED ARTIFACT RELATIONSHIPS ({activeLinks.length})
                </h3>
              </div>
              <span className="text-xs font-mono text-cyan-400">
                {activeNode ? `Filtered for ${activeNode}` : 'All Dynamic Correlated Paths'}
              </span>
            </div>

            {activeLinks.length === 0 ? (
              <div className="p-8 text-center text-slate-500 font-mono text-xs">
                No direct correlation links for the selected node.
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {activeLinks.map((link) => (
                  <div
                    key={link.id}
                    className="p-4 rounded-xl bg-slate-900/80 border border-slate-800/90 hover:border-cyan-500/40 transition space-y-2.5"
                  >
                    <div className="flex items-center justify-between text-xs font-mono">
                      <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 font-bold">
                        {link.relationType}
                      </span>
                      <span className="text-slate-400">
                        Confidence: <strong className="text-cyan-300">{link.confidence}%</strong>
                      </span>
                    </div>

                    {/* Vector flow */}
                    <div className="flex items-center gap-2 text-xs font-mono text-white bg-slate-950 p-2.5 rounded border border-slate-800">
                      <span className="text-slate-300 truncate">{link.sourceName}</span>
                      <ArrowRight className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                      <span className="text-cyan-300 truncate">{link.targetName}</span>
                    </div>

                    <div className="text-[11px] font-mono text-slate-400">
                      <span className="text-slate-500 uppercase">Vector:</span> {link.vector}
                    </div>

                    <p className="text-xs text-slate-300 leading-relaxed font-sans bg-slate-950/40 p-2.5 rounded border border-slate-800/60">
                      {link.explanation}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Forensic Defeat Mechanics Deep-Dive */}
          <div className="p-4 rounded-xl bg-cyan-950/20 border border-cyan-500/30 text-xs text-slate-300 space-y-2">
            <div className="flex items-center gap-2 font-mono text-cyan-400 font-bold">
              <Info className="w-4 h-4" />
              <span>FORENSIC CORRELATION HEURISTICS & TIMESTOMP DEFEAT MECHANISM</span>
            </div>
            <p className="leading-relaxed">
              TraceX correlates disparate artifacts across independent sub-systems: USB registry mounts (`USBSTOR`), NTFS USN Change Journals, 
              and Chromium SQLite databases. When an adversary timestomps file attributes, standard user-mode tools only update NTFS attribute 
              <strong>0x10 ($STANDARD_INFORMATION)</strong>. However, the NTFS kernel file-system driver maintains a protected attribute, 
              <strong>0x30 ($FILE_NAME)</strong>, which preserves authentic creation and modification times unless the volume is taken offline 
              and raw sectors are overwritten. By comparing 0x10 against 0x30 and cross-referencing USN Journal records, TraceX breaks anti-forensic deception 
              and reconstructs the authentic timeline.
            </p>
          </div>
        </>
      )}
    </div>
  );
};
