/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { 
  Clock, 
  AlertTriangle, 
  ShieldAlert, 
  CheckCircle2, 
  HelpCircle, 
  Play, 
  Pause, 
  SkipForward, 
  SkipBack, 
  Filter, 
  Database, 
  Layers,
  ArrowDown,
  Info
} from 'lucide-react';
import { ForensicArtifact, TimelineIntervalGap } from '../types/forensics';
import { formatEvidenceField } from '../utils/forensicEngine';

interface TimelineReconstructionProps {
  artifacts: ForensicArtifact[];
  timelineGaps: TimelineIntervalGap[];
  isDemoDataset?: boolean;
  onSelectArtifact?: (art: ForensicArtifact) => void;
}

export const TimelineReconstruction: React.FC<TimelineReconstructionProps> = ({
  artifacts,
  timelineGaps,
  isDemoDataset = false,
  onSelectArtifact
}) => {
  const [sourceFilter, setSourceFilter] = useState<string>('ALL');
  const [riskFilter, setRiskFilter] = useState<string>('ALL');
  const [onlyAntiForensics, setOnlyAntiForensics] = useState(false);
  const [showGaps, setShowGaps] = useState(true);

  // Playback / scrubber state
  const [activeStep, setActiveStep] = useState<number | null>(null);
  const [isPlaying, setIsPlaying] = useState(false);

  const hasEvidence = artifacts.length > 0;

  const getSafeTime = (ts: string) => {
    const time = new Date(ts).getTime();
    return isNaN(time) ? 0 : time;
  };

  const formatDisplayTimestamp = (ts: string) => {
    if (!ts) return 'Unknown Time';
    if (ts.includes('T')) {
      return `${ts.slice(11, 19)} UTC`;
    }
    return ts;
  };

  // Sort artifacts chronologically with safe timestamp parsing
  const sortedArtifacts = [...artifacts].sort(
    (a, b) => getSafeTime(a.timestamp) - getSafeTime(b.timestamp)
  );

  // Filtered artifacts
  const filtered = sortedArtifacts.filter(art => {
    if (sourceFilter !== 'ALL' && art.source !== sourceFilter) return false;
    if (riskFilter !== 'ALL' && art.riskLevel !== riskFilter) return false;
    if (onlyAntiForensics && !art.antiForensicIndicator) return false;
    return true;
  });

  // Build unified chronological timeline items (Artifacts + Gaps)
  interface TimelineItem {
    type: 'ARTIFACT' | 'GAP';
    timestamp: string;
    artifact?: ForensicArtifact;
    gap?: TimelineIntervalGap;
  }

  const timelineItems: TimelineItem[] = [];

  filtered.forEach(art => {
    timelineItems.push({
      type: 'ARTIFACT',
      timestamp: art.timestamp,
      artifact: art
    });
  });

  if (showGaps && hasEvidence) {
    timelineGaps.forEach(gap => {
      timelineItems.push({
        type: 'GAP',
        timestamp: gap.startTime,
        gap: gap
      });
    });
  }

  // Sort unified items chronologically
  timelineItems.sort((a, b) => getSafeTime(a.timestamp) - getSafeTime(b.timestamp));

  // Auto-playback effect
  useEffect(() => {
    let timer: any;
    if (isPlaying && timelineItems.length > 0) {
      timer = setInterval(() => {
        setActiveStep(prev => {
          if (prev === null || prev >= timelineItems.length - 1) {
            return 0;
          }
          return prev + 1;
        });
      }, 2000);
    }
    return () => clearInterval(timer);
  }, [isPlaying, timelineItems.length]);

  return (
    <div className="space-y-6">
      {/* Header & Playback Control Center */}
      <div className="glass-panel p-5 rounded-xl border border-slate-800">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <Clock className="w-5 h-5 text-cyan-400" />
              <h2 className="text-base font-display font-bold text-white tracking-wide">
                CHRONOLOGICAL TIMELINE RECONSTRUCTION
              </h2>
            </div>
            <p className="text-xs text-slate-400 mt-1 max-w-3xl">
              Chronologically ordered event stream dynamically generated from observed evidence. 
              Gaps represent unlogged intervals where activity is inferred through AI hypothesis modeling.
            </p>
          </div>

          {/* Stepper / Playback Controls */}
          {hasEvidence && (
            <div className="flex items-center gap-2 bg-slate-900/90 p-1.5 rounded-lg border border-slate-800 text-xs font-mono">
              <button
                onClick={() => setActiveStep(prev => (prev === null || prev <= 0) ? timelineItems.length - 1 : prev - 1)}
                className="p-1.5 rounded hover:bg-slate-800 text-slate-300 hover:text-white transition"
                title="Step Back"
              >
                <SkipBack className="w-4 h-4" />
              </button>

              <button
                onClick={() => setIsPlaying(!isPlaying)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded transition ${
                  isPlaying 
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' 
                    : 'bg-cyan-600 hover:bg-cyan-500 text-white shadow-[0_0_12px_rgba(6,182,212,0.3)]'
                }`}
              >
                {isPlaying ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
                <span>{isPlaying ? 'Pause' : 'Play Sequence'}</span>
              </button>

              <button
                onClick={() => setActiveStep(prev => (prev === null || prev >= timelineItems.length - 1) ? 0 : prev + 1)}
                className="p-1.5 rounded hover:bg-slate-800 text-slate-300 hover:text-white transition"
                title="Step Forward"
              >
                <SkipForward className="w-4 h-4" />
              </button>

              <span className="text-slate-500 px-2">|</span>

              <span className="text-slate-400 text-[11px]">
                Step: {activeStep !== null ? `${activeStep + 1} / ${timelineItems.length}` : 'All View'}
              </span>

              {activeStep !== null && (
                <button
                  onClick={() => { setActiveStep(null); setIsPlaying(false); }}
                  className="text-xs text-cyan-400 hover:underline ml-1"
                >
                  Reset
                </button>
              )}
            </div>
          )}
        </div>

        {/* Filter Controls Bar */}
        {hasEvidence && (
          <div className="mt-4 pt-3 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
            <div className="flex flex-wrap items-center gap-3">
              <div className="flex items-center gap-1.5">
                <span className="text-slate-400">Source:</span>
                <select
                  value={sourceFilter}
                  onChange={(e) => setSourceFilter(e.target.value)}
                  className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-slate-300 focus:border-cyan-500"
                >
                  <option value="ALL">All Sources</option>
                  <option value="USB_BUS">USB Bus</option>
                  <option value="FILE_SYSTEM">File System</option>
                  <option value="EVENT_LOG">Event Log</option>
                  <option value="BROWSER">Browser</option>
                  <option value="MFT_REGISTRY">MFT / Registry</option>
                </select>
              </div>

              <div className="flex items-center gap-1.5">
                <span className="text-slate-400">Risk:</span>
                <select
                  value={riskFilter}
                  onChange={(e) => setRiskFilter(e.target.value)}
                  className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-slate-300 focus:border-cyan-500"
                >
                  <option value="ALL">All Risks</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>
              </div>

              <label className="flex items-center gap-1.5 text-slate-300 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={onlyAntiForensics}
                  onChange={(e) => setOnlyAntiForensics(e.target.checked)}
                  className="rounded bg-slate-950 border-slate-800 text-cyan-500 focus:ring-0"
                />
                <span className="text-rose-300">Only Anti-Forensic Events</span>
              </label>

              <label className="flex items-center gap-1.5 text-slate-300 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={showGaps}
                  onChange={(e) => setShowGaps(e.target.checked)}
                  className="rounded bg-slate-950 border-slate-800 text-amber-500 focus:ring-0"
                />
                <span className="text-amber-300">Show Timeline Gaps</span>
              </label>
            </div>

            <div className="flex items-center gap-3 text-[11px]">
              <span className="flex items-center gap-1 text-emerald-400 font-mono">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-400"></span> Observed Evidence Fact
              </span>
              <span className="flex items-center gap-1 text-purple-400 font-mono">
                <span className="w-2.5 h-2.5 rounded-full bg-purple-400"></span> AI Hypothesis (Unverified)
              </span>
            </div>
          </div>
        )}
      </div>

      {!hasEvidence ? (
        <div className="glass-panel p-12 rounded-xl border border-slate-800 text-center space-y-3">
          <Database className="w-10 h-10 text-slate-600 mx-auto opacity-50" />
          <h3 className="font-display font-bold text-base text-slate-300">
            No Events to Reconstruct
          </h3>
          <p className="text-xs text-slate-500 max-w-md mx-auto">
            Upload forensic logs in the Evidence Collection tab or click Restore Demo to reconstruct a chronological event stream.
          </p>
        </div>
      ) : (
        /* Main Interactive Chronological Feed */
        <div className="relative pl-6 sm:pl-8 before:absolute before:left-3 sm:before:left-4 before:top-3 before:bottom-3 before:w-0.5 before:bg-gradient-to-b before:from-cyan-500 before:via-blue-500 before:to-rose-500 space-y-4">
          {timelineItems.map((item, idx) => {
            const isSelected = activeStep === idx;

            if (item.type === 'GAP' && item.gap) {
              const gap = item.gap;
              return (
                <div 
                  key={gap.id}
                  className={`relative transition-all duration-300 ${
                    isSelected ? 'scale-[1.01] ring-2 ring-purple-400 shadow-[0_0_25px_rgba(168,85,247,0.3)]' : ''
                  }`}
                >
                  {/* Node marker */}
                  <div className="absolute -left-[27px] sm:-left-[31px] top-4 w-5 h-5 rounded-full bg-[#050814] border-2 border-purple-400 flex items-center justify-center">
                    <div className="w-2 h-2 rounded-full bg-purple-400 animate-ping"></div>
                  </div>

                  <div className="p-4 rounded-xl bg-purple-950/20 border border-purple-500/40 text-xs font-mono space-y-2">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                      <span className="px-2 py-0.5 rounded font-bold bg-purple-500/20 text-purple-300 border border-purple-500/30 w-fit">
                        AI-GENERATED HYPOTHESIS: UNVERIFIED INTERVAL ({gap.durationMinutes} min)
                      </span>
                      <span className="text-slate-400">
                        {formatDisplayTimestamp(gap.startTime)} &rarr; {formatDisplayTimestamp(gap.endTime)}
                      </span>
                    </div>

                    <p className="text-slate-300">
                      {gap.description}
                    </p>

                    <div className="p-2.5 rounded bg-purple-950/40 border border-purple-500/30 text-purple-200 flex items-start gap-2">
                      <HelpCircle className="w-4 h-4 text-purple-400 shrink-0 mt-0.5" />
                      <div>
                        <span className="font-bold text-purple-300">Probabilistic Inference (Not Confirmed Fact):</span>
                        <p className="mt-0.5 text-[11px] leading-relaxed">
                          {gap.hypothesizedActivity}
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              );
            }

            // Artifact item
            const art = item.artifact!;
            const isAntiForensic = !!art.antiForensicIndicator;
            const isDemo = art.isSyntheticDemo ?? isDemoDataset;

            return (
              <div
                key={art.id}
                onClick={() => {
                  setActiveStep(idx);
                  if (onSelectArtifact) onSelectArtifact(art);
                }}
                className={`relative group cursor-pointer transition-all duration-200 ${
                  isSelected 
                    ? 'scale-[1.01] ring-2 ring-cyan-400 shadow-[0_0_25px_rgba(6,182,212,0.3)]' 
                    : ''
                }`}
              >
                {/* Node Marker */}
                <div className={`absolute -left-[27px] sm:-left-[31px] top-4 w-5 h-5 rounded-full bg-[#050814] border-2 flex items-center justify-center transition ${
                  isAntiForensic 
                    ? 'border-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.6)]' 
                    : 'border-cyan-400 shadow-[0_0_8px_rgba(6,182,212,0.5)]'
                }`}>
                  <div className={`w-2 h-2 rounded-full ${isAntiForensic ? 'bg-rose-500' : 'bg-cyan-400'}`}></div>
                </div>

                {/* Event Card */}
                <div className={`glass-panel p-4 rounded-xl border transition ${
                  isAntiForensic
                    ? 'border-rose-500/40 hover:border-rose-500 bg-rose-950/10'
                    : 'border-slate-800 hover:border-cyan-500/40'
                }`}>
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 border-b border-slate-800/80 pb-2">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold text-cyan-300">
                        {formatDisplayTimestamp(art.timestamp)}
                      </span>
                      <span className="text-slate-500 font-mono">|</span>
                      <span className="font-mono text-[11px] text-slate-400">
                        {art.evidenceId}
                      </span>
                      <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-slate-800 text-slate-300">
                        {art.source}
                      </span>
                    </div>

                    <div className="flex items-center gap-2">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${
                        isDemo 
                          ? 'bg-blue-950/40 text-blue-300 border-blue-500/30' 
                          : 'bg-emerald-950/40 text-emerald-300 border-emerald-500/30'
                      }`}>
                        {isDemo ? 'SYNTHETIC DEMO' : 'OBSERVED FACT'}
                      </span>

                      {isAntiForensic && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40 flex items-center gap-1">
                          <ShieldAlert className="w-3 h-3 text-rose-400" />
                          {art.antiForensicIndicator?.mitreTechnique}
                        </span>
                      )}

                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                        art.riskLevel === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300' :
                        art.riskLevel === 'HIGH' ? 'bg-amber-500/20 text-amber-300' :
                        art.riskLevel === 'MEDIUM' ? 'bg-blue-500/20 text-blue-300' :
                        'bg-slate-800 text-slate-400'
                      }`}>
                        {art.riskLevel}
                      </span>
                    </div>
                  </div>

                  <div className="mt-2.5">
                    <h3 className="text-sm font-semibold text-white group-hover:text-cyan-300 transition">
                      {art.name}
                    </h3>
                    <p className="text-xs text-slate-300 mt-1 leading-relaxed">
                      {art.description}
                    </p>
                  </div>

                  {/* Additional Metadata pill row */}
                  <div className="mt-3 pt-2.5 border-t border-slate-800/60 flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-slate-400">
                    <div className="flex items-center gap-3">
                      <span>User: <strong className="text-slate-200">{art.user}</strong></span>
                      <span>Action: <strong className="text-slate-200">{art.eventType}</strong></span>
                    </div>
                    <div className="flex items-center gap-1 text-emerald-400">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>{isDemo ? 'Synthetic Demo Event' : 'Verified Cryptographic Evidence'}</span>
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
