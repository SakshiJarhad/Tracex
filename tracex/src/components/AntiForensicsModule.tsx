/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { 
  ShieldAlert, 
  Trash2, 
  Clock, 
  Globe, 
  FileCode, 
  HardDrive, 
  AlertTriangle, 
  CheckCircle2, 
  Fingerprint, 
  Zap, 
  ArrowRight, 
  Database,
  ExternalLink,
  Info
} from 'lucide-react';
import { AntiForensicsFinding, AntiForensicCategory, ForensicArtifact } from '../types/forensics';

interface AntiForensicsModuleProps {
  findings: AntiForensicsFinding[];
  artifacts: ForensicArtifact[];
  isDemoDataset?: boolean;
  onSelectArtifactById?: (id: string) => void;
}

export const AntiForensicsModule: React.FC<AntiForensicsModuleProps> = ({
  findings,
  artifacts,
  isDemoDataset = false,
  onSelectArtifactById
}) => {
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');

  const hasEvidence = artifacts.length > 0;

  // Dynamically calculate detected anti-forensic techniques vs exfiltration indicators
  const antiForensicsFindings = findings.filter(f => f.indicatorType !== 'EXFILTRATION_INDICATOR');
  const exfiltrationFindings = findings.filter(f => f.indicatorType === 'EXFILTRATION_INDICATOR');
  
  // Total detected technique categories across actual uploaded artifacts
  const detectedAntiForensicCategories = new Set(antiForensicsFindings.map(f => f.category));
  const detectedExfiltrationCategories = new Set(exfiltrationFindings.map(f => f.category));
  const totalDetectedTechniquesCount = detectedAntiForensicCategories.size;

  // The 6 Forensic Pillars with consistent event-to-rule mapping
  const categories: {
    id: AntiForensicCategory;
    title: string;
    icon: any;
    description: string;
    mitre: string;
    mitreName: string;
    isExfiltration?: boolean;
  }[] = [
    {
      id: 'LOG_DELETION',
      title: 'System Log Deletion',
      icon: Trash2,
      description: 'Audit log clearing, Event ID 1102/104, wevtutil execution, and event service tampering.',
      mitre: 'T1070.001',
      mitreName: 'Indicator Removal on Host: Clear Windows Event Logs'
    },
    {
      id: 'BROWSER_CLEANING',
      title: 'Browser History Clearing',
      icon: Globe,
      description: 'Chromium SQLite history zeroing, WAL journal truncation, and web cache purging.',
      mitre: 'T1070.003',
      mitreName: 'Indicator Removal on Host: Clear Web Browsing History'
    },
    {
      id: 'TIMESTOMPING',
      title: 'Timestamp Manipulation',
      icon: Clock,
      description: 'MFT $STANDARD_INFORMATION altered while $FILE_NAME retains genuine timestamps; zero-millisecond traits.',
      mitre: 'T1070.006',
      mitreName: 'Indicator Removal on Host: Timestomp'
    },
    {
      id: 'METADATA_ALTERATION',
      title: 'Metadata Alteration',
      icon: FileCode,
      description: 'ExifTool scrubbing, document revision removal, and NTFS Alternate Data Streams stripping.',
      mitre: 'T1070.005',
      mitreName: 'Indicator Removal on Host: File Metadata Alteration'
    },
    {
      id: 'SECURE_DELETION',
      title: 'Secure File Deletion',
      icon: Zap,
      description: 'Multi-pass unallocated cluster shredding (SDelete, cipher /w, shred) to thwart data carving.',
      mitre: 'T1070.004',
      mitreName: 'Indicator Removal on Host: File Deletion'
    },
    {
      id: 'SUSPICIOUS_USB',
      title: 'Potential Data Exfiltration / USB Vector',
      icon: HardDrive,
      description: 'Removable USB mass storage attachment, rapid staging, or file copy to external volume.',
      mitre: 'T1052.001',
      mitreName: 'Exfiltration Over Physical Medium',
      isExfiltration: true
    }
  ];

  const filteredFindings = selectedCategory === 'ALL'
    ? findings
    : findings.filter(f => f.category === selectedCategory);

  const selectedCatObj = categories.find(c => c.id === selectedCategory);

  return (
    <div className="space-y-6">
      {/* Module Overview Banner */}
      <div className="glass-panel p-5 rounded-xl border border-slate-800 bg-gradient-to-r from-slate-900/90 to-[#071329]">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className={`w-2.5 h-2.5 rounded-full ${hasEvidence && findings.length > 0 ? 'bg-rose-500 animate-ping' : 'bg-slate-500'}`}></span>
              <h2 className="text-base font-display font-bold text-white tracking-wide">
                ANTI-FORENSICS DETECTION ENGINE
              </h2>
            </div>
            <p className="text-xs text-slate-400 mt-1 max-w-3xl">
              Evaluates uploaded forensic artifacts using deterministic rule-based heuristics. Distinguishes confirmed defense evasion from potential data exfiltration indicators.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2 text-xs font-mono shrink-0">
            <span className={`px-3 py-1.5 rounded-lg border font-bold ${
              totalDetectedTechniquesCount > 0 
                ? 'bg-rose-500/20 text-rose-300 border-rose-500/40 shadow-[0_0_12px_rgba(244,63,94,0.2)]' 
                : 'bg-slate-900 text-slate-400 border-slate-800'
            }`}>
              {totalDetectedTechniquesCount} Anti-Forensics {totalDetectedTechniquesCount === 1 ? 'Technique' : 'Techniques'} Detected
            </span>

            {exfiltrationFindings.length > 0 && (
              <span className="px-3 py-1.5 rounded-lg bg-amber-500/20 text-amber-300 border border-amber-500/40 font-bold">
                {exfiltrationFindings.length} Exfiltration Indicator{exfiltrationFindings.length === 1 ? '' : 's'}
              </span>
            )}

            <span className="px-3 py-1.5 rounded-lg bg-cyan-950 text-cyan-300 border border-cyan-800">
              MITRE ATT&CK T1070 Aligned
            </span>
          </div>
        </div>
      </div>

      {!hasEvidence ? (
        <div className="glass-panel p-12 rounded-xl border border-slate-800 text-center space-y-3">
          <Database className="w-10 h-10 text-slate-600 mx-auto opacity-50" />
          <h3 className="font-display font-bold text-base text-slate-300">
            Anti-Forensics Engine in Standby
          </h3>
          <p className="text-xs text-slate-500 max-w-md mx-auto">
            No forensic evidence is currently loaded. Ingest a CSV or JSON file in Evidence Collection or load the synthetic demo case to execute heuristic scans.
          </p>
        </div>
      ) : (
        <>
          {/* 6 Category Summary Cards Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {categories.map((cat) => {
              const Icon = cat.icon;
              const matchingFindings = findings.filter(f => f.category === cat.id);
              const isDetected = matchingFindings.length > 0;
              const isSelected = selectedCategory === cat.id;
              const primary = (cat.id === 'SUSPICIOUS_USB' 
                ? (matchingFindings.find(f => f.title.includes('Exfiltration') || (f.detectionReason && f.detectionReason.includes('file copy'))) || matchingFindings[0]) 
                : matchingFindings[0]);

              // Extraction of the 6 mandatory display properties:
              // 1. Detection status: Detected or Not Detected
              // 2. Evidence event ID
              // 3. Evidence timestamp
              // 4. Detection reason
              // 5. Severity level
              // 6. MITRE ATT&CK mapping
              const detectionStatus = isDetected 
                ? (cat.isExfiltration ? 'Detected (Exfiltration Vector)' : 'Detected') 
                : 'Not Detected';

              const evidenceId = isDetected 
                ? (primary.evidenceEventId || primary.relatedArtifactIds[0] || 'EVD-OBSERVED') 
                : 'None';

              const evidenceTimestamp = isDetected
                ? (primary.evidenceTimestamp ? (primary.evidenceTimestamp.includes('T') ? primary.evidenceTimestamp.replace('T', ' ').slice(0, 19) + ' UTC' : primary.evidenceTimestamp) : 'Recorded')
                : 'N/A';

              const detectionReason = isDetected
                ? primary.detectionReason
                : `No evidence of ${cat.title.toLowerCase()} identified in uploaded artifacts.`;

              const severityLevel = isDetected ? primary.severity : 'Nominal';

              const mitreMapping = isDetected 
                ? `MITRE ${primary.mitreTechnique}` 
                : `MITRE ${cat.mitre}`;

              return (
                <div
                  key={cat.id}
                  onClick={() => setSelectedCategory(isSelected ? 'ALL' : cat.id)}
                  className={`p-4 rounded-xl border cursor-pointer transition flex flex-col justify-between relative overflow-hidden ${
                    isDetected
                      ? cat.isExfiltration
                        ? isSelected
                          ? 'bg-amber-950/40 border-amber-500 shadow-[0_0_20px_rgba(245,158,11,0.25)]'
                          : 'bg-slate-900/90 border-amber-500/50 hover:border-amber-400'
                        : isSelected
                          ? 'bg-rose-950/40 border-rose-500 shadow-[0_0_20px_rgba(244,63,94,0.25)]'
                          : 'bg-slate-900/90 border-rose-500/50 hover:border-rose-400'
                      : isSelected
                        ? 'bg-slate-900 border-cyan-500'
                        : 'bg-slate-900/40 border-slate-800/80 hover:border-slate-700'
                  }`}
                >
                  <div>
                    {/* Header: Title, Icon, Status Badge */}
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex items-center gap-2.5">
                        <div className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 ${
                          isDetected 
                            ? cat.isExfiltration
                              ? 'bg-amber-500/20 border border-amber-500/40 text-amber-400'
                              : 'bg-rose-500/20 border border-rose-500/40 text-rose-400' 
                            : 'bg-slate-800 text-slate-400'
                        }`}>
                          <Icon className="w-4 h-4" />
                        </div>
                        <div>
                          <h3 className="text-sm font-semibold text-white leading-snug">
                            {cat.title}
                          </h3>
                          <div className="flex items-center gap-1.5 mt-0.5">
                            <span className="text-[10px] font-mono text-cyan-400">
                              {mitreMapping}
                            </span>
                            {cat.isExfiltration && (
                              <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-amber-950 text-amber-300 border border-amber-800/50">
                                Exfiltration Vector
                              </span>
                            )}
                          </div>
                        </div>
                      </div>

                      {/* Detection Status Badge */}
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold shrink-0 ${
                        isDetected 
                          ? cat.isExfiltration
                            ? 'bg-amber-500/30 text-amber-200 border border-amber-500/50 animate-pulse'
                            : 'bg-rose-500/30 text-rose-200 border border-rose-500/50' 
                          : 'bg-slate-800 text-slate-400 border border-slate-700'
                      }`}>
                        {detectionStatus}
                      </span>
                    </div>

                    {/* Technique Summary */}
                    <p className="text-xs text-slate-400 mt-2.5 line-clamp-2">
                      {cat.description}
                    </p>
                  </div>

                  {/* Mandatory Forensic Metadata Breakdown */}
                  <div className="mt-3 pt-3 border-t border-slate-800/80 space-y-1.5 text-xs font-mono">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400 text-[11px]">Detection Status:</span>
                      <span className={`font-semibold ${isDetected ? (cat.isExfiltration ? 'text-amber-300' : 'text-rose-400') : 'text-slate-500'}`}>
                        {isDetected ? 'Detected' : 'Not Detected'}
                      </span>
                    </div>

                    <div className="flex items-center justify-between">
                      <span className="text-slate-400 text-[11px]">Evidence Event ID:</span>
                      <span className={isDetected ? 'text-cyan-300 font-bold' : 'text-slate-500'}>
                        {evidenceId}
                      </span>
                    </div>

                    <div className="flex items-center justify-between">
                      <span className="text-slate-400 text-[11px]">Evidence Timestamp:</span>
                      <span className={isDetected ? 'text-slate-200' : 'text-slate-500'}>
                        {evidenceTimestamp}
                      </span>
                    </div>

                    <div className="flex items-center justify-between">
                      <span className="text-slate-400 text-[11px]">Severity Level:</span>
                      <span className={`font-bold ${
                        severityLevel === 'CRITICAL' ? 'text-rose-400' :
                        severityLevel === 'HIGH' ? 'text-amber-400' :
                        severityLevel === 'MEDIUM' ? 'text-yellow-400' :
                        'text-slate-500'
                      }`}>
                        {severityLevel}
                      </span>
                    </div>

                    {/* Detection Reason Box */}
                    <div className="mt-2 text-[11px] text-slate-300 bg-slate-950/80 p-2.5 rounded border border-slate-800 leading-relaxed">
                      <span className="text-slate-400 font-semibold block mb-0.5 text-[10px] uppercase tracking-wider">
                        Detection Reason:
                      </span>
                      <span className="line-clamp-2">
                        {detectionReason}
                      </span>
                    </div>
                  </div>

                  {isDetected && (
                    <div className="mt-2.5 pt-2 border-t border-slate-800/60 flex items-center justify-between text-[11px] font-mono text-cyan-300">
                      <span>Rule Confidence: {primary.confidence}%</span>
                      <span className="flex items-center gap-1 hover:text-white transition">
                        Inspect Details <ArrowRight className="w-3 h-3" />
                      </span>
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Filter Bar */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-xs font-mono">
            <div className="flex items-center gap-2">
              <span className="text-slate-400">Pillar Filter:</span>
              <span className="text-cyan-300 font-bold">
                {selectedCategory === 'ALL' ? 'Showing All Anti-Forensic Findings' : selectedCatObj?.title || selectedCategory}
              </span>
            </div>
            {selectedCategory !== 'ALL' && (
              <button
                onClick={() => setSelectedCategory('ALL')}
                className="text-slate-400 hover:text-white underline text-xs text-left"
              >
                Clear Filter (Show All)
              </button>
            )}
          </div>

          {/* Findings Detail List */}
          <div className="space-y-4">
            {filteredFindings.length === 0 ? (
              <div className="glass-panel p-8 rounded-xl border border-slate-800 text-center space-y-2 font-mono text-xs">
                <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto opacity-70" />
                <div className="text-slate-300 font-bold text-sm">
                  {selectedCatObj ? `${selectedCatObj.title}: Not Detected` : 'No Findings Match Filter'}
                </div>
                <p className="text-slate-400 max-w-lg mx-auto">
                  {selectedCatObj 
                    ? `Heuristic rules for ${selectedCatObj.title} (${selectedCatObj.mitre}) evaluated all ${artifacts.length} uploaded forensic artifacts with 0 signature triggers. No evasion detected.`
                    : 'No anti-forensics findings detected for the selected category in the current evidence set.'}
                </p>
              </div>
            ) : (
              filteredFindings.map((finding) => {
                const relatedArtifacts = artifacts.filter(a => finding.relatedArtifactIds.includes(a.id));
                const isExfil = finding.indicatorType === 'EXFILTRATION_INDICATOR';

                return (
                  <div
                    key={finding.id}
                    className={`glass-panel p-5 rounded-xl border transition space-y-4 ${
                      isExfil 
                        ? 'border-amber-500/40 bg-gradient-to-r from-amber-950/20 to-slate-900/80 hover:border-amber-500/70' 
                        : 'border-rose-500/40 bg-gradient-to-r from-rose-950/20 to-slate-900/80 hover:border-rose-500/70'
                    }`}
                  >
                    {/* Header */}
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
                      <div className="flex flex-wrap items-center gap-2.5">
                        <span className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold border ${
                          finding.severity === 'CRITICAL'
                            ? 'bg-rose-500/30 text-rose-200 border-rose-500/50'
                            : 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                        }`}>
                          {finding.severity} SEVERITY
                        </span>

                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold border ${
                          isExfil
                            ? 'bg-amber-950/80 text-amber-300 border-amber-600/50'
                            : 'bg-rose-950/80 text-rose-300 border-rose-600/50'
                        }`}>
                          {isExfil ? 'POTENTIAL DATA EXFILTRATION INDICATOR' : 'CONFIRMED DEFENSE EVASION'}
                        </span>

                        <h3 className="text-base font-display font-bold text-white">
                          {finding.title}
                        </h3>

                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${
                          isDemoDataset 
                            ? 'bg-blue-950/40 text-blue-300 border-blue-500/30' 
                            : 'bg-emerald-950/40 text-emerald-300 border-emerald-500/30'
                        }`}>
                          {isDemoDataset ? 'DEMO DATASET' : 'OBSERVED EVIDENCE'}
                        </span>
                      </div>

                      <div className="flex items-center gap-2 font-mono text-xs shrink-0">
                        <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                          MITRE ATT&CK {finding.mitreTechnique}
                        </span>
                        <span className="text-slate-400">
                          Confidence: <strong className="text-cyan-300">{finding.confidence}%</strong>
                        </span>
                      </div>
                    </div>

                    {/* Detection Reason */}
                    <div>
                      <div className={`text-xs font-mono uppercase tracking-wider mb-1 flex items-center gap-1.5 ${
                        isExfil ? 'text-amber-400' : 'text-rose-400'
                      }`}>
                        <Fingerprint className="w-3.5 h-3.5" />
                        Detection Rationale & Rule Trigger
                      </div>
                      <p className="text-xs text-slate-200 bg-slate-900/80 p-3 rounded-lg border border-slate-800 leading-relaxed font-mono">
                        {finding.detectionReason}
                      </p>
                    </div>

                    {/* Observed Forensic Indicators */}
                    <div>
                      <div className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-1.5">
                        Observed Forensic Signatures
                      </div>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs font-mono">
                        {finding.forensicIndicators.map((ind, idx) => (
                          <div key={idx} className="flex items-start gap-2 p-2 rounded bg-slate-950/60 border border-slate-800/80">
                            <CheckCircle2 className={`w-3.5 h-3.5 shrink-0 mt-0.5 ${isExfil ? 'text-amber-400' : 'text-rose-400'}`} />
                            <span className="text-slate-300">{ind}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Reconstruction Impact */}
                    <div className="p-3 rounded-lg bg-blue-950/20 border border-blue-500/30 text-xs">
                      <div className="font-mono text-cyan-400 font-semibold mb-1">
                        Timeline Reconstruction Impact
                      </div>
                      <p className="text-slate-300">
                        {finding.reconstructionImpact}
                      </p>
                    </div>

                    {/* Triggering Artifacts */}
                    {relatedArtifacts.length > 0 && (
                      <div className="pt-2 border-t border-slate-800/80 flex flex-wrap items-center gap-2 text-xs font-mono">
                        <span className="text-slate-400">Triggering Artifact:</span>
                        {relatedArtifacts.map(art => (
                          <span 
                            key={art.id}
                            onClick={() => onSelectArtifactById && onSelectArtifactById(art.id)}
                            className="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-cyan-300 hover:border-cyan-500 transition cursor-pointer"
                            title={art.description}
                          >
                            {art.evidenceId} ({art.name}) • {art.timestamp}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </>
      )}
    </div>
  );
};
