/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useRef } from 'react';
import { 
  Upload, 
  FileText, 
  Download, 
  Plus, 
  Search, 
  CheckCircle2, 
  AlertCircle, 
  Eye, 
  Trash2, 
  RotateCcw, 
  Terminal, 
  Layers, 
  Clock, 
  X,
  FileCode,
  ShieldCheck,
  Sparkles,
  ArrowRight,
  Database
} from 'lucide-react';
import { ForensicArtifact, ArtifactSource, RiskLevel } from '../types/forensics';
import { parseForensicCSV, parseForensicJSON, generateSampleCSV, formatEvidenceField } from '../utils/forensicEngine';

interface EvidenceCollectionProps {
  artifacts: ForensicArtifact[];
  isDemoDataset: boolean;
  caseDate?: string;
  onUpdateArtifacts: (newArtifacts: ForensicArtifact[], isDemo?: boolean) => void;
  onResetDemo: () => void;
  onClearEvidence: () => void;
}

export const EvidenceCollection: React.FC<EvidenceCollectionProps> = ({
  artifacts,
  isDemoDataset,
  caseDate,
  onUpdateArtifacts,
  onResetDemo,
  onClearEvidence
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [sourceFilter, setSourceFilter] = useState<string>('ALL');
  const [riskFilter, setRiskFilter] = useState<string>('ALL');
  const [selectedArtifact, setSelectedArtifact] = useState<ForensicArtifact | null>(null);
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [uploadFeedback, setUploadFeedback] = useState<{ type: 'success' | 'error' | 'info'; message: string } | null>(null);

  // Ingestion Preview State
  const [pendingUpload, setPendingUpload] = useState<{
    fileName: string;
    fileType: 'CSV' | 'JSON';
    artifacts: ForensicArtifact[];
    errors: string[];
  } | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  // Base date from case (e.g., 2026-10-30) for time-only timestamps
  const baseDate = caseDate ? caseDate.slice(0, 10) : '2026-10-30';

  // New artifact form state
  const [newArtifactName, setNewArtifactName] = useState('');
  const [newArtifactSource, setNewArtifactSource] = useState<ArtifactSource>('FILE_SYSTEM');
  const [newArtifactTime, setNewArtifactTime] = useState(new Date().toISOString().slice(0, 19));
  const [newArtifactDesc, setNewArtifactDesc] = useState('');
  const [newArtifactUser, setNewArtifactUser] = useState('CORP\\analyst');
  const [newArtifactRisk, setNewArtifactRisk] = useState<RiskLevel>('HIGH');
  const [newArtifactType, setNewArtifactType] = useState('SUSPICIOUS_ACCESS');

  // Handle File Upload with Interactive Preview & Validation
  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const text = e.target?.result as string;
        let parsedArtifacts: ForensicArtifact[] = [];
        let parsingErrors: string[] = [];
        let fileType: 'CSV' | 'JSON' = 'CSV';

        if (file.name.endsWith('.csv')) {
          fileType = 'CSV';
          const res = parseForensicCSV(text, baseDate);
          parsedArtifacts = res.artifacts;
          parsingErrors = res.errors;
        } else if (file.name.endsWith('.json')) {
          fileType = 'JSON';
          const res = parseForensicJSON(text, baseDate);
          parsedArtifacts = res.artifacts;
          parsingErrors = res.errors;
        } else {
          throw new Error('Unsupported format. Please upload a .csv or .json forensic log export.');
        }

        if (parsedArtifacts.length === 0) {
          throw new Error('No valid forensic artifacts detected in file.');
        }

        // Open validation preview modal
        setPendingUpload({
          fileName: file.name,
          fileType,
          artifacts: parsedArtifacts,
          errors: parsingErrors
        });

      } catch (err: any) {
        setUploadFeedback({
          type: 'error',
          message: `File format validation failed: ${err?.message || 'Invalid syntax'}`
        });
      }
    };
    reader.readAsText(file);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  // Commit pending upload: replace or append
  const handleCommitUpload = (mode: 'replace' | 'append') => {
    if (!pendingUpload) return;

    const count = pendingUpload.artifacts.length;
    if (mode === 'replace') {
      onUpdateArtifacts(pendingUpload.artifacts, false);
      setUploadFeedback({
        type: 'success',
        message: `Investigation dataset replaced with ${count} validated artifacts from ${pendingUpload.fileName}.`
      });
    } else {
      onUpdateArtifacts([...artifacts, ...pendingUpload.artifacts], false);
      setUploadFeedback({
        type: 'success',
        message: `Appended ${count} artifacts from ${pendingUpload.fileName} to current investigation.`
      });
    }
    setPendingUpload(null);
  };

  // Download Sample CSV
  const handleDownloadSampleCSV = () => {
    const csvData = generateSampleCSV();
    const blob = new Blob([csvData], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', 'tracex_sample_evidence.csv');
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Handle Manual Add
  const handleAddArtifactSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newArtifactName.trim()) return;

    const newArt: ForensicArtifact = {
      id: `ART-MAN-${Date.now().toString().slice(-4)}`,
      evidenceId: `EVD-MAN-${Math.floor(Math.random() * 900 + 100)}`,
      timestamp: newArtifactTime.endsWith('Z') ? newArtifactTime : `${newArtifactTime}Z`,
      name: newArtifactName.trim(),
      source: newArtifactSource,
      eventType: newArtifactType,
      description: newArtifactDesc.trim() || newArtifactName.trim(),
      user: newArtifactUser.trim(),
      system: '',
      hash: '',
      riskLevel: newArtifactRisk,
      details: { addedBy: 'Investigator Manual Entry', method: 'Direct SOC Input' },
      isObserved: true,
      isSyntheticDemo: false
    };

    onUpdateArtifacts([...artifacts, newArt], isDemoDataset);
    setIsAddModalOpen(false);
    setNewArtifactName('');
    setNewArtifactDesc('');
    setUploadFeedback({
      type: 'success',
      message: `Artifact '${newArt.name}' added to evidence set.`
    });
  };

  // Delete Artifact
  const handleDeleteArtifact = (id: string) => {
    onUpdateArtifacts(artifacts.filter(a => a.id !== id), isDemoDataset);
    if (selectedArtifact?.id === id) setSelectedArtifact(null);
  };

  // Filter & Search
  const filteredArtifacts = artifacts.filter(art => {
    const matchesSearch = 
      art.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      art.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
      art.evidenceId.toLowerCase().includes(searchTerm.toLowerCase()) ||
      art.user.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesSource = sourceFilter === 'ALL' || art.source === sourceFilter;
    const matchesRisk = riskFilter === 'ALL' || art.riskLevel === riskFilter;

    return matchesSearch && matchesSource && matchesRisk;
  }).sort((a, b) => {
    const tA = new Date(a.timestamp).getTime();
    const tB = new Date(b.timestamp).getTime();
    return (isNaN(tA) ? 0 : tA) - (isNaN(tB) ? 0 : tB);
  });

  return (
    <div className="space-y-6">
      {/* Evidence Mode Banner */}
      <div className={`p-4 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono ${
        isDemoDataset 
          ? 'bg-blue-950/30 border-blue-500/40 text-blue-200' 
          : artifacts.length > 0 
          ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-200'
          : 'bg-slate-900 border-slate-800 text-slate-400'
      }`}>
        <div className="flex items-center gap-2.5">
          <span className={`w-2.5 h-2.5 rounded-full ${isDemoDataset ? 'bg-cyan-400 animate-pulse' : artifacts.length > 0 ? 'bg-emerald-400' : 'bg-slate-500'}`}></span>
          <div>
            <span className="font-bold tracking-wider uppercase">
              {isDemoDataset ? 'DATASET MODE: SYNTHETIC DEMONSTRATION SCENARIO' : artifacts.length > 0 ? 'DATASET MODE: USER UPLOADED EVIDENCE' : 'DATASET MODE: EMPTY (AWAITING EVIDENCE)'}
            </span>
            <p className="text-[11px] text-slate-400 font-sans mt-0.5">
              {isDemoDataset 
                ? 'Displaying synthetic employee data theft case (SanDisk USB exfiltration & multi-tier cover-up).'
                : artifacts.length > 0 
                ? `Ingested ${artifacts.length} live observed artifacts. All analysis metrics are derived strictly from these events.`
                : 'No evidence loaded. Upload a CSV/JSON export or restore the synthetic demo dataset.'}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          {!isDemoDataset && (
            <button
              onClick={onResetDemo}
              className="px-3 py-1.5 rounded bg-blue-950/80 hover:bg-blue-900 text-cyan-300 border border-blue-700/50 text-xs transition flex items-center gap-1.5"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Load Demo Case</span>
            </button>
          )}

          {artifacts.length > 0 && (
            <button
              onClick={onClearEvidence}
              className="px-3 py-1.5 rounded bg-slate-900 hover:bg-rose-950/50 text-slate-400 hover:text-rose-300 border border-slate-800 hover:border-rose-500/40 text-xs transition flex items-center gap-1.5"
              title="Clear all artifacts to start a blank investigation"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Clear Evidence</span>
            </button>
          )}
        </div>
      </div>

      {/* Evidence Controls & Ingestion Header */}
      <div className="glass-panel p-5 rounded-xl border border-slate-800">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-cyan-400"></span>
              <h2 className="text-base font-display font-bold text-white tracking-wide">
                DIGITAL FORENSIC EVIDENCE INGESTION
              </h2>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Upload actual CSV or JSON forensic exports. Validates timestamp sequences, parses metadata, and computes SHA-256 evidence chain integrity.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <input 
              type="file" 
              ref={fileInputRef} 
              onChange={handleFileUpload} 
              accept=".csv,.json" 
              className="hidden" 
            />
            
            <button
              onClick={() => fileInputRef.current?.click()}
              className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs shadow-[0_0_15px_rgba(6,182,212,0.3)] transition"
            >
              <Upload className="w-3.5 h-3.5" />
              <span>Upload CSV / JSON</span>
            </button>

            <button
              onClick={handleDownloadSampleCSV}
              className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 text-xs transition"
              title="Download a template CSV formatted for TraceX"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              <span>Sample CSV</span>
            </button>

            <button
              onClick={() => setIsAddModalOpen(true)}
              className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 text-xs transition"
            >
              <Plus className="w-3.5 h-3.5 text-cyan-400" />
              <span>Add Artifact</span>
            </button>
          </div>
        </div>

        {/* Validation Feedback Notification */}
        {uploadFeedback && (
          <div className={`mt-4 p-3 rounded-lg text-xs flex items-center justify-between border ${
            uploadFeedback.type === 'success' 
              ? 'bg-emerald-950/40 border-emerald-500/30 text-emerald-300' 
              : 'bg-rose-950/40 border-rose-500/30 text-rose-300'
          }`}>
            <div className="flex items-center gap-2">
              {uploadFeedback.type === 'success' ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              ) : (
                <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
              )}
              <span>{uploadFeedback.message}</span>
            </div>
            <button 
              onClick={() => setUploadFeedback(null)} 
              className="text-slate-400 hover:text-white"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}
      </div>

      {/* Uploaded File Validation & Ingestion Preview Modal */}
      {pendingUpload && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-md p-4">
          <div className="bg-[#0b1022] border border-cyan-500/50 rounded-xl max-w-3xl w-full p-6 space-y-4 shadow-[0_0_40px_rgba(6,182,212,0.3)]">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <FileCode className="w-5 h-5 text-cyan-400" />
                <h3 className="font-display font-bold text-base text-white">
                  Validate & Ingest Forensic Evidence: {pendingUpload.fileName}
                </h3>
              </div>
              <button 
                onClick={() => setPendingUpload(null)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="flex items-center gap-4 text-xs font-mono">
              <span className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-cyan-300">
                Format: <strong>{pendingUpload.fileType}</strong>
              </span>
              <span className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-emerald-300">
                Valid Artifacts: <strong>{pendingUpload.artifacts.length}</strong>
              </span>
              {pendingUpload.errors.length > 0 && (
                <span className="px-2.5 py-1 rounded bg-amber-950/60 border border-amber-500/40 text-amber-300">
                  Warnings: <strong>{pendingUpload.errors.length}</strong>
                </span>
              )}
            </div>

            {/* Ingestion Warning List */}
            {pendingUpload.errors.length > 0 && (
              <div className="p-3 rounded bg-amber-950/30 border border-amber-500/30 text-xs text-amber-200 font-mono max-h-24 overflow-y-auto space-y-1">
                {pendingUpload.errors.map((err, i) => (
                  <div key={i}>• {err}</div>
                ))}
              </div>
            )}

            {/* Preview of Parsed Items */}
            <div className="border border-slate-800 rounded-lg overflow-hidden max-h-56 overflow-y-auto">
              <table className="w-full text-left border-collapse text-[11px] font-mono">
                <thead className="bg-slate-900 text-slate-400 sticky top-0">
                  <tr className="border-b border-slate-800">
                    <th className="p-2">Timestamp</th>
                    <th className="p-2">Name</th>
                    <th className="p-2">Source</th>
                    <th className="p-2">Risk</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  {pendingUpload.artifacts.slice(0, 6).map((art, idx) => (
                    <tr key={idx} className="hover:bg-slate-900/40">
                      <td className="p-2 text-cyan-400">
                        {art.timestamp.includes('T') ? art.timestamp.split('T')[1].slice(0, 8) : art.timestamp}
                      </td>
                      <td className="p-2 text-white font-medium">{art.name}</td>
                      <td className="p-2 text-slate-400">{art.source}</td>
                      <td className="p-2">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          art.riskLevel === 'CRITICAL' ? 'text-rose-400' :
                          art.riskLevel === 'HIGH' ? 'text-amber-400' : 'text-blue-400'
                        }`}>
                          {art.riskLevel}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Ingestion Actions */}
            <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-slate-800">
              <span className="text-xs text-slate-400 font-mono">
                Choose how to apply this evidence to the investigation:
              </span>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => setPendingUpload(null)}
                  className="px-3 py-1.5 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 text-xs font-mono"
                >
                  Cancel
                </button>
                <button
                  onClick={() => handleCommitUpload('append')}
                  className="px-3.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 text-xs font-mono font-semibold"
                >
                  Append to Existing ({artifacts.length})
                </button>
                <button
                  onClick={() => handleCommitUpload('replace')}
                  className="px-3.5 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-semibold shadow-[0_0_15px_rgba(6,182,212,0.3)]"
                >
                  Replace Entire Dataset
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Filter & Search Bar */}
      <div className="flex flex-col md:flex-row items-center justify-between gap-3 p-3 rounded-xl bg-slate-900/60 border border-slate-800 text-xs">
        <div className="relative w-full md:w-80">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search artifact name, ID, user, hash..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono text-xs"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2 w-full md:w-auto">
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400 font-mono">Source:</span>
            <select
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-slate-300 font-mono focus:border-cyan-500 text-xs"
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
            <span className="text-slate-400 font-mono">Risk:</span>
            <select
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-slate-300 font-mono focus:border-cyan-500 text-xs"
            >
              <option value="ALL">All Risks</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          <span className="text-slate-500 font-mono ml-auto">
            Showing {filteredArtifacts.length} of {artifacts.length}
          </span>
        </div>
      </div>

      {/* Forensic Evidence Table */}
      <div className="glass-panel rounded-xl border border-slate-800/80 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/80 font-mono text-slate-400 uppercase text-[11px]">
                <th className="py-3 px-4">Evidence ID</th>
                <th className="py-3 px-4">Timestamp (UTC)</th>
                <th className="py-3 px-4">Artifact Name</th>
                <th className="py-3 px-4">Provenance</th>
                <th className="py-3 px-4">Source</th>
                <th className="py-3 px-4">User</th>
                <th className="py-3 px-4">Risk</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {filteredArtifacts.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-500 font-mono">
                    <Database className="w-8 h-8 text-slate-600 mx-auto mb-2 opacity-50" />
                    <div>No forensic artifacts match the active filters or dataset is empty.</div>
                    <div className="text-xs text-slate-600 mt-1">Upload a CSV/JSON file above or click "Restore Demo" to inspect.</div>
                  </td>
                </tr>
              ) : (
                filteredArtifacts.map((art) => {
                  const isAntiForensic = !!art.antiForensicIndicator;
                  const isDemo = art.isSyntheticDemo ?? isDemoDataset;

                  return (
                    <tr 
                      key={art.id} 
                      className={`hover:bg-cyan-950/20 transition cursor-pointer ${
                        selectedArtifact?.id === art.id ? 'bg-cyan-950/40 border-l-2 border-cyan-400' : ''
                      }`}
                      onClick={() => setSelectedArtifact(art)}
                    >
                      <td className="py-3 px-4 font-bold text-cyan-400">
                        {art.evidenceId}
                      </td>
                      <td className="py-3 px-4 text-slate-300">
                        <div>{art.timestamp.replace('T', ' ').replace('Z', '')}</div>
                        {art.details?.isTimeOnly && (
                          <div className="text-[10px] text-cyan-400 font-mono">
                            Time-only ({art.details.originalTimestamp})
                          </div>
                        )}
                      </td>
                      <td className="py-3 px-4 font-sans font-medium text-slate-200">
                        <div className="flex items-center gap-2">
                          <span>{art.name}</span>
                          {isAntiForensic && (
                            <span className="px-1.5 py-0.2 rounded text-[10px] bg-rose-500/20 text-rose-300 border border-rose-500/40">
                              Anti-Forensic
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] text-slate-400 truncate max-w-xs font-mono">
                          {art.description}
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${
                          isDemo 
                            ? 'bg-blue-950/50 text-blue-300 border-blue-500/30' 
                            : 'bg-emerald-950/50 text-emerald-300 border-emerald-500/30'
                        }`}>
                          {isDemo ? 'SYNTHETIC DEMO' : 'OBSERVED FACT'}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 border border-slate-700">
                          {art.source}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-300 truncate max-w-[120px]">
                        {formatEvidenceField(art.user)}
                      </td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          art.riskLevel === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' :
                          art.riskLevel === 'HIGH' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' :
                          art.riskLevel === 'MEDIUM' ? 'bg-blue-500/20 text-blue-300 border border-blue-500/40' :
                          'bg-slate-800 text-slate-400'
                        }`}>
                          {art.riskLevel}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <div className="flex items-center justify-end gap-1.5" onClick={(e) => e.stopPropagation()}>
                          <button
                            onClick={() => setSelectedArtifact(art)}
                            className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-cyan-400 transition"
                            title="Inspect Details"
                          >
                            <Eye className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => handleDeleteArtifact(art.id)}
                            className="p-1 rounded hover:bg-rose-950/50 text-slate-500 hover:text-rose-400 transition"
                            title="Remove from current evidence set"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Artifact Detailed Inspector Drawer / Modal */}
      {selectedArtifact && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-[#0b1022] border border-cyan-500/40 rounded-xl max-w-2xl w-full p-6 space-y-4 shadow-[0_0_35px_rgba(6,182,212,0.2)] max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 rounded font-mono text-xs bg-cyan-950 text-cyan-300 border border-cyan-800">
                  {formatEvidenceField(selectedArtifact.evidenceId)}
                </span>
                <h3 className="font-display font-bold text-lg text-white">
                  {formatEvidenceField(selectedArtifact.name)}
                </h3>
              </div>
              <button
                onClick={() => setSelectedArtifact(null)}
                className="text-slate-400 hover:text-white p-1 rounded hover:bg-slate-800"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
              <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                <span className="text-slate-500 block">SOURCE</span>
                <span className="text-cyan-400 font-semibold">{formatEvidenceField(selectedArtifact.source)}</span>
              </div>
              <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                <span className="text-slate-500 block">EVENT TYPE</span>
                <span className="text-slate-200">{formatEvidenceField(selectedArtifact.eventType)}</span>
              </div>
              <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                <span className="text-slate-500 block">RISK LEVEL</span>
                <span className={`font-bold ${
                  selectedArtifact.riskLevel === 'CRITICAL' ? 'text-rose-400' :
                  selectedArtifact.riskLevel === 'HIGH' ? 'text-amber-400' : 'text-blue-400'
                }`}>
                  {selectedArtifact.riskLevel}
                </span>
              </div>
              <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                <span className="text-slate-500 block">PROVENANCE</span>
                <span className={selectedArtifact.isSyntheticDemo ? 'text-blue-300' : 'text-emerald-400'}>
                  {selectedArtifact.isSyntheticDemo ? 'Synthetic Demo' : 'Observed Fact'}
                </span>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
              <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                <span className="text-slate-500 block">USER ACCOUNT</span>
                <span className="text-slate-200">{formatEvidenceField(selectedArtifact.user)}</span>
              </div>
              <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                <span className="text-slate-500 block">TARGET SYSTEM / HOST</span>
                <span className="text-slate-200">{formatEvidenceField(selectedArtifact.system)}</span>
              </div>
            </div>

            <div className="space-y-1">
              <span className="text-xs font-mono text-slate-400 uppercase">Forensic Timestamp</span>
              <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800 font-mono text-xs text-slate-200">
                {formatEvidenceField(selectedArtifact.timestamp)}
              </div>
            </div>

            <div className="space-y-1">
              <span className="text-xs font-mono text-slate-400 uppercase">Description / Finding</span>
              <p className="p-2.5 rounded bg-slate-900/80 border border-slate-800 text-xs text-slate-300">
                {formatEvidenceField(selectedArtifact.description)}
              </p>
            </div>

            {/* Anti-Forensic Flag Detail */}
            {selectedArtifact.antiForensicIndicator && (
              <div className="p-3 rounded-lg bg-rose-950/30 border border-rose-500/40 space-y-2">
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-rose-400 font-bold uppercase flex items-center gap-1.5">
                    <AlertCircle className="w-4 h-4 text-rose-400" />
                    ANTI-FORENSIC MECHANISM DETECTED
                  </span>
                  <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
                    MITRE {selectedArtifact.antiForensicIndicator.mitreTechnique}
                  </span>
                </div>
                <div className="text-xs text-slate-300">
                  <span className="text-slate-400 font-semibold">Tactic:</span> {selectedArtifact.antiForensicIndicator.mitreName}
                </div>
                <div className="text-xs text-slate-300">
                  <span className="text-slate-400 font-semibold">Detection Reason:</span> {selectedArtifact.antiForensicIndicator.reason}
                </div>
                <div className="text-xs text-cyan-300 font-mono">
                  Confidence: {selectedArtifact.antiForensicIndicator.confidence}% | Indicator: {selectedArtifact.antiForensicIndicator.indicatorArtifact}
                </div>
              </div>
            )}

            {/* Raw Metadata & Hash */}
            <div className="space-y-1">
              <span className="text-xs font-mono text-slate-400 uppercase">SHA-256 Artifact Hash</span>
              <div className="p-2 rounded bg-slate-950 border border-slate-800 font-mono text-[11px] text-cyan-300 break-all">
                {formatEvidenceField(selectedArtifact.hash)}
              </div>
            </div>

            <div className="space-y-1">
              <span className="text-xs font-mono text-slate-400 uppercase">Extended Technical Payload</span>
              <pre className="p-3 rounded bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto max-h-40">
                {JSON.stringify(selectedArtifact.details, null, 2)}
              </pre>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedArtifact(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-white text-xs font-mono"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Manual Add Artifact Modal */}
      {isAddModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <form onSubmit={handleAddArtifactSubmit} className="bg-[#0b1022] border border-cyan-500/40 rounded-xl max-w-lg w-full p-6 space-y-4 shadow-[0_0_35px_rgba(6,182,212,0.2)]">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="font-display font-bold text-base text-white">
                Add Forensic Evidence Record
              </h3>
              <button
                type="button"
                onClick={() => setIsAddModalOpen(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 text-xs font-mono">
              <div>
                <label className="text-slate-400 block mb-1">Artifact Name *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g., Prefetch Execution / SDelete Wiping"
                  value={newArtifactName}
                  onChange={(e) => setNewArtifactName(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:border-cyan-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">Source Hive/Subsystem</label>
                  <select
                    value={newArtifactSource}
                    onChange={(e) => setNewArtifactSource(e.target.value as ArtifactSource)}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:border-cyan-500"
                  >
                    <option value="FILE_SYSTEM">File System (NTFS/FAT)</option>
                    <option value="USB_BUS">USB Bus / Driver</option>
                    <option value="EVENT_LOG">Event Log (.evtx)</option>
                    <option value="BROWSER">Browser SQLite/WAL</option>
                    <option value="MFT_REGISTRY">MFT / Registry Hive</option>
                    <option value="MEMORY">RAM / Volatility</option>
                    <option value="NETWORK">Network PCAP/DNS</option>
                  </select>
                </div>

                <div>
                  <label className="text-slate-400 block mb-1">Risk Severity</label>
                  <select
                    value={newArtifactRisk}
                    onChange={(e) => setNewArtifactRisk(e.target.value as RiskLevel)}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:border-cyan-500"
                  >
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Timestamp (UTC)</label>
                <input
                  type="datetime-local"
                  value={newArtifactTime}
                  onChange={(e) => setNewArtifactTime(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:border-cyan-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">Event Type Identifier</label>
                  <input
                    type="text"
                    value={newArtifactType}
                    onChange={(e) => setNewArtifactType(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:border-cyan-500"
                  />
                </div>
                <div>
                  <label className="text-slate-400 block mb-1">Subject Account</label>
                  <input
                    type="text"
                    value={newArtifactUser}
                    onChange={(e) => setNewArtifactUser(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:border-cyan-500"
                  />
                </div>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Forensic Description & Clues</label>
                <textarea
                  rows={3}
                  placeholder="Specific file path, command-line arguments, registry keys..."
                  value={newArtifactDesc}
                  onChange={(e) => setNewArtifactDesc(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:border-cyan-500"
                ></textarea>
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setIsAddModalOpen(false)}
                className="px-4 py-2 rounded bg-slate-800 text-slate-300 hover:bg-slate-700 text-xs font-mono"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-4 py-2 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs font-semibold shadow-[0_0_15px_rgba(6,182,212,0.3)]"
              >
                Inject Artifact
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
