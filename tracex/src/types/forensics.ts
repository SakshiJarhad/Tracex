/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export type ArtifactSource = 
  | 'USB_BUS'
  | 'FILE_SYSTEM'
  | 'EVENT_LOG'
  | 'BROWSER'
  | 'MFT_REGISTRY'
  | 'MEMORY'
  | 'NETWORK';

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type AntiForensicCategory =
  | 'LOG_DELETION'
  | 'BROWSER_CLEANING'
  | 'TIMESTOMPING'
  | 'METADATA_ALTERATION'
  | 'SECURE_DELETION'
  | 'SUSPICIOUS_USB';

export interface AntiForensicIndicator {
  category: AntiForensicCategory;
  detected: boolean;
  reason: string;
  mitreTechnique: string;
  mitreName: string;
  confidence: number; // 0 - 100 based on exact rule criteria
  indicatorArtifact: string;
  matchedRules?: string[];
}

export interface ForensicArtifact {
  id: string;
  evidenceId: string;
  timestamp: string; // ISO string e.g. 2026-10-30T12:05:14Z
  name: string;
  source: ArtifactSource;
  eventType: string;
  description: string;
  user: string;
  system: string;
  hash: string; // SHA-256
  riskLevel: RiskLevel;
  details: Record<string, string | number | boolean>;
  antiForensicIndicator?: AntiForensicIndicator;
  isObserved: boolean; // true = hard forensic trace; false = AI-reconstructed hypothesis
  isSyntheticDemo?: boolean; // true = preloaded demo scenario; false = user uploaded/created
}

export interface AntiForensicsFinding {
  id: string;
  category: AntiForensicCategory;
  title: string;
  severity: RiskLevel;
  detectionReason: string;
  mitreTechnique: string;
  mitreName: string;
  relatedArtifactIds: string[];
  forensicIndicators: string[];
  reconstructionImpact: string;
  confidence: number;
  ruleExplanation?: string;
  indicatorType?: 'ANTI_FORENSICS' | 'EXFILTRATION_INDICATOR';
  evidenceEventId?: string;
  evidenceTimestamp?: string;
}

export interface TimelineIntervalGap {
  id: string;
  startTime: string;
  endTime: string;
  durationMinutes: number;
  description: string;
  suspicionScore: number;
  hypothesizedActivity: string;
  isObserved: false;
}

export interface EvidenceCorrelationLink {
  id: string;
  sourceArtifactId: string;
  targetArtifactId: string;
  sourceName: string;
  targetName: string;
  relationType: 'Direct File Transfer' | 'Temporal Chain' | 'Audit Blackout Coverup' | 'Account Identity' | 'Volume Association' | 'Tool Execution';
  vector: string;
  confidence: number;
  explanation: string;
}

export interface AttackChainPhase {
  id: string;
  title: string;
  color: string;
  badge: string;
  description: string;
  nodeIds: string[];
}

export interface RiskScoreBreakdown {
  overallScore: number;
  confidenceScore: number;
  baseSeverityPoints: number;
  antiForensicsMultiplier: number;
  temporalDensityPoints: number;
  sourceCorroborationBonus: number;
  rulesApplied: {
    name: string;
    points: number;
    description: string;
  }[];
}

export interface AIAnalysisResult {
  executiveSummary: string;
  attackChainNarrative: string;
  antiForensicTacticsAnalysis: string;
  missingEvidenceGaps: {
    interval: string;
    analysis: string;
    hypothesizedAction: string;
    confidence: number;
  }[];
  observedFactsVsHypotheses: {
    observedFacts: string[];
    aiHypotheses: string[];
  };
  riskScore: number;
  confidenceScore: number;
  correlationHighlights: {
    title: string;
    chain: string[];
    description: string;
  }[];
  recommendations: {
    priority: 'P1 - Immediate' | 'P2 - High' | 'P3 - Moderate';
    action: string;
    target: string;
    rationale: string;
  }[];
  analyzedAt: string;
  modelUsed: string;
}

export interface InvestigationCase {
  caseId: string;
  caseName: string;
  targetHost: string;
  investigator: string;
  organization: string;
  status: 'ANALYSIS_COMPLETE' | 'IN_PROGRESS' | 'ANTI_FORENSICS_FLAGGED' | 'EVIDENCE_LOCKED' | 'AWAITING_EVIDENCE';
  evidenceChainHash: string;
  createdAt: string;
  isDemoDataset: boolean;
  artifacts: ForensicArtifact[];
  findings: AntiForensicsFinding[];
  timelineGaps: TimelineIntervalGap[];
  correlations?: EvidenceCorrelationLink[];
  phases?: AttackChainPhase[];
  riskBreakdown?: RiskScoreBreakdown;
  aiAnalysis?: AIAnalysisResult;
}
