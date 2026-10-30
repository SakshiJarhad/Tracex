/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { ForensicArtifact, AntiForensicsFinding, TimelineIntervalGap, InvestigationCase } from '../types/forensics';

export const DEMO_CASE_EMPLOYEE_THEFT: InvestigationCase = {
  caseId: "TRACEX-2026-CASE-0914",
  caseName: "Operation DarkShred: Insider Exfiltration & Anti-Forensics Wipe",
  targetHost: "FIN-WORKSTATION-042 (10.14.22.89)",
  investigator: "Forensic Analyst N. Vance, GCFE / CISSP",
  organization: "Global Financial Technologies SOC",
  status: "ANTI_FORENSICS_FLAGGED",
  evidenceChainHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  createdAt: "2026-10-30T12:00:00Z",
  isDemoDataset: true,
  artifacts: [
    {
      id: "ART-1001",
      evidenceId: "EVD-USB-01",
      timestamp: "2026-10-30T12:05:00Z",
      name: "SanDisk Ultra Flash Drive Connected",
      source: "USB_BUS",
      eventType: "USB_CONNECTED",
      description: "USB storage device attached and mounted to Drive E:\\ with serial 4C531001560 registered in SYSTEM registry hive.",
      user: "CORP\\jdoe",
      system: "FIN-WORKSTATION-042",
      hash: "a4f89d123e456b7890123456789abcdef0123456789abcdef0123456789abcde",
      riskLevel: "HIGH",
      details: {
        vendorId: "0x0781 (SanDisk Corp.)",
        productId: "0x5581 (Ultra)",
        serialNumber: "4C531001560",
        assignedMount: "E:\\",
        deviceClass: "USBSTOR\\DiskSanDisk_Ultra___________1.00",
        guid: "{53f56307-b6bf-11d0-94f2-00a0c91efb8b}",
        registryKey: "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR"
      },
      isObserved: true,
      isSyntheticDemo: true
    },
    {
      id: "ART-1002",
      evidenceId: "EVD-NTFS-02",
      timestamp: "2026-10-30T12:08:22Z",
      name: "Confidential Spreadsheet Accessed",
      source: "FILE_SYSTEM",
      eventType: "FILE_ACCESSED",
      description: "Target financial acquisition model opened in Excel: Q3_Financial_Acquisition_Target.xlsx.",
      user: "CORP\\jdoe",
      system: "FIN-WORKSTATION-042",
      hash: "c6d01f345a678d90123456789cdef0123456789cdef0123456789cdef012345",
      riskLevel: "HIGH",
      details: {
        filePath: "C:\\CorporateVault\\Q3_Financial_Acquisition_Target.xlsx",
        fileSize: "26,024,192 bytes",
        processName: "EXCEL.EXE (PID 8412)",
        action: "Read/Access",
        classification: "TOP_SECRET_FINANCIAL",
        mftRecordNumber: 104928
      },
      isObserved: true,
      isSyntheticDemo: true
    },
    {
      id: "ART-1003",
      evidenceId: "EVD-NTFS-03",
      timestamp: "2026-10-30T12:10:05Z",
      name: "Confidential Spreadsheet Copied to USB",
      source: "FILE_SYSTEM",
      eventType: "FILE_COPIED_TO_USB",
      description: "USN Journal confirms copy to E:\\Exfil\\Q3_Financial_Acquisition_Target.xlsx.",
      user: "CORP\\jdoe",
      system: "FIN-WORKSTATION-042",
      hash: "d7e12a456b789e0123456789def0123456789def0123456789def0123456789",
      riskLevel: "CRITICAL",
      details: {
        sourcePath: "C:\\CorporateVault\\Q3_Financial_Acquisition_Target.xlsx",
        destinationPath: "E:\\Exfil\\Q3_Financial_Acquisition_Target.xlsx",
        volumeSerial: "9C42-17E2 (Drive E:)",
        usnJournalRecord: 4892011,
        bytesWritten: 26024192,
        transferMechanism: "Robocopy / Explorer File Copy"
      },
      isObserved: true,
      isSyntheticDemo: true
    },
    {
      id: "ART-1004",
      evidenceId: "EVD-BRW-04",
      timestamp: "2026-10-30T12:12:30Z",
      name: "Chrome Browser Browsing History Wiped",
      source: "BROWSER",
      eventType: "BROWSER_HISTORY_CLEARED",
      description: "Google Chrome SQLite history cleared and WAL journal truncated to 0 bytes.",
      user: "CORP\\jdoe",
      system: "FIN-WORKSTATION-042",
      hash: "e8f23b567c890f123456789ef0123456789ef0123456789ef0123456789ef012",
      riskLevel: "CRITICAL",
      details: {
        browser: "Google Chrome 130.0.6723.70",
        databasePath: "C:\\Users\\jdoe\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History",
        deletedEntriesEstimate: "1,420 URL visits wiped",
        walFileStatus: "Truncated from 4.2MB to 0 bytes",
        trigger: "Manual browser setting invocation ('Clear All Browsing Data Since Beginning')"
      },
      isObserved: true,
      isSyntheticDemo: true
    },
    {
      id: "ART-1005",
      evidenceId: "EVD-LOG-05",
      timestamp: "2026-10-30T12:13:15Z",
      name: "Windows Audit Security Event Log Wiped",
      source: "EVENT_LOG",
      eventType: "LOG_DELETION",
      description: "Windows Security Event ID 1102 - Security.evtx audit log deleted via wevtutil.exe.",
      user: "CORP\\jdoe",
      system: "FIN-WORKSTATION-042",
      hash: "f9034c678d901023456789f0123456789f0123456789f0123456789f01234567",
      riskLevel: "CRITICAL",
      details: {
        eventId: 1102,
        logProvider: "Microsoft-Windows-Eventlog",
        clearedLogName: "Security.evtx",
        callerUserSid: "S-1-5-21-3948201-2049102-1004",
        callerProcess: "C:\\Windows\\System32\\wevtutil.exe cl Security",
        backupPath: "None (Logs wiped without creating .evtx backup file)"
      },
      isObserved: true,
      isSyntheticDemo: true
    },
    {
      id: "ART-1006",
      evidenceId: "EVD-MFT-06",
      timestamp: "2026-10-30T12:14:02Z",
      name: "NTFS Filesystem Timestomp Anomaly Detected",
      source: "MFT_REGISTRY",
      eventType: "TIMESTAMP_ANOMALY",
      description: "Discrepancy detected: $STANDARD_INFORMATION backdated while $FILE_NAME retains genuine 2026 stamp.",
      user: "CORP\\jdoe",
      system: "FIN-WORKSTATION-042",
      hash: "0a145d789e012134567890123456789012345678901234567890123456789012",
      riskLevel: "CRITICAL",
      details: {
        targetFile: "C:\\CorporateVault\\Q3_Financial_Acquisition_Target.xlsx",
        siModifiedTime: "2024-03-12 09:00:00.0000000 (Artificial Timestomp)",
        fnModifiedTime: "2026-10-30 12:08:22.4182901 (Authentic MFT Record)",
        millisecondGranularity: "0000000 (Classic tool artifact - PowerShell / timestomp.exe)",
        mftEntry: 104928,
        sequenceNumber: 4
      },
      isObserved: true,
      isSyntheticDemo: true
    },
    {
      id: "ART-1007",
      evidenceId: "EVD-USB-07",
      timestamp: "2026-10-30T12:16:00Z",
      name: "SanDisk Ultra Flash Drive Disconnected",
      source: "USB_BUS",
      eventType: "USB_DISCONNECTED",
      description: "Removable USB storage device unmounted and safely removed from system.",
      user: "CORP\\jdoe",
      system: "FIN-WORKSTATION-042",
      hash: "1b256e890f123245678901234567890123456789012345678901234567890123",
      riskLevel: "LOW",
      details: {
        action: "Hardware Dismount",
        assignedMount: "E:\\ (Released)",
        deviceClass: "USBSTOR"
      },
      isObserved: true,
      isSyntheticDemo: true
    }
  ],
  findings: [
    {
      id: "FND-01",
      category: "LOG_DELETION",
      title: "Security Event Log Obliteration (Event ID 1102)",
      severity: "CRITICAL",
      detectionReason: "The Windows Security event log was wiped clean at 12:13:15 using wevtutil.exe by user 'CORP\\jdoe'. This eliminated all logon sessions and process tracking.",
      mitreTechnique: "T1070.001",
      mitreName: "Clear Windows Event Logs",
      relatedArtifactIds: ["ART-1006"],
      forensicIndicators: [
        "Event ID 1102 logged in Microsoft-Windows-Eventlog provider",
        "Process wevtutil.exe executed with elevated tokens",
        "Missing 4624 (Logon) and 4688 (Process Creation) records from 11:30 to 12:13"
      ],
      reconstructionImpact: "Severely restricts visibility into whether additional files were touched between 12:10 and 12:13; necessitates fallback to MFT and USN journal carve.",
      confidence: 99
    },
    {
      id: "FND-02",
      category: "TIMESTOMPING",
      title: "MFT Timestamp Manipulation ($STANDARD_INFO vs $FILE_NAME Mismatch)",
      severity: "CRITICAL",
      detectionReason: "The confidential financial spreadsheet had its $STANDARD_INFORMATION Modified time altered to 2024-03-12 with zeroed milliseconds, masquerading as legacy file data.",
      mitreTechnique: "T1070.006",
      mitreName: "Timestomp",
      relatedArtifactIds: ["ART-1003", "ART-1007"],
      forensicIndicators: [
        "$STANDARD_INFO modified time (2024-03-12 09:00:00.0000000)",
        "$FILE_NAME modified time (2026-10-30 12:08:22.4182901)",
        "Zero millisecond granularity in attribute 0x10"
      ],
      reconstructionImpact: "Standard timeline tools sorting solely by SI timestamps miss this event entirely; TraceX correlator corrects chronology using $FILE_NAME and USN records.",
      confidence: 97
    },
    {
      id: "FND-03",
      category: "BROWSER_CLEANING",
      title: "Chromium SQLite History Database Destruction & Journal Purge",
      severity: "HIGH",
      detectionReason: "User wiped Chrome history database and truncated the Write-Ahead Log (WAL) at 12:12:30, immediately prior to clearing the system event log.",
      mitreTechnique: "T1070.003",
      mitreName: "Clear Web Browsing History",
      relatedArtifactIds: ["ART-1005"],
      forensicIndicators: [
        "Chrome History SQLite DB size dropped to zero-byte schema template",
        "History-wal journal truncated without checkpoint flush",
        "Session storage and cookies purged in the same transaction"
      ],
      reconstructionImpact: "Potential cloud upload (e.g. personal Mega/Dropbox/ProtonMail) obscured from browser cache; network perimeter DNS logs recommended for cross-examination.",
      confidence: 98
    },
    {
      id: "FND-04",
      category: "SUSPICIOUS_USB",
      title: "Unauthorized Mass Storage Device Connection & Exfiltration Mount",
      severity: "HIGH",
      detectionReason: "Unapproved SanDisk Ultra 64GB USB device was mounted at 12:05:14, followed 5 minutes later by high-volume confidential file copy.",
      mitreTechnique: "T1052.001",
      mitreName: "Exfiltration Over Physical Medium",
      relatedArtifactIds: ["ART-1001", "ART-1004"],
      forensicIndicators: [
        "USBSTOR registry entry created for serial 4C531001560",
        "Volume mount to E:\\ confirmed in MountPoints2",
        "USN Journal confirms file write to destination volume"
      ],
      reconstructionImpact: "Establishes definitive physical exfiltration vector and serial number for physical device subpoena.",
      confidence: 96
    },
    {
      id: "FND-05",
      category: "SECURE_DELETION",
      title: "Multi-Pass Forensic Shredding (Sysinternals SDelete)",
      severity: "HIGH",
      detectionReason: "Execution of SDelete with 3-pass DoD overwrite flags targeting intermediate exfiltration zip archive in AppData\\Local\\Temp.",
      mitreTechnique: "T1070.004",
      mitreName: "File Deletion",
      relatedArtifactIds: ["ART-1008"],
      forensicIndicators: [
        "PSReadLine history record for sdelete64.exe -p 3",
        "Prefetch hash SDELETE64.EXE-884A911C.pf created",
        "Zeroed clusters identified in Temp volume unallocated sectors"
      ],
      reconstructionImpact: "Intermediate staging archive is unrecoverable from disk carve; however, original file metadata and USN entries remain intact.",
      confidence: 95
    }
  ],
  timelineGaps: [
    {
      id: "GAP-01",
      startTime: "2026-10-30T12:10:05Z",
      endTime: "2026-10-30T12:12:30Z",
      durationMinutes: 2.4,
      description: "Critical Timeline Gap: 2 minutes 25 seconds of silence between USB file copy and browser purge.",
      suspicionScore: 88,
      hypothesizedActivity: "Suspect likely compressed exfiltrated files or attempted secondary cloud exfiltration (Mega/Google Drive/Email) prior to browser wipe.",
      isObserved: false
    },
    {
      id: "GAP-02",
      startTime: "2026-10-30T12:13:15Z",
      endTime: "2026-10-30T12:14:02Z",
      durationMinutes: 0.8,
      description: "Event Log Blackout Interval: Window immediately following Security.evtx wipe.",
      suspicionScore: 92,
      hypothesizedActivity: "Suspect launched PowerShell or custom timestomping binary without generating Event 4688 records due to just-cleared audit policy.",
      isObserved: false
    }
  ],
  aiAnalysis: {
    executiveSummary: "Forensic analysis of FIN-WORKSTATION-042 reveals a coordinated, deliberate insider data exfiltration incident followed by aggressive anti-forensic countermeasures. User CORP\\jdoe attached an unauthorized USB drive, navigated directly to restricted corporate M&A folders, decrypted and copied 24.8 MB of confidential financial acquisition targets, and subsequently executed a 4-stage anti-forensic cover-up (browser purge, security log destruction, NTFS MFT timestomping, and multi-pass unallocated cluster shredding). Despite these destruction techniques, multi-artifact correlation through USN Journal and MFT $FILE_NAME attributes successfully defeated the timestomping and reconstructed the timeline with 96% confidence.",
    attackChainNarrative: "Phase 1 (12:05 - Staging & Physical Vector): An unapproved SanDisk Ultra 64GB USB storage device (Serial: 4C531001560) was mounted to drive letter E:\\. Shellbags and LNK records demonstrate immediate targeted navigation to restricted corporate shares.\\n\\nPhase 2 (12:08 to 12:10 - Exfiltration): The primary target file 'Q3_Financial_Acquisition_Target.xlsx' was opened via Excel and copied to the external volume 'E:\\Exfil\\'. USN Journal confirms 26,024,192 bytes transferred.\\n\\nPhase 3 (12:12 to 12:14 - Anti-Forensic Cover-Up): Realizing local traces remained, the subject systematically attempted forensic destruction: first wiping Chrome SQLite history, then invoking wevtutil.exe to destroy the Security Event Log (Event ID 1102), and finally timestomping the source spreadsheet's $STANDARD_INFORMATION attribute backwards to 2024.\\n\\nPhase 4 (12:15 - Cleanup): Sysinternals SDelete was invoked to shred the intermediate zip archive.",
    antiForensicTacticsAnalysis: "The adversary exhibited intermediate-to-advanced operational security knowledge by targeting four distinct forensic artifact repositories: Application history (Chrome), Operating System audit logs (Security.evtx), Filesystem timestamps (NTFS MFT 0x10 attribute), and Disk slack (SDelete). However, the failure to alter NTFS $FILE_NAME (0x30 attribute), which requires kernel-level direct disk write privileges, created a definitive anti-forensic fingerprint that conclusively proves intentional evidence tampering rather than inadvertent error.",
    missingEvidenceGaps: [
      {
        interval: "12:10:05 - 12:12:30 (2m 25s)",
        analysis: "Between USB file write and browser history destruction, no operating system event logs were generated.",
        hypothesizedAction: "AI Hypothesis: Suspect evaluated whether cloud transmission was necessary or staged an encrypted zip file using 7-Zip, prompting subsequent browser cleanup.",
        confidence: 84
      },
      {
        interval: "12:13:15 - 12:14:02 (47s)",
        analysis: "Directly following the Security log wipe, a 47-second window exists before the MFT timestomp was logged.",
        hypothesizedAction: "AI Hypothesis: Script execution occurred during this blackout window without triggering 4688 process creation audits.",
        confidence: 91
      }
    ],
    observedFactsVsHypotheses: {
      observedFacts: [
        "VERIFIED: USB SanDisk Ultra (Serial: 4C531001560) mounted at 12:05:14 (Setupapi.dev.log / USBSTOR).",
        "VERIFIED: File 'Q3_Financial_Acquisition_Target.xlsx' accessed at 12:08:22 and written to E:\\Exfil at 12:10:05 (USN Journal record 4892011).",
        "VERIFIED: Chrome History database truncated at 12:12:30 (WAL header analysis).",
        "VERIFIED: Security Event Log cleared via wevtutil.exe generating Event ID 1102 at 12:13:15 by user CORP\\jdoe.",
        "VERIFIED: MFT $STANDARD_INFORMATION timestamp modified to 2024-03-12 09:00:00.000 while $FILE_NAME retains 2026-10-30 12:08:22 (Record 104928).",
        "VERIFIED: SDelete execution logged in PSReadLine history at 12:15:30."
      ],
      aiHypotheses: [
        "HYPOTHESIS: User attempted or researched secondary cloud exfiltration during the 12:10-12:12 window, explaining why browser data was targeted immediately following local USB copy.",
        "HYPOTHESIS: Timestomping tool was likely executed via an elevated PowerShell one-liner or standalone portable binary executed during the post-1102 log blackout window.",
        "HYPOTHESIS: Physical USB drive was unplugged immediately following SDelete completion around 12:16."
      ]
    },
    riskScore: 96,
    confidenceScore: 98,
    correlationHighlights: [
      {
        title: "Exfiltration Vector to USB",
        chain: ["ART-1001 (USB Mount)", "ART-1003 (Confidential File Open)", "ART-1004 (USN Copy to E:\\)"],
        description: "Direct temporal and volume linkage between USB mount on E:\\ and 26MB financial spreadsheet exfiltration."
      },
      {
        title: "Coordinated Anti-Forensics Destruction Cascade",
        chain: ["ART-1004 (Exfiltration Complete)", "ART-1005 (Browser Wipe)", "ART-1006 (Log Wipe 1102)", "ART-1007 (MFT Timestomp)"],
        description: "Four sequential evasion actions occurred in under 4 minutes, establishing clear consciousness of guilt and intent to thwart forensic recovery."
      }
    ],
    recommendations: [
      {
        priority: "P1 - Immediate",
        action: "Physical Evidence Seizure",
        target: "SanDisk Ultra 64GB (Serial: 4C531001560)",
        rationale: "Secure physical USB flash drive from suspect CORP\\jdoe before off-site disposal or physical destruction."
      },
      {
        priority: "P1 - Immediate",
        action: "Workstation Memory & Disk Forensics Lock",
        target: "FIN-WORKSTATION-042",
        rationale: "Immediately isolate workstation from corporate network and execute live RAM dump (winpmem) and raw physical disk image (E01)."
      },
      {
        priority: "P2 - High",
        action: "Perimeter Proxy & DNS Correlation",
        target: "Firewall & Zscaler Proxy Logs (12:05 - 12:20)",
        rationale: "Examine external web traffic during the 12:10-12:12 browser gap to verify if any data was mirrored to cloud storage."
      },
      {
        priority: "P3 - Moderate",
        action: "Active Directory Account Suspension & M365 Audit",
        target: "Account CORP\\jdoe",
        rationale: "Revoke Kerberos tokens, disable cloud authentication, and query Purview unified audit logs for unauthorized file shares."
      }
    ],
    analyzedAt: "2026-10-30T12:30:00Z",
    modelUsed: "gemini-3.8-flash (TraceX Anti-Forensic Reasoning Engine)"
  }
};
