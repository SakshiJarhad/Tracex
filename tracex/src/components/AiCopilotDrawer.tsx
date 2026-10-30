/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useRef, useEffect } from 'react';
import { 
  Terminal, 
  Send, 
  X, 
  Sparkles, 
  Bot, 
  User, 
  HelpCircle, 
  ShieldAlert, 
  RotateCcw,
  Layers,
  ArrowRight,
  Database
} from 'lucide-react';
import { InvestigationCase } from '../types/forensics';

interface AiCopilotDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  investigationCase: InvestigationCase;
}

interface Message {
  id: string;
  sender: 'user' | 'model';
  text: string;
  timestamp: string;
}

export const AiCopilotDrawer: React.FC<AiCopilotDrawerProps> = ({
  isOpen,
  onClose,
  investigationCase
}) => {
  const hasEvidence = investigationCase.artifacts.length > 0;

  const [messages, setMessages] = useState<Message[]>([
    {
      id: 'init-1',
      sender: 'model',
      text: hasEvidence
        ? `Hello Examiner. I am TraceX AI Copilot, powered by server-side Gemini 3.8 Flash. I have synchronized with the active investigation on **${investigationCase.targetHost}** (${investigationCase.artifacts.length} observed artifacts, ${investigationCase.findings.length} anti-forensic triggers detected).\n\nMode: ${investigationCase.isDemoDataset ? '**Synthetic Demo Scenario**' : '**Live Observed Evidence**'}.\n\nAsk me anything regarding artifact correlation, $STANDARD_INFO vs $FILE_NAME timestomping mechanics, or unlogged timeline intervals.`
        : `Hello Examiner. TraceX AI Copilot is online. However, no evidence is currently loaded in the investigation workspace. Please upload a forensic CSV/JSON export or restore the synthetic demonstration case so I can reason over your actual artifacts.`,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    }
  ]);

  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const quickQuestions = hasEvidence 
    ? [
        "Why was $STANDARD_INFO timestomped while $FILE_NAME was not?",
        "What occurred during the unlogged timeline intervals?",
        "How does Event ID 1102 connect to the exfiltration vector?",
        "What are the prioritized legal preservation steps?"
      ]
    : [
        "How does TraceX detect timestomping in NTFS?",
        "What signatures indicate Event ID 1102 log wiping?",
        "How does Chromium WAL truncation conceal history?"
      ];

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    if (isOpen) {
      scrollToBottom();
    }
  }, [messages, isOpen]);

  const handleSend = async (messageText: string) => {
    const textToSend = messageText.trim();
    if (!textToSend || isLoading) return;

    const userMsg: Message = {
      id: `usr-${Date.now()}`,
      sender: 'user',
      text: textToSend,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    setMessages(prev => [...prev, userMsg]);
    setInput('');
    setIsLoading(true);

    try {
      const response = await fetch('/api/gemini/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: textToSend,
          caseContext: {
            caseId: investigationCase.caseId,
            caseName: investigationCase.caseName,
            targetHost: investigationCase.targetHost,
            isDemoDataset: investigationCase.isDemoDataset,
            artifactCount: investigationCase.artifacts.length,
            findingsCount: investigationCase.findings.length,
            artifactsSample: investigationCase.artifacts.slice(0, 10).map(a => ({
              id: a.id,
              name: a.name,
              time: a.timestamp,
              source: a.source,
              type: a.eventType,
              desc: a.description,
              risk: a.riskLevel
            })),
            findingsSample: investigationCase.findings.map(f => ({
              title: f.title,
              technique: f.mitreTechnique,
              severity: f.severity,
              reason: f.detectionReason
            }))
          }
        })
      });

      if (!response.ok) {
        throw new Error(`Server returned HTTP ${response.status}`);
      }

      const data = await response.json();
      const modelMsg: Message = {
        id: `mod-${Date.now()}`,
        sender: 'model',
        text: data.reply || 'No analysis available.',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };
      setMessages(prev => [...prev, modelMsg]);
    } catch (err: any) {
      // Deterministic fallback based on actual evidence
      let fallback = `[TraceX DFIR Engine]: In evaluating "${textToSend}" based on current evidence: `;
      if (investigationCase.findings.length > 0) {
        const topFinding = investigationCase.findings[0];
        fallback += `The primary forensic trigger is '${topFinding.title}' (${topFinding.mitreTechnique}). The observed evidence demonstrates ${topFinding.detectionReason}. This establishes intentional evidence tampering under MITRE ATT&CK guidelines.`;
      } else {
        fallback += `No anti-forensics indicators have been flagged in the current evidence set. Ensure you have ingested sufficient system event logs or filesystem journals.`;
      }

      setMessages(prev => [
        ...prev,
        {
          id: `mod-${Date.now()}`,
          sender: 'model',
          text: fallback,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        }
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-y-0 right-0 z-50 w-full sm:w-[460px] bg-[#090e20] border-l border-cyan-500/40 shadow-[-10px_0_40px_rgba(0,0,0,0.8)] flex flex-col">
      {/* Header */}
      <div className="p-4 border-b border-slate-800 bg-[#060a17] flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-lg bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center">
            <Sparkles className="w-4 h-4 text-cyan-400" />
          </div>
          <div>
            <h3 className="font-display font-bold text-sm text-white">
              TraceX Forensic Copilot
            </h3>
            <span className="text-[10px] font-mono text-cyan-300">
              Gemini 3.8 Flash DFIR Engine
            </span>
          </div>
        </div>

        <button
          onClick={onClose}
          className="p-1.5 rounded text-slate-400 hover:text-white hover:bg-slate-800"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Provenance Pill Bar */}
      <div className="px-4 py-2 border-b border-slate-800/80 bg-slate-950 flex items-center justify-between text-[11px] font-mono">
        <span className="text-slate-400">Target Host: <strong className="text-white">{investigationCase.targetHost}</strong></span>
        <span className={`px-1.5 py-0.2 rounded border ${
          investigationCase.isDemoDataset 
            ? 'bg-blue-950/60 text-blue-300 border-blue-500/30' 
            : hasEvidence 
            ? 'bg-emerald-950/60 text-emerald-300 border-emerald-500/30'
            : 'bg-slate-900 text-slate-500 border-slate-800'
        }`}>
          {investigationCase.isDemoDataset ? 'DEMO DATA' : hasEvidence ? `${investigationCase.artifacts.length} ARTIFACTS` : 'EMPTY'}
        </span>
      </div>

      {/* Quick Prompts Bar */}
      <div className="p-3 border-b border-slate-800/80 bg-slate-950/60 overflow-x-auto scrollbar-none flex gap-2">
        {quickQuestions.map((q, idx) => (
          <button
            key={idx}
            onClick={() => handleSend(q)}
            disabled={isLoading}
            className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 hover:border-cyan-500/50 text-[11px] font-mono text-slate-300 hover:text-cyan-300 whitespace-nowrap transition disabled:opacity-50"
          >
            {q}
          </button>
        ))}
      </div>

      {/* Messages Scroll Area */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.map((msg) => {
          const isUser = msg.sender === 'user';
          return (
            <div
              key={msg.id}
              className={`flex flex-col ${isUser ? 'items-end' : 'items-start'}`}
            >
              <div className="flex items-center gap-1.5 mb-1 text-[10px] font-mono text-slate-500">
                <span>{isUser ? 'Examiner' : 'TraceX Gemini DFIR AI'}</span>
                <span>•</span>
                <span>{msg.timestamp}</span>
              </div>

              <div
                className={`p-3.5 rounded-xl max-w-[90%] text-xs font-sans leading-relaxed ${
                  isUser
                    ? 'bg-cyan-600 text-white rounded-tr-none'
                    : 'bg-slate-900/90 text-slate-200 border border-slate-800 rounded-tl-none font-mono whitespace-pre-line'
                }`}
              >
                {msg.text}
              </div>
            </div>
          );
        })}

        {isLoading && (
          <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 p-2">
            <Sparkles className="w-4 h-4 animate-spin" />
            <span>Consulting Gemini 3.8 Flash forensic model with case evidence...</span>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Input Form */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          handleSend(input);
        }}
        className="p-3 border-t border-slate-800 bg-[#060a17] flex items-center gap-2"
      >
        <input
          type="text"
          placeholder="Ask about timestamps, MFT records, log wipe..."
          value={input}
          onChange={(e) => setInput(e.target.value)}
          disabled={isLoading}
          className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
        />
        <button
          type="submit"
          disabled={isLoading || !input.trim()}
          className="p-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white transition disabled:opacity-50"
        >
          <Send className="w-4 h-4" />
        </button>
      </form>
    </div>
  );
};
