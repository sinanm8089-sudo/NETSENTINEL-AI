"use client";

import React, { useState } from "react";
import {
  BrainCircuit,
  CheckCircle2,
  ShieldAlert,
  Sparkles,
  FileSearch,
  AlertCircle,
  Cpu,
} from "lucide-react";
import { FindingRecord } from "@/lib/types";
import { apiFetch } from "@/lib/api";

interface AIAnalystViewProps {
  findings: FindingRecord[];
  role: string;
  onRefresh: () => void;
}

export default function AIAnalystView({
  findings,
  role,
  onRefresh,
}: AIAnalystViewProps) {
  const [selectedFinding, setSelectedFinding] = useState<FindingRecord | null>(
    findings[0] || null
  );
  const [question, setQuestion] = useState<string>(
    "Which newly exposed services should the SOC team investigate first and why?"
  );
  const [providerPref, setProviderPref] = useState<string>("AUTO");
  const [nlResponse, setNlResponse] = useState<any | null>(null);
  const [loadingAI, setLoadingAI] = useState<boolean>(false);

  const handleAskAnalyst = async () => {
    if (!question.trim()) return;
    setLoadingAI(true);
    try {
      const res = await apiFetch<any>(
        "/ai/investigate",
        {
          method: "POST",
          body: JSON.stringify({
            question,
            preferred_provider: providerPref,
          }),
        },
        role
      );
      setNlResponse(res);
    } catch (err) {
      console.error(err);
    } finally {
      setLoadingAI(false);
    }
  };

  const handleUpdateFindingStatus = async (findingId: string, newStatus: string) => {
    try {
      await apiFetch(
        `/findings/${findingId}/status?new_status=${newStatus}`,
        { method: "PATCH" },
        role
      );
      onRefresh();
    } catch (err: any) {
      alert(`Permission or API Error: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Natural-Language Hybrid AI Analyst Console */}
      <div className="rounded-xl border border-cyan-500/30 bg-gradient-to-r from-[#0b1329] to-[#0f172a] p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-500/20 border border-cyan-400/40 text-cyan-300">
              <BrainCircuit className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-base font-semibold text-white flex items-center gap-2">
                Module 5 & Innovation 4 — Hybrid AI Security Analyst & Autonomous Exposure Investigator
              </h2>
              <p className="text-xs text-slate-300">
                100% Independent Statistical Risk Engine • Pluggable Local Ollama & Cloud Gemini/OpenAI • Mandatory Evidence Traceability
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <label className="text-xs text-slate-400">Execution Mode:</label>
            <select
              value={providerPref}
              onChange={(e) => setProviderPref(e.target.value)}
              className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-cyan-200 focus:border-cyan-500 focus:outline-none"
            >
              <option value="AUTO">AUTO (Hybrid Local/Cloud + Statistical Fallback)</option>
              <option value="STATISTICAL_OFFLINE">STATISTICAL_OFFLINE (100% Offline Deterministic)</option>
              <option value="LOCAL_OLLAMA">LOCAL_OLLAMA (Local LLM via localhost:11434)</option>
              <option value="CLOUD_GEMINI">CLOUD_GEMINI (Cloud Gemini API)</option>
            </select>
          </div>
        </div>

        <div className="flex flex-col gap-2 sm:flex-row">
          <input
            type="text"
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            placeholder="Ask the Explainable Security Analyst about exposures, port mismatches, or network drift..."
            className="flex-1 rounded-lg border border-slate-700 bg-slate-950/90 px-3.5 py-2 text-xs text-white placeholder-slate-500 focus:border-cyan-400 focus:outline-none"
          />
          <button
            onClick={handleAskAnalyst}
            disabled={loadingAI}
            className="flex items-center justify-center gap-1.5 rounded-lg bg-cyan-600 px-4 py-2 text-xs font-semibold text-white hover:bg-cyan-500 disabled:opacity-50"
          >
            <Sparkles className="h-4 w-4" />
            {loadingAI ? "Synthesizing..." : "Analyze with Evidence"}
          </button>
        </div>

        {nlResponse && (
          <div className="rounded-xl border border-cyan-500/30 bg-slate-950/90 p-4 space-y-2 text-xs">
            <div className="flex items-center justify-between text-cyan-300 border-b border-slate-800 pb-2">
              <span className="font-semibold">
                Analyst Investigation Synthesis (Engine: {nlResponse.provider_used})
              </span>
              <span className="text-[11px] text-emerald-400">
                {nlResponse.safety_attestation}
              </span>
            </div>
            <pre className="whitespace-pre-wrap font-sans text-slate-200 leading-relaxed">
              {nlResponse.answer_markdown}
            </pre>
          </div>
        )}
      </div>

      {/* Findings List & Deep Explainable Evidence / Autonomous Investigation Split */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
        {/* Left column: Prioritized Security Findings */}
        <div className="lg:col-span-5 space-y-3">
          <h3 className="text-sm font-semibold text-white flex items-center justify-between">
            <span>Prioritized Findings ({findings.length})</span>
            <span className="text-xs font-normal text-slate-400">
              Sorted by Statistical Risk Score (0–100)
            </span>
          </h3>

          <div className="space-y-2.5 max-h-[680px] overflow-y-auto pr-1">
            {findings.map((f) => {
              const isSelected = selectedFinding?.finding_id === f.finding_id;
              return (
                <div
                  key={f.finding_id}
                  onClick={() => setSelectedFinding(f)}
                  className={`cursor-pointer rounded-xl border p-3.5 transition ${
                    isSelected
                      ? "border-cyan-400 bg-cyan-950/25"
                      : "border-slate-800 bg-[#0b1120] hover:border-slate-700"
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <span
                      className={`rounded px-2 py-0.5 text-[11px] font-bold ${
                        f.severity === "Critical"
                          ? "bg-red-500/20 text-red-300 border border-red-500/40"
                          : f.severity === "High"
                          ? "bg-orange-500/20 text-orange-300 border border-orange-500/40"
                          : "bg-amber-500/20 text-amber-300 border border-amber-500/40"
                      }`}
                    >
                      {f.severity} • {f.risk_score}/100
                    </span>
                    <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-[10px] text-slate-300">
                      {f.status}
                    </span>
                  </div>
                  <div className="mt-2 text-xs font-semibold text-white">
                    {f.title}
                  </div>
                  <div className="mt-1.5 flex flex-wrap items-center gap-2 text-[11px] text-slate-400">
                    <span className="font-mono text-cyan-300">
                      {f.evidence_json?.ip_address}:{f.evidence_json?.port}/{f.evidence_json?.protocol}
                    </span>
                    <span>•</span>
                    <span>{f.category}</span>
                    {f.investigation && (
                      <span className="rounded bg-purple-500/20 border border-purple-500/40 px-1.5 py-0.2 text-[10px] text-purple-300">
                        7-Step Auto-Investigation Ready
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right column: Selected Finding Explainable Breakdown & Autonomous Investigator */}
        <div className="lg:col-span-7 space-y-4">
          {!selectedFinding ? (
            <div className="rounded-xl border border-slate-800 bg-[#0b1120] p-12 text-center text-xs text-slate-400">
              Select a finding on the left to inspect its statistical score breakdown, AI explanation, and Autonomous Exposure Investigation record.
            </div>
          ) : (
            <div className="rounded-xl border border-slate-800 bg-[#0b1120] p-5 space-y-5">
              <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-800 pb-4">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs text-cyan-400">
                      Finding #{selectedFinding.finding_id.slice(0, 8)}
                    </span>
                    <span className="rounded bg-slate-800 px-2 py-0.5 text-[11px] text-slate-300">
                      Engine: {selectedFinding.ai_provider_used}
                    </span>
                  </div>
                  <h3 className="mt-1 text-base font-bold text-white">
                    {selectedFinding.title}
                  </h3>
                </div>

                <div className="flex items-center gap-1.5">
                  {["OPEN", "INVESTIGATING", "ACKNOWLEDGED", "RESOLVED"].map((st) => (
                    <button
                      key={st}
                      onClick={() =>
                        handleUpdateFindingStatus(selectedFinding.finding_id, st)
                      }
                      className={`rounded px-2 py-1 text-[10px] font-semibold transition ${
                        selectedFinding.status === st
                          ? "bg-cyan-600 text-white"
                          : "bg-slate-800 text-slate-400 hover:bg-slate-700"
                      }`}
                    >
                      {st}
                    </button>
                  ))}
                </div>
              </div>

              {/* Section 8: Explainable Statistical Risk Factor Breakdown (0-100) */}
              <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-4 space-y-3">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-semibold text-white flex items-center gap-1.5">
                    <Cpu className="h-4 w-4 text-cyan-400" />
                    Independent Statistical Risk Formula Breakdown
                  </span>
                  <span className="font-mono font-bold text-amber-300">
                    Total Score: {selectedFinding.risk_score} / 100 ({selectedFinding.severity})
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-5 text-xs">
                  {[
                    {
                      label: "Service Exposure",
                      val: selectedFinding.score_breakdown_json?.service_exposure ?? 0,
                      max: 35,
                    },
                    {
                      label: "Asset Criticality",
                      val: selectedFinding.score_breakdown_json?.asset_criticality ?? 0,
                      max: 25,
                    },
                    {
                      label: "Unexpected Drift",
                      val: selectedFinding.score_breakdown_json?.unexpected_change ?? 0,
                      max: 20,
                    },
                    {
                      label: "Version Intel",
                      val: selectedFinding.score_breakdown_json?.version_intelligence ?? 0,
                      max: 10,
                    },
                    {
                      label: "Port Mismatch",
                      val: selectedFinding.score_breakdown_json?.service_mismatch ?? 0,
                      max: 10,
                    },
                  ].map((item) => (
                    <div
                      key={item.label}
                      className="rounded-lg border border-slate-800 bg-slate-950/80 p-2.5"
                    >
                      <div className="text-[10px] text-slate-400">{item.label}</div>
                      <div className="mt-1 font-mono text-sm font-bold text-cyan-300">
                        +{item.val}{" "}
                        <span className="text-[10px] font-normal text-slate-500">
                          / {item.max}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Innovation 2: Autonomous Exposure Investigator 7-Step Record */}
              {selectedFinding.investigation && (
                <div className="rounded-xl border border-purple-500/40 bg-purple-950/15 p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <h4 className="text-xs font-bold uppercase tracking-wider text-purple-300 flex items-center gap-1.5">
                      <FileSearch className="h-4 w-4 text-purple-400" />
                      Innovation 2 — Autonomous Exposure Investigator (7-Step Verification)
                    </h4>
                    <span className="text-[11px] text-purple-200">
                      Owner Routed: {selectedFinding.investigation.notified_owner}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300">
                    {selectedFinding.investigation.business_impact_summary}
                  </p>
                  <div className="space-y-1.5">
                    {selectedFinding.investigation.steps_completed_json.map((step) => (
                      <div
                        key={step.step}
                        className="flex items-start gap-2 rounded-lg bg-slate-950/75 p-2 text-xs border border-slate-800/80"
                      >
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0 mt-0.5" />
                        <div>
                          <span className="font-semibold text-white">
                            Step {step.step} — {step.action}:
                          </span>{" "}
                          <span className="text-slate-300">{step.detail}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Explainable AI Security Analyst Narrative & Uncertainty Note */}
              <div className="space-y-3">
                <h4 className="text-xs font-bold uppercase tracking-wider text-cyan-300">
                  Explainable Security Analysis & Traceable Evidence
                </h4>
                <pre className="whitespace-pre-wrap rounded-xl border border-slate-800 bg-slate-950/90 p-4 font-sans text-xs text-slate-200 leading-relaxed">
                  {selectedFinding.ai_explanation}
                </pre>

                {selectedFinding.uncertainty_note && (
                  <div className="flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-950/20 p-3 text-xs text-amber-200">
                    <AlertCircle className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
                    <div>
                      <strong>Analytical Uncertainty & Non-Compromise Attestation:</strong>{" "}
                      {selectedFinding.uncertainty_note}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

