"use client";

import React, { useState } from "react";
import {
  Network,
  Server,
  ShieldAlert,
  CheckCircle2,
  GitCompare,
  Layers,
  Lock,
  Cpu,
  Info,
  AlertTriangle,
} from "lucide-react";
import { TopologyEdge, TopologyNode } from "@/lib/types";
import { apiFetch } from "@/lib/api";

interface TopologyCanvasProps {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  stats: Record<string, any>;
  snapshots: Array<{
    snapshot_id: string;
    label: string;
    captured_at: string;
    stats: Record<string, any>;
  }>;
  role: string;
  onRefresh: () => void;
}

export default function TopologyCanvas({
  nodes,
  edges,
  stats,
  snapshots,
  role,
}: TopologyCanvasProps) {
  const [selectedNode, setSelectedNode] = useState<TopologyNode | null>(null);
  const [subnetFilter, setSubnetFilter] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [twinMode, setTwinMode] = useState<boolean>(false);
  const [baselineSnap, setBaselineSnap] = useState<string>(
    snapshots.length > 1 ? snapshots[snapshots.length - 1].snapshot_id : snapshots[0]?.snapshot_id || ""
  );
  const [targetSnap, setTargetSnap] = useState<string>(snapshots[0]?.snapshot_id || "");
  const [diffResult, setDiffResult] = useState<any | null>(null);
  const [diffLoading, setDiffLoading] = useState<boolean>(false);

  const subnets = nodes.filter((n) => n.type === "SUBNET");
  const hosts = nodes.filter((n) => {
    if (n.type !== "HOST") return false;
    if (subnetFilter !== "ALL" && n.subnet !== subnetFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        (n.ip_address || "").toLowerCase().includes(q) ||
        (n.hostname || "").toLowerCase().includes(q) ||
        (n.business_service || "").toLowerCase().includes(q) ||
        (n.operating_system || "").toLowerCase().includes(q)
      );
    }
    return true;
  });

  const getPortsForHost = (ip?: string) => {
    if (!ip) return [];
    const hostNodeId = `host:${ip}`;
    const portTargetIds = new Set(
      edges.filter((e) => e.source === hostNodeId).map((e) => e.target)
    );
    return nodes.filter((n) => n.type === "SERVICE_PORT" && portTargetIds.has(n.id));
  };

  const getRiskBadgeColor = (score: number) => {
    if (score >= 80) return "border-red-500/70 bg-red-950/50 text-red-300";
    if (score >= 60) return "border-orange-500/70 bg-orange-950/50 text-orange-300";
    if (score >= 40) return "border-amber-500/70 bg-amber-950/50 text-amber-300";
    if (score >= 20) return "border-cyan-500/70 bg-cyan-950/50 text-cyan-300";
    return "border-emerald-500/60 bg-emerald-950/40 text-emerald-300";
  };

  const handleCompareSnapshots = async () => {
    if (!baselineSnap || !targetSnap) return;
    setDiffLoading(true);
    try {
      const data = await apiFetch<any>(
        `/topology/compare?baseline_id=${encodeURIComponent(baselineSnap)}&target_id=${encodeURIComponent(targetSnap)}`,
        {},
        role
      );
      setDiffResult(data);
    } catch (err) {
      console.error(err);
    } finally {
      setDiffLoading(false);
    }
  };

  return (
    <div className="space-y-5">
      {/* Top Control & Digital Twin Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-slate-800 bg-[#0b1120] p-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Network className="h-5 w-5" />
          </div>
          <div>
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              Live Enterprise Network Topology & Exposure Digital Twin
              <span className="rounded-full bg-cyan-500/15 px-2.5 py-0.5 text-xs font-medium text-cyan-300 border border-cyan-500/30">
                Network → Subnet → Host → Service → Port
              </span>
            </h2>
            <p className="text-xs text-slate-400">
              Observed relationships vs. inferred /24 subnet groupings • Gateway labels strictly require route verification
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filter host IP, hostname, OS, service..."
            className="rounded-lg border border-slate-700 bg-slate-900/90 px-3 py-1.5 text-xs text-slate-100 placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
          />
          <select
            value={subnetFilter}
            onChange={(e) => setSubnetFilter(e.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none"
          >
            <option value="ALL">All Authorized Subnets ({subnets.length})</option>
            {subnets.map((s) => (
              <option key={s.id} value={s.subnet}>
                {s.subnet}
              </option>
            ))}
          </select>
          <button
            onClick={() => setTwinMode(!twinMode)}
            className={`flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition ${
              twinMode
                ? "border-purple-500 bg-purple-500/20 text-purple-200"
                : "border-slate-700 bg-slate-800/80 text-slate-300 hover:border-purple-400"
            }`}
          >
            <GitCompare className="h-3.5 w-3.5" />
            {twinMode ? "Hide Digital Twin Comparator" : "Digital Twin Time-Travel Diff"}
          </button>
        </div>
      </div>

      {/* Innovation 1: Network Exposure Digital Twin Historical Comparison Panel */}
      {twinMode && (
        <div className="rounded-xl border border-purple-500/40 bg-purple-950/15 p-4 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-semibold text-purple-200 flex items-center gap-2">
                <GitCompare className="h-4 w-4 text-purple-400" />
                Innovation 1 — Network Exposure Digital Twin (Historical Snapshot Comparison)
              </h3>
              <p className="text-xs text-slate-400">
                Compare any baseline topology snapshot against a later scan snapshot to inspect newly exposed services, host changes, and risk score shifts.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <select
                value={baselineSnap}
                onChange={(e) => setBaselineSnap(e.target.value)}
                className="rounded-lg border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-xs text-slate-200"
              >
                {snapshots.map((s) => (
                  <option key={s.snapshot_id} value={s.snapshot_id}>
                    Baseline: {s.label}
                  </option>
                ))}
              </select>
              <span className="text-xs text-slate-400">→</span>
              <select
                value={targetSnap}
                onChange={(e) => setTargetSnap(e.target.value)}
                className="rounded-lg border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-xs text-slate-200"
              >
                {snapshots.map((s) => (
                  <option key={s.snapshot_id} value={s.snapshot_id}>
                    Target: {s.label}
                  </option>
                ))}
              </select>
              <button
                onClick={handleCompareSnapshots}
                disabled={diffLoading}
                className="rounded-lg bg-purple-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-purple-500 disabled:opacity-50"
              >
                {diffLoading ? "Comparing..." : "Compare Snapshots"}
              </button>
            </div>
          </div>

          {diffResult && (
            <div className="grid grid-cols-1 gap-3 md:grid-cols-3 pt-2 border-t border-purple-500/20">
              <div className="rounded-lg border border-slate-800 bg-slate-900/80 p-3">
                <div className="text-xs font-semibold text-emerald-400 mb-1.5">
                  Newly Discovered Hosts ({diffResult.added_hosts?.length || 0})
                </div>
                {diffResult.added_hosts?.length === 0 ? (
                  <p className="text-xs text-slate-500">No new hosts between selected snapshots.</p>
                ) : (
                  <ul className="space-y-1 text-xs">
                    {diffResult.added_hosts.map((h: any) => (
                      <li key={h.id} className="text-slate-200 font-mono">
                        + {h.ip_address} ({h.hostname || "unlabeled"}) — Risk {h.risk_score}
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-900/80 p-3">
                <div className="text-xs font-semibold text-red-400 mb-1.5">
                  Newly Exposed Service Ports ({diffResult.added_service_ports?.length || 0})
                </div>
                {diffResult.added_service_ports?.length === 0 ? (
                  <p className="text-xs text-slate-500">No new open ports between selected snapshots.</p>
                ) : (
                  <ul className="space-y-1 text-xs">
                    {diffResult.added_service_ports.map((p: any) => (
                      <li key={p.id} className="text-red-200 font-mono">
                        + {p.id.replace("port:", "")} [{p.detected_service}] (Score: {p.risk_score})
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-900/80 p-3">
                <div className="text-xs font-semibold text-amber-400 mb-1.5">
                  Host Risk & Status Deltas ({diffResult.host_risk_and_status_deltas?.length || 0})
                </div>
                {diffResult.host_risk_and_status_deltas?.length === 0 ? (
                  <p className="text-xs text-slate-500">No host risk shifts recorded.</p>
                ) : (
                  <ul className="space-y-1 text-xs">
                    {diffResult.host_risk_and_status_deltas.map((d: any) => (
                      <li key={d.ip_address} className="text-slate-200 font-mono">
                        {d.ip_address}: Risk {d.previous_risk} → {d.current_risk} (
                        <span className={d.risk_delta > 0 ? "text-red-400" : "text-emerald-400"}>
                          {d.risk_delta > 0 ? `+${d.risk_delta}` : d.risk_delta}
                        </span>
                        )
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Main Visual Topology Grid & Inspector Drawer */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
        <div className="lg:col-span-8 space-y-6 rounded-xl border border-slate-800 bg-[#070c18] p-5">
          {/* Root Enterprise Core Node Banner */}
          <div className="flex flex-col items-center">
            <div className="flex items-center gap-3 rounded-xl border border-cyan-500/50 bg-cyan-950/30 px-5 py-2.5 shadow-lg shadow-cyan-950/30">
              <Layers className="h-5 w-5 text-cyan-400" />
              <div>
                <div className="text-xs font-bold uppercase tracking-wider text-cyan-300">
                  NETSENTINEL Authorized Network Core
                </div>
                <div className="text-[11px] text-slate-400">
                  {stats.total_subnets || 0} Subnets • {stats.total_hosts || 0} Hosts • {stats.open_service_ports || 0} Active Service Ports
                </div>
              </div>
            </div>
            <div className="h-5 w-0.5 bg-gradient-to-b from-cyan-500/60 to-slate-700" />
          </div>

          {/* Subnet Groupings */}
          <div className="space-y-6">
            {subnets
              .filter((s) => subnetFilter === "ALL" || s.subnet === subnetFilter)
              .map((subnetNode) => {
                const subnetHosts = hosts.filter((h) => h.subnet === subnetNode.subnet);
                return (
                  <div
                    key={subnetNode.id}
                    className="rounded-xl border border-slate-800/90 bg-[#0b1324]/90 p-4 space-y-4"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
                      <div className="flex items-center gap-2.5">
                        <span className="h-2.5 w-2.5 rounded-full bg-cyan-400 animate-pulse" />
                        <span className="font-mono text-sm font-bold text-white">
                          Subnet Enclave: {subnetNode.subnet}
                        </span>
                        <span className="rounded bg-slate-800 px-2 py-0.5 text-[11px] text-slate-300 border border-slate-700">
                          Relationship: INFERRED_SUBNET_GROUPING
                        </span>
                      </div>
                      <div className="text-xs text-slate-400">
                        Peak Host Risk:{" "}
                        <span className="font-semibold text-amber-300">
                          {subnetNode.risk_score}/100
                        </span>
                      </div>
                    </div>

                    {/* Host Nodes inside Subnet */}
                    <div className="grid grid-cols-1 gap-3.5 md:grid-cols-2">
                      {subnetHosts.map((host) => {
                        const hostPorts = getPortsForHost(host.ip_address);
                        const isSelected = selectedNode?.id === host.id;
                        return (
                          <div
                            key={host.id}
                            onClick={() => setSelectedNode(host)}
                            className={`cursor-pointer rounded-xl border p-3.5 transition all ${
                              isSelected
                                ? "border-cyan-400 bg-cyan-950/25 ring-1 ring-cyan-400/40"
                                : "border-slate-800 bg-slate-900/75 hover:border-slate-600"
                            }`}
                          >
                            <div className="flex items-start justify-between gap-2">
                              <div className="flex items-center gap-2">
                                <Server
                                  className={`h-4 w-4 ${
                                    host.status === "ACTIVE"
                                      ? "text-emerald-400"
                                      : "text-red-400"
                                  }`}
                                />
                                <div>
                                  <div className="font-mono text-sm font-bold text-white flex items-center gap-1.5">
                                    {host.ip_address}
                                    {host.is_gateway_verified && (
                                      <span className="rounded bg-emerald-500/20 border border-emerald-500/40 px-1.5 py-0.2 text-[10px] font-sans font-semibold text-emerald-300">
                                        Verified Gateway
                                      </span>
                                    )}
                                  </div>
                                  <div className="text-xs text-slate-400 truncate max-w-[210px]">
                                    {host.hostname || "unlabeled-host"}
                                  </div>
                                </div>
                              </div>
                              <span
                                className={`rounded-md border px-2 py-0.5 text-xs font-bold ${getRiskBadgeColor(
                                  host.risk_score
                                )}`}
                              >
                                Risk {host.risk_score}
                              </span>
                            </div>

                            <div className="mt-2.5 flex flex-wrap items-center gap-1.5 text-[11px] text-slate-300">
                              <span className="rounded bg-slate-800 px-2 py-0.5 text-cyan-200">
                                {host.business_service || "Enterprise Asset"}
                              </span>
                              <span className="rounded bg-slate-800/80 px-2 py-0.5 text-slate-400">
                                {host.operating_system || "Unknown OS"}
                              </span>
                            </div>

                            {/* Child Service & Port Nodes */}
                            <div className="mt-3 pt-2.5 border-t border-slate-800/80">
                              <div className="text-[10px] uppercase tracking-wider text-slate-400 mb-1.5">
                                Exposed Service & Port Nodes ({hostPorts.length})
                              </div>
                              <div className="flex flex-wrap gap-1.5">
                                {hostPorts.map((pNode) => (
                                  <button
                                    key={pNode.id}
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      setSelectedNode(pNode);
                                    }}
                                    className={`rounded-md border px-2 py-1 font-mono text-[11px] transition flex items-center gap-1 ${
                                      pNode.service_mismatch
                                        ? "border-red-500 bg-red-950/60 text-red-200"
                                        : getRiskBadgeColor(pNode.risk_score)
                                    }`}
                                  >
                                    <span>
                                      {pNode.port_number}/{pNode.protocol}
                                    </span>
                                    <span className="opacity-85">
                                      ({pNode.detected_service})
                                    </span>
                                    {pNode.service_mismatch && (
                                      <AlertTriangle className="h-3 w-3 text-red-300" />
                                    )}
                                  </button>
                                ))}
                              </div>
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

        {/* Right Host / Service Port Detail Inspector Panel */}
        <div className="lg:col-span-4 rounded-xl border border-slate-800 bg-[#0b1120] p-5 h-fit sticky top-6">
          <h3 className="text-sm font-semibold text-white flex items-center gap-2 border-b border-slate-800 pb-3">
            <Info className="h-4 w-4 text-cyan-400" />
            Topology Node Telemetry Inspector
          </h3>

          {!selectedNode ? (
            <div className="py-12 text-center text-xs text-slate-400 space-y-2">
              <Cpu className="h-8 w-8 mx-auto text-slate-600" />
              <p>Click any Host or Service/Port node in the topology graph to inspect its live Nmap intelligence, business context, and risk evidence.</p>
            </div>
          ) : selectedNode.type === "HOST" ? (
            <div className="mt-4 space-y-3.5 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-mono text-base font-bold text-cyan-300">
                  {selectedNode.ip_address}
                </span>
                <span
                  className={`rounded-md border px-2 py-0.5 font-semibold ${getRiskBadgeColor(
                    selectedNode.risk_score
                  )}`}
                >
                  {selectedNode.risk_classification} ({selectedNode.risk_score}/100)
                </span>
              </div>
              <div className="space-y-1.5 rounded-lg bg-slate-900/90 p-3 border border-slate-800">
                <div>
                  <span className="text-slate-400">Hostname:</span>{" "}
                  <span className="font-mono text-slate-100">
                    {selectedNode.hostname || "N/A"}
                  </span>
                </div>
                <div>
                  <span className="text-slate-400">Subnet Enclave:</span>{" "}
                  <span className="font-mono text-slate-100">{selectedNode.subnet}</span>
                </div>
                <div>
                  <span className="text-slate-400">Operating System:</span>{" "}
                  <span className="text-slate-100">{selectedNode.operating_system}</span>
                </div>
                <div>
                  <span className="text-slate-400">Business Service:</span>{" "}
                  <span className="font-semibold text-cyan-300">
                    {selectedNode.business_service}
                  </span>
                </div>
                <div>
                  <span className="text-slate-400">Owner Team:</span>{" "}
                  <span className="text-slate-200">{selectedNode.owner_team}</span>
                </div>
                <div>
                  <span className="text-slate-400">Asset Criticality:</span>{" "}
                  <span className="font-semibold text-amber-300">
                    {selectedNode.criticality}
                  </span>
                </div>
                <div>
                  <span className="text-slate-400">Gateway Verification:</span>{" "}
                  {selectedNode.is_gateway_verified ? (
                    <span className="text-emerald-400 font-medium">
                      Verified ({selectedNode.gateway_evidence})
                    </span>
                  ) : (
                    <span className="text-slate-400">
                      Standard Host (No gateway route claim)
                    </span>
                  )}
                </div>
              </div>
            </div>
          ) : (
            <div className="mt-4 space-y-3.5 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-mono text-sm font-bold text-amber-300">
                  {selectedNode.label}
                </span>
                <span
                  className={`rounded-md border px-2 py-0.5 font-semibold ${getRiskBadgeColor(
                    selectedNode.risk_score
                  )}`}
                >
                  Score {selectedNode.risk_score}/100
                </span>
              </div>

              {selectedNode.service_mismatch && (
                <div className="rounded-lg border border-red-500/50 bg-red-950/40 p-2.5 text-red-200">
                  <strong>Port-to-Service Mismatch Detected!</strong> Conventional port expects{" "}
                  <code>{selectedNode.conventional_service}</code>, but Nmap service probe identified{" "}
                  <code>{selectedNode.detected_service}</code>.
                </div>
              )}

              <div className="space-y-2 rounded-lg bg-slate-900/90 p-3 border border-slate-800">
                <div>
                  <span className="text-slate-400">Conventional Port Service:</span>{" "}
                  <code className="text-slate-200">{selectedNode.conventional_service}</code>
                </div>
                <div>
                  <span className="text-slate-400">Actual Detected Service:</span>{" "}
                  <code className="text-cyan-300 font-bold">{selectedNode.detected_service}</code>
                </div>
                <div>
                  <span className="text-slate-400">Exposure Class:</span>{" "}
                  <code className="text-amber-300">{selectedNode.exposure_class}</code>
                </div>
                <div>
                  <span className="text-slate-400">Typical Application Purpose:</span>
                  <p className="mt-1 text-slate-200 leading-relaxed">
                    {selectedNode.typical_purpose}
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

