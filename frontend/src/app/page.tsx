"use client";

import React, { useEffect, useState, useCallback } from "react";
import {
  Shield,
  Activity,
  Network,
  Server,
  Terminal as TerminalIcon,
  BrainCircuit,
  GitPullRequestDraft,
  Radar,
  Bell,
  FileSpreadsheet,
  FileText,
  FileCode2,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Lock,
  Play,
  Sparkles,
  Sliders,
  Eye,
} from "lucide-react";
import { apiFetch, getReportUrl, WS_BASE } from "@/lib/api";
import {
  AssetRecord,
  FindingRecord,
  NetworkChangeRecord,
  PortRecord,
  ScanJobRecord,
} from "@/lib/types";
import TopologyCanvas from "@/components/TopologyCanvas";
import TerminalPanel from "@/components/TerminalPanel";
import AIAnalystView from "@/components/AIAnalystView";

type TabKey =
  | "DASHBOARD"
  | "TOPOLOGY"
  | "ASSETS_PORTS"
  | "CHANGES_PREDICT"
  | "AI_ANALYST"
  | "TERMINAL"
  | "SCANS_CIDR"
  | "ALERTS_REPORTS";

const RBAC_ROLES = [
  { role: "SUPER_ADMIN", user: "sinan.mohammed", label: "Super Admin (Full Config)" },
  { role: "SECURITY_ADMIN", user: "secadmin.ops", label: "Security Admin (Scans & Analysis)" },
  { role: "SOC_ANALYST", user: "soc.analyst", label: "SOC Analyst (Monitor & Investigate)" },
  { role: "NETWORK_ADMIN", user: "net.admin", label: "Network Admin (Assets & Topology)" },
  { role: "AUDITOR", user: "compliance.auditor", label: "Auditor (Read-Only Reports)" },
];

export default function NetSentinelCommandCenter() {
  const [activeTab, setActiveTab] = useState<TabKey>("DASHBOARD");
  const [selectedRoleIdx, setSelectedRoleIdx] = useState<number>(0);
  const currentActor = RBAC_ROLES[selectedRoleIdx];

  const [autoRefresh, setAutoRefresh] = useState<boolean>(true);
  const [lastUpdated, setLastUpdated] = useState<string>("");
  const [wsConnected, setWsConnected] = useState<boolean>(false);

  // Operational Telemetry State
  const [dashboard, setDashboard] = useState<any | null>(null);
  const [assets, setAssets] = useState<AssetRecord[]>([]);
  const [ports, setPorts] = useState<PortRecord[]>([]);
  const [findings, setFindings] = useState<FindingRecord[]>([]);
  const [changes, setChanges] = useState<NetworkChangeRecord[]>([]);
  const [predictions, setPredictions] = useState<any[]>([]);
  const [scans, setScans] = useState<ScanJobRecord[]>([]);
  const [cidrs, setCidrs] = useState<any[]>([]);
  const [schedules, setSchedules] = useState<any[]>([]);
  const [topology, setTopology] = useState<any>({ nodes: [], edges: [], stats: {} });
  const [snapshots, setSnapshots] = useState<any[]>([]);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [audits, setAudits] = useState<any[]>([]);

  // Filters & Form States
  const [dashSubnet, setDashSubnet] = useState<string>("");
  const [dashProtocol, setDashProtocol] = useState<string>("");
  const [mismatchOnly, setMismatchOnly] = useState<boolean>(false);
  const [scanTarget, setScanTarget] = useState<string>("192.168.56.0/24");
  const [scanProfile, setScanProfile] = useState<string>("STANDARD_TCP_INTEL");
  const [scanScenario, setScanScenario] = useState<string>("ENTERPRISE_DRIFT");
  const [scanBannerMsg, setScanBannerMsg] = useState<{ type: "ok" | "err"; text: string } | null>(
    null
  );
  const [newCidr, setNewCidr] = useState<string>("");
  const [newCidrDesc, setNewCidrDesc] = useState<string>("");
  const [selectedXmlScan, setSelectedXmlScan] = useState<any | null>(null);

  // Asset Business Context Modal
  const [editingAsset, setEditingAsset] = useState<AssetRecord | null>(null);
  const [editService, setEditService] = useState<string>("");
  const [editOwner, setEditOwner] = useState<string>("");
  const [editCrit, setEditCrit] = useState<string>("HIGH");
  const [editGateway, setEditGateway] = useState<boolean>(false);
  const [editGatewayEv, setEditGatewayEv] = useState<string>("");

  const fetchAllTelemetry = useCallback(async () => {
    try {
      const dashParams = new URLSearchParams();
      if (dashSubnet) dashParams.set("subnet", dashSubnet);
      if (dashProtocol) dashParams.set("protocol", dashProtocol);

      const [
        dashData,
        assetsData,
        portsData,
        findingsData,
        changesData,
        predData,
        scansData,
        cidrData,
        schedData,
        topoData,
        snapData,
        alertData,
        auditData,
      ] = await Promise.all([
        apiFetch<any>(`/dashboard?${dashParams.toString()}`, {}, currentActor.role, currentActor.user),
        apiFetch<AssetRecord[]>("/assets", {}, currentActor.role, currentActor.user),
        apiFetch<PortRecord[]>(
          `/ports${mismatchOnly ? "?mismatch_only=true" : ""}`,
          {},
          currentActor.role,
          currentActor.user
        ),
        apiFetch<FindingRecord[]>("/findings", {}, currentActor.role, currentActor.user),
        apiFetch<NetworkChangeRecord[]>("/changes", {}, currentActor.role, currentActor.user),
        apiFetch<any[]>("/changes/predictions", {}, currentActor.role, currentActor.user),
        apiFetch<ScanJobRecord[]>("/scans", {}, currentActor.role, currentActor.user),
        apiFetch<any[]>("/cidrs", {}, currentActor.role, currentActor.user),
        apiFetch<any[]>("/schedules", {}, currentActor.role, currentActor.user),
        apiFetch<any>("/topology", {}, currentActor.role, currentActor.user),
        apiFetch<any[]>("/topology/snapshots", {}, currentActor.role, currentActor.user),
        apiFetch<any[]>("/alerts", {}, currentActor.role, currentActor.user),
        apiFetch<any[]>("/audit", {}, currentActor.role, currentActor.user),
      ]);

      setDashboard(dashData);
      setAssets(assetsData);
      setPorts(portsData);
      setFindings(findingsData);
      setChanges(changesData);
      setPredictions(predData);
      setScans(scansData);
      setCidrs(cidrData);
      setSchedules(schedData);
      setTopology(topoData);
      setSnapshots(snapData);
      setAlerts(alertData);
      setAudits(auditData);
      setLastUpdated(new Date().toLocaleTimeString());
    } catch (err) {
      console.error("Telemetry refresh error:", err);
    }
  }, [currentActor.role, currentActor.user, dashSubnet, dashProtocol, mismatchOnly]);

  useEffect(() => {
    fetchAllTelemetry();
  }, [fetchAllTelemetry]);

  // Configurable 8-second auto-refresh (PRD Section 12)
  useEffect(() => {
    if (!autoRefresh) return;
    const timer = setInterval(() => {
      fetchAllTelemetry();
    }, 8000);
    return () => clearInterval(timer);
  }, [autoRefresh, fetchAllTelemetry]);

  // Real-time WebSocket event stream connection
  useEffect(() => {
    let ws: WebSocket | null = null;
    try {
      ws = new WebSocket(`${WS_BASE}/ws/events`);
      ws.onopen = () => setWsConnected(true);
      ws.onclose = () => setWsConnected(false);
      ws.onmessage = () => {
        fetchAllTelemetry();
      };
    } catch {
      setWsConnected(false);
    }
    return () => {
      ws?.close();
    };
  }, [fetchAllTelemetry]);

  const handleLaunchScan = async (targetOverride?: string) => {
    setScanBannerMsg(null);
    const t = targetOverride || scanTarget;
    try {
      const res = await apiFetch<ScanJobRecord>(
        "/scans",
        {
          method: "POST",
          body: JSON.stringify({
            target: t,
            scan_profile: scanProfile,
            simulation_scenario: scanScenario,
          }),
        },
        currentActor.role,
        currentActor.user
      );
      setScanBannerMsg({
        type: "ok",
        text: `Scan ${res.scan_id.slice(0, 8)} completed on ${res.target} (${res.execution_mode}). Discovered ${
          res.summary_json?.hosts_discovered || 0
        } hosts & ${res.summary_json?.open_ports_observed || 0} open ports.`,
      });
      fetchAllTelemetry();
    } catch (err: any) {
      setScanBannerMsg({
        type: "err",
        text: `Scan Error: ${err.message}`,
      });
      fetchAllTelemetry();
    }
  };

  const handleAddCidr = async () => {
    if (!newCidr.trim() || !newCidrDesc.trim()) return;
    try {
      await apiFetch(
        "/cidrs",
        {
          method: "POST",
          body: JSON.stringify({
            cidr_block: newCidr.trim(),
            description: newCidrDesc.trim(),
          }),
        },
        currentActor.role,
        currentActor.user
      );
      setNewCidr("");
      setNewCidrDesc("");
      fetchAllTelemetry();
    } catch (err: any) {
      alert(`CIDR Update Failed: ${err.message}`);
    }
  };

  const handleOptimizeSchedules = async () => {
    try {
      await apiFetch(
        "/schedules/optimize",
        { method: "POST" },
        currentActor.role,
        currentActor.user
      );
      fetchAllTelemetry();
    } catch (err: any) {
      alert(`Optimization Error: ${err.message}`);
    }
  };

  const handleViewRawXml = async (scanId: string) => {
    try {
      const detail = await apiFetch<any>(
        `/scans/${scanId}`,
        {},
        currentActor.role,
        currentActor.user
      );
      setSelectedXmlScan(detail);
    } catch (err) {
      console.error(err);
    }
  };

  const handleSaveBusinessContext = async () => {
    if (!editingAsset) return;
    try {
      await apiFetch(
        `/assets/${editingAsset.asset_id}/business-context`,
        {
          method: "PATCH",
          body: JSON.stringify({
            business_service: editService,
            owner_team: editOwner,
            criticality: editCrit,
            is_gateway_verified: editGateway,
            gateway_evidence: editGatewayEv || undefined,
          }),
        },
        currentActor.role,
        currentActor.user
      );
      setEditingAsset(null);
      fetchAllTelemetry();
    } catch (err: any) {
      alert(`Failed to update asset context: ${err.message}`);
    }
  };

  const handleAcknowledgeAlert = async (alertId: string) => {
    try {
      await apiFetch(
        `/alerts/${alertId}/acknowledge`,
        { method: "POST" },
        currentActor.role,
        currentActor.user
      );
      fetchAllTelemetry();
    } catch (err: any) {
      alert(`Alert Acknowledge Error: ${err.message}`);
    }
  };

  const kpis = dashboard?.kpis || {};

  return (
    <div className="min-h-screen flex flex-col bg-[#050811] text-slate-100">
      {/* Top Enterprise Command Bar */}
      <header className="sticky top-0 z-30 border-b border-slate-800/90 bg-[#070c18]/95 backdrop-blur px-6 py-3">
        <div className="mx-auto flex max-w-[1600px] flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 shadow-lg shadow-cyan-500/20">
              <Shield className="h-6 w-6 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-lg font-extrabold tracking-tight text-white">
                  NETSENTINEL <span className="text-cyan-400">AI</span>
                </h1>
                <span className="rounded-md bg-cyan-500/15 border border-cyan-500/30 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-cyan-300">
                  Autonomous Exposure Intelligence v1.0
                </span>
              </div>
              <p className="text-[11px] text-slate-400">
                Discover → Identify → Understand → Analyze → Prioritize → Monitor → Report • Creator: Sinan Mohammed
              </p>
            </div>
          </div>

          {/* Right Live Telemetry & RBAC Role Switcher */}
          <div className="flex flex-wrap items-center gap-3 text-xs">
            <div className="flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900/90 px-2.5 py-1.5">
              <span
                className={`h-2 w-2 rounded-full ${
                  wsConnected ? "bg-emerald-400 animate-ping" : "bg-cyan-400"
                }`}
              />
              <span className="text-slate-300">
                Statistical Engine: <strong className="text-emerald-400">INDEPENDENT</strong>
              </span>
            </div>

            <div className="flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900/90 px-2.5 py-1">
              <Lock className="h-3.5 w-3.5 text-amber-400" />
              <span className="text-slate-400">RBAC Role:</span>
              <select
                value={selectedRoleIdx}
                onChange={(e) => setSelectedRoleIdx(Number(e.target.value))}
                className="bg-transparent font-semibold text-amber-300 focus:outline-none"
              >
                {RBAC_ROLES.map((r, i) => (
                  <option key={r.role} value={i} className="bg-slate-900 text-slate-100">
                    {r.label}
                  </option>
                ))}
              </select>
            </div>

            <button
              onClick={() => setAutoRefresh(!autoRefresh)}
              className={`flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 transition ${
                autoRefresh
                  ? "border-emerald-500/40 bg-emerald-950/30 text-emerald-300"
                  : "border-slate-700 bg-slate-900 text-slate-400"
              }`}
            >
              <RefreshCw className={`h-3.5 w-3.5 ${autoRefresh ? "animate-spin" : ""}`} />
              <span>Auto-Refresh (8s): {autoRefresh ? "ON" : "OFF"}</span>
            </button>

            <button
              onClick={fetchAllTelemetry}
              className="rounded-lg bg-cyan-600 px-3 py-1.5 font-semibold text-white hover:bg-cyan-500 transition"
            >
              Sync Now
            </button>
          </div>
        </div>

        {/* Navigation Bar across all 9 Modules */}
        <div className="mx-auto mt-3 flex max-w-[1600px] items-center gap-1.5 overflow-x-auto pb-1">
          {[
            { id: "DASHBOARD", label: "Live SOC Dashboard", icon: Activity },
            { id: "TOPOLOGY", label: "Live Topology & Digital Twin", icon: Network },
            { id: "ASSETS_PORTS", label: "Asset & Port Intelligence", icon: Server },
            { id: "CHANGES_PREDICT", label: "Change Detection & Drift Forecast", icon: GitPullRequestDraft },
            { id: "AI_ANALYST", label: "Hybrid AI & Exposure Investigator", icon: BrainCircuit },
            { id: "TERMINAL", label: "Hybrid Command Terminal", icon: TerminalIcon },
            { id: "SCANS_CIDR", label: "Scanner, CIDR Scope & Optimizer", icon: Radar },
            {
              id: "ALERTS_REPORTS",
              label: `Alerts (${kpis.unacknowledged_alerts || 0}) & Audit Reports`,
              icon: Bell,
            },
          ].map((tab) => {
            const Icon = tab.icon;
            const active = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as TabKey)}
                className={`flex items-center gap-2 whitespace-nowrap rounded-lg px-3.5 py-2 text-xs font-semibold transition ${
                  active
                    ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm"
                    : "text-slate-400 hover:bg-slate-900 hover:text-slate-200 border border-transparent"
                }`}
              >
                <Icon className="h-4 w-4" />
                {tab.label}
              </button>
            );
          })}
        </div>
      </header>

      {/* Main Content Workspace */}
      <main className="mx-auto w-full max-w-[1600px] flex-1 p-6">
        {/* TAB 1: LIVE SOC DASHBOARD (Module 7) */}
        {activeTab === "DASHBOARD" && (
          <div className="space-y-6">
            {/* Filter & Quick Scan Bar */}
            <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-800 bg-[#0b1120] p-4">
              <div className="flex flex-wrap items-center gap-3">
                <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                  <Sliders className="h-3.5 w-3.5 text-cyan-400" />
                  SOC Telemetry Filters:
                </span>
                <select
                  value={dashSubnet}
                  onChange={(e) => setDashSubnet(e.target.value)}
                  className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-200"
                >
                  <option value="">All Authorized Subnets</option>
                  {(dashboard?.available_subnets || []).map((s: string) => (
                    <option key={s} value={s}>
                      Subnet {s}
                    </option>
                  ))}
                </select>
                <select
                  value={dashProtocol}
                  onChange={(e) => setDashProtocol(e.target.value)}
                  className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-200"
                >
                  <option value="">All Protocols (TCP + UDP)</option>
                  <option value="TCP">TCP Only</option>
                  <option value="UDP">UDP Only</option>
                </select>
              </div>
              <div className="flex items-center gap-3 text-xs text-slate-400">
                <span>Last Telemetry Sync: {lastUpdated || "Just now"}</span>
                <button
                  onClick={() => handleLaunchScan("192.168.56.0/24")}
                  className="flex items-center gap-1.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 px-3.5 py-1.5 font-semibold text-white hover:from-cyan-500 hover:to-blue-500 shadow"
                >
                  <Play className="h-3.5 w-3.5" />
                  Run Autonomous Sweep (192.168.56.0/24)
                </button>
              </div>
            </div>

            {scanBannerMsg && (
              <div
                className={`rounded-xl border p-3.5 text-xs flex items-center justify-between ${
                  scanBannerMsg.type === "ok"
                    ? "border-emerald-500/40 bg-emerald-950/30 text-emerald-200"
                    : "border-red-500/40 bg-red-950/30 text-red-200"
                }`}
              >
                <span>{scanBannerMsg.text}</span>
                <button
                  onClick={() => setScanBannerMsg(null)}
                  className="text-slate-400 hover:text-white"
                >
                  Dismiss
                </button>
              </div>
            )}

            {/* KPI Cards Grid */}
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
              {[
                {
                  title: "Discovered Assets",
                  value: kpis.total_discovered_assets ?? 0,
                  sub: `${kpis.active_hosts ?? 0} Active • ${kpis.missing_or_unreachable_hosts ?? 0} Missing`,
                  color: "text-cyan-400",
                },
                {
                  title: "Open TCP Ports",
                  value: kpis.open_tcp_ports ?? 0,
                  sub: "Verified SYN/Connect Probes",
                  color: "text-emerald-400",
                },
                {
                  title: "Open UDP Ports",
                  value: kpis.open_udp_ports ?? 0,
                  sub: "DNS / SNMP / Core UDP",
                  color: "text-blue-400",
                },
                {
                  title: "Port-Service Mismatches",
                  value: kpis.service_mismatches ?? 0,
                  sub: "Detected != Conventional Port",
                  color: "text-amber-400",
                },
                {
                  title: "High/Critical Findings",
                  value: kpis.high_priority_findings ?? 0,
                  sub: `${kpis.total_open_findings ?? 0} Total Active Findings`,
                  color: "text-red-400",
                },
                {
                  title: "Detected Network Drift",
                  value: kpis.recent_changes_count ?? 0,
                  sub: `Latest Scan: ${kpis.latest_scan_status || "COMPLETED"}`,
                  color: "text-purple-400",
                },
              ].map((card) => (
                <div
                  key={card.title}
                  className="rounded-xl border border-slate-800 bg-[#0b1120] p-4 shadow-sm"
                >
                  <div className="text-[11px] font-medium uppercase tracking-wider text-slate-400">
                    {card.title}
                  </div>
                  <div className={`mt-2 text-2xl font-extrabold ${card.color}`}>
                    {card.value}
                  </div>
                  <div className="mt-1 text-[11px] text-slate-400">{card.sub}</div>
                </div>
              ))}
            </div>

            {/* Middle Analytics Row: Risk Distribution + Top Exposed Services */}
            <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
              <div className="lg:col-span-7 rounded-xl border border-slate-800 bg-[#0b1120] p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-semibold text-white">
                      Statistical Risk Prioritization Distribution (0–100 Bands)
                    </h3>
                    <p className="text-xs text-slate-400">
                      Internal multi-factor prioritization bands (Independent of Cloud AI)
                    </p>
                  </div>
                  <span className="text-xs font-mono text-cyan-400">PRD Section 8</span>
                </div>

                <div className="space-y-3">
                  {(dashboard?.risk_distribution || []).map((band: any) => {
                    const colorMap: Record<string, string> = {
                      Critical: "bg-red-500",
                      High: "bg-orange-500",
                      Medium: "bg-amber-500",
                      Low: "bg-cyan-500",
                      Informational: "bg-emerald-500",
                    };
                    const totalF = Math.max(1, findings.length);
                    const pct = Math.min(100, Math.round((band.findings / totalF) * 100));
                    return (
                      <div key={band.band} className="space-y-1">
                        <div className="flex items-center justify-between text-xs">
                          <span className="font-semibold text-slate-200">{band.band}</span>
                          <span className="text-slate-400">
                            {band.assets} Assets •{" "}
                            <strong className="text-white">{band.findings} Findings</strong>
                          </span>
                        </div>
                        <div className="h-2.5 w-full rounded-full bg-slate-900 overflow-hidden">
                          <div
                            className={`h-full rounded-full ${colorMap[band.band] || "bg-cyan-500"}`}
                            style={{ width: `${Math.max(pct, band.findings > 0 ? 10 : 2)}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              <div className="lg:col-span-5 rounded-xl border border-slate-800 bg-[#0b1120] p-5 space-y-4">
                <div>
                  <h3 className="text-sm font-semibold text-white">
                    Top Exposed Application Services
                  </h3>
                  <p className="text-xs text-slate-400">
                    Grouped by actual Nmap service probe identification (-sV)
                  </p>
                </div>

                <div className="space-y-2.5">
                  {(dashboard?.top_exposed_services || []).map((svc: any) => (
                    <div
                      key={svc.service}
                      className="flex items-center justify-between rounded-lg border border-slate-800/80 bg-slate-900/70 px-3.5 py-2 text-xs"
                    >
                      <span className="font-mono font-semibold uppercase text-cyan-300">
                        {svc.service}
                      </span>
                      <span className="rounded bg-cyan-500/15 px-2.5 py-0.5 font-mono font-bold text-cyan-200">
                        {svc.count} Open Endpoints
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Bottom Row: High-Priority Findings & Recent Network Drift */}
            <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
              <div className="lg:col-span-7 rounded-xl border border-slate-800 bg-[#0b1120] p-5 space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-white">
                    Which Findings Should the Security Team Investigate First?
                  </h3>
                  <button
                    onClick={() => setActiveTab("AI_ANALYST")}
                    className="text-xs font-semibold text-cyan-400 hover:underline"
                  >
                    Open AI Analyst & Investigator →
                  </button>
                </div>

                <div className="space-y-2.5">
                  {(dashboard?.high_priority_findings || []).map((f: any) => (
                    <div
                      key={f.finding_id}
                      onClick={() => setActiveTab("AI_ANALYST")}
                      className="cursor-pointer rounded-lg border border-slate-800 bg-slate-900/80 p-3 hover:border-cyan-500/50 transition"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-xs font-bold text-white">{f.title}</span>
                        <span
                          className={`rounded px-2 py-0.5 text-[11px] font-bold ${
                            f.severity === "Critical"
                              ? "bg-red-500/20 text-red-300 border border-red-500/40"
                              : "bg-orange-500/20 text-orange-300 border border-orange-500/40"
                          }`}
                        >
                          {f.severity} ({f.risk_score}/100)
                        </span>
                      </div>
                      <p className="mt-1 text-xs text-slate-400">{f.recommendation}</p>
                    </div>
                  ))}
                </div>
              </div>

              <div className="lg:col-span-5 rounded-xl border border-slate-800 bg-[#0b1120] p-5 space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-white">
                    What Changed Since the Previous Scan?
                  </h3>
                  <button
                    onClick={() => setActiveTab("CHANGES_PREDICT")}
                    className="text-xs font-semibold text-cyan-400 hover:underline"
                  >
                    Full Change Timeline →
                  </button>
                </div>

                <div className="space-y-2.5">
                  {(dashboard?.recent_changes || []).slice(0, 6).map((c: any) => (
                    <div
                      key={c.change_id}
                      className="rounded-lg border border-slate-800 bg-slate-900/80 p-3 text-xs space-y-1"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono font-bold text-amber-300">
                          {c.change_type}
                        </span>
                        <span className="text-[11px] text-slate-400">
                          Significance: {c.significance_score}
                        </span>
                      </div>
                      <p className="text-slate-200">{c.summary}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: LIVE TOPOLOGY & DIGITAL TWIN (Module 3 + Innovation 1) */}
        {activeTab === "TOPOLOGY" && (
          <TopologyCanvas
            nodes={topology.nodes || []}
            edges={topology.edges || []}
            stats={topology.stats || {}}
            snapshots={snapshots}
            role={currentActor.role}
            onRefresh={fetchAllTelemetry}
          />
        )}

        {/* TAB 3: ASSET & PORT INTELLIGENCE + BUSINESS MAPPING (Modules 1, 2 + Innovation 3) */}
        {activeTab === "ASSETS_PORTS" && (
          <div className="space-y-6">
            {/* Asset Inventory & Business Service Mapping */}
            <div className="rounded-xl border border-slate-800 bg-[#0b1120] p-5 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <h2 className="text-base font-semibold text-white">
                    Module 1 & Innovation 3 — Enterprise Asset Inventory & Port-to-Business-Service Mapping
                  </h2>
                  <p className="text-xs text-slate-400">
                    Associate technical assets with business services, owner teams, criticality, and verified gateway route evidence.
                  </p>
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400">
                      <th className="py-2.5 px-3">IP Address</th>
                      <th className="py-2.5 px-3">Hostname & OS</th>
                      <th className="py-2.5 px-3">Subnet</th>
                      <th className="py-2.5 px-3">Business Service & Owner</th>
                      <th className="py-2.5 px-3">Criticality</th>
                      <th className="py-2.5 px-3">Gateway Status</th>
                      <th className="py-2.5 px-3">Risk Score</th>
                      <th className="py-2.5 px-3">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/70">
                    {assets.map((a) => (
                      <tr key={a.asset_id} className="hover:bg-slate-900/60">
                        <td className="py-3 px-3 font-mono font-bold text-cyan-300">
                          {a.ip_address}
                        </td>
                        <td className="py-3 px-3">
                          <div className="font-medium text-white">
                            {a.hostname || "unlabeled"}
                          </div>
                          <div className="text-[11px] text-slate-400">
                            {a.operating_system}
                          </div>
                        </td>
                        <td className="py-3 px-3 font-mono text-slate-300">{a.subnet}</td>
                        <td className="py-3 px-3">
                          <div className="font-semibold text-slate-100">
                            {a.business_service}
                          </div>
                          <div className="text-[11px] text-slate-400">{a.owner_team}</div>
                        </td>
                        <td className="py-3 px-3">
                          <span className="rounded bg-slate-800 px-2 py-0.5 font-semibold text-amber-300">
                            {a.criticality}
                          </span>
                        </td>
                        <td className="py-3 px-3">
                          {a.is_gateway_verified ? (
                            <span
                              title={a.gateway_evidence || ""}
                              className="rounded bg-emerald-500/20 border border-emerald-500/40 px-2 py-0.5 text-[11px] text-emerald-300"
                            >
                              Verified Gateway
                            </span>
                          ) : (
                            <span className="text-slate-500">Standard Host</span>
                          )}
                        </td>
                        <td className="py-3 px-3 font-mono font-bold text-white">
                          {a.risk_score}/100 ({a.risk_classification})
                        </td>
                        <td className="py-3 px-3">
                          <button
                            onClick={() => {
                              setEditingAsset(a);
                              setEditService(a.business_service || "");
                              setEditOwner(a.owner_team || "");
                              setEditCrit(a.criticality || "MEDIUM");
                              setEditGateway(a.is_gateway_verified);
                              setEditGatewayEv(a.gateway_evidence || "");
                            }}
                            className="rounded border border-cyan-500/40 bg-cyan-950/40 px-2.5 py-1 text-xs text-cyan-300 hover:bg-cyan-500/20"
                          >
                            Map Context
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Edit Business Context Modal */}
            {editingAsset && (
              <div className="rounded-xl border border-cyan-500/50 bg-[#0f172a] p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-bold text-white">
                    Update Business Context & Gateway Evidence for {editingAsset.ip_address}
                  </h3>
                  <button
                    onClick={() => setEditingAsset(null)}
                    className="text-xs text-slate-400 hover:text-white"
                  >
                    Cancel
                  </button>
                </div>
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-3 text-xs">
                  <div>
                    <label className="block text-slate-400 mb-1">Business Service</label>
                    <input
                      type="text"
                      value={editService}
                      onChange={(e) => setEditService(e.target.value)}
                      className="w-full rounded border border-slate-700 bg-slate-900 px-3 py-1.5 text-white"
                    />
                  </div>
                  <div>
                    <label className="block text-slate-400 mb-1">Owner Team</label>
                    <input
                      type="text"
                      value={editOwner}
                      onChange={(e) => setEditOwner(e.target.value)}
                      className="w-full rounded border border-slate-700 bg-slate-900 px-3 py-1.5 text-white"
                    />
                  </div>
                  <div>
                    <label className="block text-slate-400 mb-1">Asset Criticality</label>
                    <select
                      value={editCrit}
                      onChange={(e) => setEditCrit(e.target.value)}
                      className="w-full rounded border border-slate-700 bg-slate-900 px-3 py-1.5 text-white"
                    >
                      <option value="LOW">LOW</option>
                      <option value="MEDIUM">MEDIUM</option>
                      <option value="HIGH">HIGH</option>
                      <option value="CRITICAL">CRITICAL</option>
                    </select>
                  </div>
                </div>
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-3 text-xs items-center">
                  <label className="flex items-center gap-2 text-slate-200">
                    <input
                      type="checkbox"
                      checked={editGateway}
                      onChange={(e) => setEditGateway(e.target.checked)}
                    />
                    Mark as Verified Subnet Gateway (Requires route evidence)
                  </label>
                  <div className="sm:col-span-2">
                    <input
                      type="text"
                      value={editGatewayEv}
                      onChange={(e) => setEditGatewayEv(e.target.value)}
                      placeholder="Route or LLDP/OSPF infrastructure verification evidence..."
                      className="w-full rounded border border-slate-700 bg-slate-900 px-3 py-1.5 text-white"
                    />
                  </div>
                </div>
                <button
                  onClick={handleSaveBusinessContext}
                  className="rounded-lg bg-cyan-600 px-4 py-1.5 text-xs font-semibold text-white hover:bg-cyan-500"
                >
                  Save & Recompute Statistical Risk Scores
                </button>
              </div>
            )}

            {/* Module 2: Port-to-Application Intelligence Table */}
            <div className="rounded-xl border border-slate-800 bg-[#0b1120] p-5 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <h2 className="text-base font-semibold text-white">
                    Module 2 — Port-to-Application Intelligence Engine ({ports.length} Observations)
                  </h2>
                  <p className="text-xs text-slate-400">
                    Distinguishes conventional IANA port expectations from actual Nmap service probe detections (-sV)
                  </p>
                </div>
                <label className="flex items-center gap-2 text-xs text-amber-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={mismatchOnly}
                    onChange={(e) => setMismatchOnly(e.target.checked)}
                  />
                  Show Only Port-to-Service Mismatches
                </label>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400">
                      <th className="py-2.5 px-3">Port / Proto</th>
                      <th className="py-2.5 px-3">State</th>
                      <th className="py-2.5 px-3">Detected Service</th>
                      <th className="py-2.5 px-3">Conventional Service</th>
                      <th className="py-2.5 px-3">Product & Version</th>
                      <th className="py-2.5 px-3">Typical Application Purpose</th>
                      <th className="py-2.5 px-3">Risk Score</th>
                      <th className="py-2.5 px-3">Recommended Defensive Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/70">
                    {ports.map((p) => (
                      <tr key={p.port_id} className="hover:bg-slate-900/60">
                        <td className="py-3 px-3 font-mono font-bold text-white">
                          {p.port_number}/{p.protocol}
                        </td>
                        <td className="py-3 px-3">
                          <span className="rounded bg-emerald-500/15 px-2 py-0.5 font-mono text-emerald-300">
                            {p.state}
                          </span>
                        </td>
                        <td className="py-3 px-3 font-mono font-bold text-cyan-300">
                          {p.detected_service}
                          {p.service_mismatch && (
                            <span className="ml-1.5 rounded bg-red-500/20 border border-red-500/40 px-1.5 py-0.5 text-[10px] text-red-300">
                              MISMATCH
                            </span>
                          )}
                        </td>
                        <td className="py-3 px-3 font-mono text-slate-400">
                          {p.conventional_service}
                        </td>
                        <td className="py-3 px-3 text-slate-200">
                          {p.product || "-"} {p.version || ""}
                        </td>
                        <td className="py-3 px-3 max-w-xs text-slate-300">
                          {p.typical_purpose}
                        </td>
                        <td className="py-3 px-3 font-mono font-bold text-amber-300">
                          {p.risk_score} ({p.risk_classification})
                        </td>
                        <td className="py-3 px-3 max-w-xs text-slate-300">
                          {p.recommended_action}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* TAB 4: AUTONOMOUS CHANGE DETECTION & VOLATILITY FORECAST (Module 4 + Innovation 5) */}
        {activeTab === "CHANGES_PREDICT" && (
          <div className="space-y-6">
            {/* Innovation 5: Statistical Change Risk Prediction */}
            <div className="rounded-xl border border-slate-800 bg-[#0b1120] p-5 space-y-4">
              <div>
                <h2 className="text-base font-semibold text-white">
                  Innovation 5 — Statistical Network Change Risk & Volatility Prediction
                </h2>
                <p className="text-xs text-slate-400">
                  Identifies assets with recurring administrative or database port churn and recommends adaptive polling cadences.
                </p>
              </div>

              <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
                {predictions.map((pred) => (
                  <div
                    key={pred.asset_id}
                    className="rounded-xl border border-slate-800 bg-slate-900/80 p-4 space-y-2 text-xs"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-sm font-bold text-cyan-300">
                        {pred.ip_address}
                      </span>
                      <span className="rounded bg-purple-500/20 border border-purple-500/40 px-2 py-0.5 font-semibold text-purple-300">
                        Volatility: {pred.volatility_score}/100
                      </span>
                    </div>
                    <div className="font-medium text-white">{pred.business_service}</div>
                    <p className="text-slate-400">{pred.statistical_rationale}</p>
                    <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-[11px]">
                      <span className="text-amber-300 font-semibold">{pred.trend_label}</span>
                      <span className="text-emerald-300">{pred.recommended_scan_cadence}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Module 4: State-Aware Change Detection Log */}
            <div className="rounded-xl border border-slate-800 bg-[#0b1120] p-5 space-y-4">
              <div>
                <h2 className="text-base font-semibold text-white">
                  Module 4 — State-Aware Autonomous Change Detection Log ({changes.length})
                </h2>
                <p className="text-xs text-slate-400">
                  Strictly distinguishes closed (RST), filtered, unreachable, and not_observed states between consecutive scans.
                </p>
              </div>

              <div className="space-y-2.5">
                {changes.map((c) => (
                  <div
                    key={c.change_id}
                    className="rounded-xl border border-slate-800 bg-slate-900/75 p-3.5 text-xs flex flex-wrap items-center justify-between gap-3"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="rounded bg-amber-500/20 border border-amber-500/40 px-2 py-0.5 font-mono font-bold text-amber-300">
                          {c.change_type}
                        </span>
                        <span className="font-semibold text-white">{c.summary}</span>
                      </div>
                      <div className="font-mono text-[11px] text-slate-400">
                        Previous: {JSON.stringify(c.previous_value)} → Current:{" "}
                        {JSON.stringify(c.current_value)}
                      </div>
                    </div>
                    <div className="text-right">
                      <div className="font-bold text-cyan-300">
                        Significance: {c.significance_score}
                      </div>
                      <div className="text-[11px] text-slate-500">
                        {new Date(c.observed_at).toLocaleString()}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* TAB 5: EXPLAINABLE AI ANALYST & EXPOSURE INVESTIGATOR (Module 5 + Innovations 2 & 4) */}
        {activeTab === "AI_ANALYST" && (
          <AIAnalystView
            findings={findings}
            role={currentActor.role}
            onRefresh={fetchAllTelemetry}
          />
        )}

        {/* TAB 6: HYBRID COMMAND TERMINAL (Module 6) */}
        {activeTab === "TERMINAL" && (
          <TerminalPanel
            role={currentActor.role}
            user={currentActor.user}
            onScanTriggered={fetchAllTelemetry}
          />
        )}

        {/* TAB 7: SCAN ORCHESTRATOR, CIDR ALLOWLIST & OPTIMIZER (Module 1 + Innovation 6) */}
        {activeTab === "SCANS_CIDR" && (
          <div className="space-y-6">
            {/* Scan Orchestration & Scope Guard Test */}
            <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
              <div className="lg:col-span-7 rounded-xl border border-slate-800 bg-[#0b1120] p-5 space-y-4">
                <h2 className="text-base font-semibold text-white">
                  Module 1 — Authorized Scan Orchestrator
                </h2>
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-3 text-xs">
                  <div>
                    <label className="block text-slate-400 mb-1">
                      Target IP or CIDR Scope
                    </label>
                    <input
                      type="text"
                      value={scanTarget}
                      onChange={(e) => setScanTarget(e.target.value)}
                      className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 font-mono text-white"
                    />
                  </div>
                  <div>
                    <label className="block text-slate-400 mb-1">Nmap Profile</label>
                    <select
                      value={scanProfile}
                      onChange={(e) => setScanProfile(e.target.value)}
                      className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-white"
                    >
                      <option value="STANDARD_TCP_INTEL">STANDARD_TCP_INTEL (-sT -sV -O)</option>
                      <option value="FULL_TCP">FULL_TCP (-sS -p 1-65535 -sV -O)</option>
                      <option value="FULL_UDP">FULL_UDP (-sU -p 1-65535 -sV)</option>
                      <option value="CONNECT_TCP">CONNECT_TCP (-sT -p 1-65535 -sV)</option>
                      <option value="DISCOVERY_ONLY">DISCOVERY_ONLY (-sn -PE)</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-slate-400 mb-1">Lab Drift Scenario</label>
                    <select
                      value={scanScenario}
                      onChange={(e) => setScanScenario(e.target.value)}
                      className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-white"
                    >
                      <option value="ENTERPRISE_DRIFT">ENTERPRISE_DRIFT (New DB + Mismatch)</option>
                      <option value="BASELINE">BASELINE (Clean Initial State)</option>
                    </select>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-2.5 pt-2">
                  <button
                    onClick={() => handleLaunchScan()}
                    className="flex items-center gap-1.5 rounded-lg bg-cyan-600 px-4 py-2 text-xs font-semibold text-white hover:bg-cyan-500"
                  >
                    <Play className="h-3.5 w-3.5" />
                    Execute Authorized Scan
                  </button>
                  <button
                    onClick={() => handleLaunchScan("10.20.30.0/24")}
                    className="rounded-lg border border-emerald-500/40 bg-emerald-950/30 px-3 py-2 text-xs text-emerald-300 hover:bg-emerald-900/40"
                  >
                    Quick Scan Data Tier (10.20.30.0/24)
                  </button>
                </div>

                {scanBannerMsg && (
                  <div
                    className={`rounded-lg border p-3 text-xs ${
                      scanBannerMsg.type === "ok"
                        ? "border-emerald-500/40 bg-emerald-950/30 text-emerald-200"
                        : "border-red-500/40 bg-red-950/30 text-red-200"
                    }`}
                  >
                    {scanBannerMsg.text}
                  </div>
                )}
              </div>

              {/* Authorized CIDR Allowlist Manager */}
              <div className="lg:col-span-5 rounded-xl border border-slate-800 bg-[#0b1120] p-5 space-y-4">
                <h2 className="text-base font-semibold text-white">
                  Authorized CIDR Scope Allowlist
                </h2>
                <div className="space-y-2 max-h-40 overflow-y-auto">
                  {cidrs.map((c) => (
                    <div
                      key={c.cidr_id}
                      className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-900/80 px-3 py-2 text-xs"
                    >
                      <div>
                        <span className="font-mono font-bold text-emerald-400">
                          {c.cidr_block}
                        </span>
                        <p className="text-[11px] text-slate-400">{c.description}</p>
                      </div>
                      <span className="rounded bg-emerald-500/15 px-2 py-0.5 text-[10px] text-emerald-300">
                        ACTIVE
                      </span>
                    </div>
                  ))}
                </div>

                <div className="flex gap-2 pt-2 border-t border-slate-800 text-xs">
                  <input
                    type="text"
                    value={newCidr}
                    onChange={(e) => setNewCidr(e.target.value)}
                    placeholder="e.g. 172.16.10.0/24"
                    className="w-36 rounded border border-slate-700 bg-slate-900 px-2.5 py-1.5 font-mono text-white"
                  />
                  <input
                    type="text"
                    value={newCidrDesc}
                    onChange={(e) => setNewCidrDesc(e.target.value)}
                    placeholder="Subnet description..."
                    className="flex-1 rounded border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-white"
                  />
                  <button
                    onClick={handleAddCidr}
                    className="rounded bg-slate-800 px-3 py-1.5 font-semibold text-cyan-300 hover:bg-slate-700"
                  >
                    Add Scope
                  </button>
                </div>
              </div>
            </div>

            {/* Innovation 6: Autonomous Scan Optimizer & Schedules */}
            <div className="rounded-xl border border-slate-800 bg-[#0b1120] p-5 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <h2 className="text-base font-semibold text-white">
                    Innovation 6 — Autonomous Scan Optimization & Adaptive Schedules
                  </h2>
                  <p className="text-xs text-slate-400">
                    Automatically prioritizes high-volatility assets and spaces out expensive full-UDP scans.
                  </p>
                </div>
                <button
                  onClick={handleOptimizeSchedules}
                  className="flex items-center gap-1.5 rounded-lg bg-purple-600 px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-purple-500"
                >
                  <Sparkles className="h-3.5 w-3.5" />
                  Run Autonomous Schedule Optimizer
                </button>
              </div>

              <div className="grid grid-cols-1 gap-3 md:grid-cols-3 text-xs">
                {schedules.map((s) => (
                  <div
                    key={s.schedule_id}
                    className="rounded-lg border border-slate-800 bg-slate-900/80 p-3.5 space-y-1.5"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-white">{s.name}</span>
                      <span className="rounded bg-cyan-500/15 px-2 py-0.5 font-mono text-[10px] text-cyan-300">
                        Every {s.interval_minutes}m
                      </span>
                    </div>
                    <div className="font-mono text-slate-300">
                      Target: {s.target} ({s.scan_profile})
                    </div>
                    <div className="text-[11px] text-amber-300">Tier: {s.priority_tier}</div>
                    <p className="text-[11px] text-slate-400">{s.optimization_reason}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Scan History & Raw XML Viewer */}
            <div className="rounded-xl border border-slate-800 bg-[#0b1120] p-5 space-y-4">
              <h2 className="text-base font-semibold text-white">
                Completed & Historical Scan Jobs ({scans.length})
              </h2>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400">
                      <th className="py-2 px-3">Scan ID</th>
                      <th className="py-2 px-3">Target</th>
                      <th className="py-2 px-3">Profile / Mode</th>
                      <th className="py-2 px-3">Nmap Command</th>
                      <th className="py-2 px-3">Summary</th>
                      <th className="py-2 px-3">Raw XML</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/70">
                    {scans.map((s) => (
                      <tr key={s.scan_id}>
                        <td className="py-2.5 px-3 font-mono text-cyan-300">
                          {s.scan_id.slice(0, 8)}
                        </td>
                        <td className="py-2.5 px-3 font-mono font-bold text-white">
                          {s.target}
                        </td>
                        <td className="py-2.5 px-3">
                          {s.scan_profile} ({s.execution_mode})
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[11px] text-slate-400">
                          {s.nmap_command}
                        </td>
                        <td className="py-2.5 px-3 text-slate-300">
                          {s.summary_json?.hosts_discovered ?? 0} hosts •{" "}
                          {s.summary_json?.open_ports_observed ?? 0} ports •{" "}
                          {s.summary_json?.changes_detected ?? 0} changes
                        </td>
                        <td className="py-2.5 px-3">
                          <button
                            onClick={() => handleViewRawXml(s.scan_id)}
                            className="flex items-center gap-1 rounded border border-slate-700 bg-slate-800 px-2 py-1 text-[11px] text-cyan-300 hover:bg-slate-700"
                          >
                            <Eye className="h-3 w-3" />
                            Inspect XML
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {selectedXmlScan && (
                <div className="rounded-xl border border-slate-700 bg-slate-950 p-4 space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono font-bold text-cyan-300">
                      Raw Nmap XML Output — Scan {selectedXmlScan.scan_id}
                    </span>
                    <button
                      onClick={() => setSelectedXmlScan(null)}
                      className="text-slate-400 hover:text-white"
                    >
                      Close XML Viewer
                    </button>
                  </div>
                  <pre className="max-h-72 overflow-y-auto font-mono text-[11px] text-emerald-300">
                    {selectedXmlScan.raw_xml}
                  </pre>
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 8: DEDUPLICATED ALERTS, AUDIT LOGS & EXPORT REPORTS (Modules 8 & 9) */}
        {activeTab === "ALERTS_REPORTS" && (
          <div className="space-y-6">
            {/* Module 9: Exportable Executive & Technical Reports */}
            <div className="rounded-xl border border-slate-800 bg-[#0b1120] p-5 flex flex-wrap items-center justify-between gap-4">
              <div>
                <h2 className="text-base font-semibold text-white">
                  Module 9 — Security Reporting, Compliance Exports & Audit Evidence
                </h2>
                <p className="text-xs text-slate-400">
                  Includes scan time, authorized CIDR scope, configuration, analytical limitations, executive summary, and technical evidence.
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-2.5 text-xs">
                <a
                  href={getReportUrl("html")}
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center gap-1.5 rounded-lg bg-cyan-600 px-3.5 py-2 font-semibold text-white hover:bg-cyan-500"
                >
                  <FileText className="h-4 w-4" />
                  Open Printable PDF / HTML Security Report
                </a>
                <a
                  href={getReportUrl("csv")}
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3.5 py-2 font-semibold text-slate-200 hover:bg-slate-700"
                >
                  <FileSpreadsheet className="h-4 w-4 text-emerald-400" />
                  Download CSV Asset Export
                </a>
                <a
                  href={getReportUrl("json")}
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3.5 py-2 font-semibold text-slate-200 hover:bg-slate-700"
                >
                  <FileCode2 className="h-4 w-4 text-amber-400" />
                  Export JSON Audit Bundle
                </a>
              </div>
            </div>

            {/* Module 8: Deduplicated Alerts */}
            <div className="rounded-xl border border-slate-800 bg-[#0b1120] p-5 space-y-4">
              <h2 className="text-base font-semibold text-white">
                Module 8 — Deduplicated SOC Alerts ({alerts.length})
              </h2>
              <div className="space-y-2.5">
                {alerts.map((al) => (
                  <div
                    key={al.alert_id}
                    className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-800 bg-slate-900/80 p-3.5 text-xs"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="rounded bg-red-500/20 border border-red-500/40 px-2 py-0.5 font-bold text-red-300">
                          {al.severity}
                        </span>
                        <span className="font-bold text-white">{al.title}</span>
                        <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-[10px] text-cyan-300">
                          Deduplicated Count: {al.occurrence_count}x
                        </span>
                      </div>
                      <p className="text-slate-300">{al.message}</p>
                    </div>
                    <div>
                      {al.acknowledged ? (
                        <span className="text-emerald-400 font-semibold">
                          Acknowledged by {al.acknowledged_by}
                        </span>
                      ) : (
                        <button
                          onClick={() => handleAcknowledgeAlert(al.alert_id)}
                          className="rounded-lg bg-emerald-600 px-3 py-1.5 font-semibold text-white hover:bg-emerald-500"
                        >
                          Acknowledge
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Administrator & Security Audit Log */}
            <div className="rounded-xl border border-slate-800 bg-[#0b1120] p-5 space-y-4">
              <h2 className="text-base font-semibold text-white">
                Privileged Action & Security Guardrail Audit Log ({audits.length})
              </h2>
              <div className="overflow-x-auto max-h-80">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400">
                      <th className="py-2 px-3">Timestamp</th>
                      <th className="py-2 px-3">Actor</th>
                      <th className="py-2 px-3">Role</th>
                      <th className="py-2 px-3">Action</th>
                      <th className="py-2 px-3">Resource</th>
                      <th className="py-2 px-3">Outcome</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/70">
                    {audits.map((ev) => (
                      <tr key={ev.event_id}>
                        <td className="py-2 px-3 font-mono text-[11px] text-slate-400">
                          {new Date(ev.timestamp).toLocaleTimeString()}
                        </td>
                        <td className="py-2 px-3 font-mono text-white">{ev.actor_id}</td>
                        <td className="py-2 px-3 text-amber-300">{ev.actor_role}</td>
                        <td className="py-2 px-3 font-mono text-cyan-300">{ev.action}</td>
                        <td className="py-2 px-3 font-mono text-slate-300">{ev.resource}</td>
                        <td className="py-2 px-3">
                          <span
                            className={`rounded px-2 py-0.5 text-[10px] font-bold ${
                              ev.outcome === "SUCCESS"
                                ? "bg-emerald-500/20 text-emerald-300"
                                : "bg-red-500/20 text-red-300"
                            }`}
                          >
                            {ev.outcome}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

