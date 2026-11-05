"use client";

import React, { useState, useRef, useEffect } from "react";
import { Terminal, ShieldCheck, Play, Trash2, Cpu } from "lucide-react";
import { apiFetch } from "@/lib/api";

interface TerminalEntry {
  id: string;
  command: string;
  output: string;
  allowed: boolean;
  status: string;
  timeMs: number;
  timestamp: string;
}

interface TerminalPanelProps {
  role: string;
  user: string;
  onScanTriggered: () => void;
}

const PLATFORM_QUICK_COMMANDS = [
  "help",
  "status",
  "assets",
  "ports",
  "ports 192.168.56.10",
  "changes",
  "findings",
  "scan 192.168.56.10",
  "investigate 192.168.56.10",
  "ai Summarize all critical network exposures and remediation commands",
  "optimize",
];

const ENGINEER_SHELL_COMMANDS = [
  { label: "whoami", cmd: "whoami" },
  { label: "ipconfig /all", cmd: "ipconfig" },
  { label: "Routing Table", cmd: "shell ip route" },
  { label: "ARP Cache (arp -a)", cmd: "arp -a" },
  { label: "Active Sockets (netstat)", cmd: "netstat -ano" },
  { label: "OS Kernel (uname -a)", cmd: "shell uname -a" },
  { label: "Nmap Version", cmd: "shell nmap --version" },
];

export default function TerminalPanel({
  role,
  user,
  onScanTriggered,
}: TerminalPanelProps) {
  const [input, setInput] = useState<string>("");
  const [history, setHistory] = useState<TerminalEntry[]>([
    {
      id: "init-0",
      command: "status",
      output:
        "NETSENTINEL AI Hybrid Command Terminal Initialized (Unrestricted Cybersecurity Engineer Mode)\n" +
        "All Platform Commands, Direct OS/Network Shell Commands, and AI Queries Enabled.\n" +
        "Type 'help' for platform commands, 'ai <question>' for AI analysis, or run any CLI command directly.",
      allowed: true,
      status: "READY",
      timeMs: 1.0,
      timestamp: new Date().toLocaleTimeString(),
    },
  ]);
  const [cmdHistory, setCmdHistory] = useState<string[]>([]);
  const [historyIdx, setHistoryIdx] = useState<number>(-1);
  const [running, setRunning] = useState<boolean>(false);
  const bottomRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [history]);

  const executeCommand = async (rawCmd: string) => {
    const trimmed = rawCmd.trim();
    if (!trimmed) return;

    if (trimmed.toLowerCase() === "clear") {
      setHistory([]);
      setInput("");
      return;
    }

    setRunning(true);
    setCmdHistory((prev) => [trimmed, ...prev]);
    setHistoryIdx(-1);

    try {
      const res = await apiFetch<{
        command: string;
        allowed: boolean;
        status: string;
        output: string;
        execution_time_ms: number;
      }>(
        "/terminal/command",
        {
          method: "POST",
          body: JSON.stringify({ command: trimmed, session_id: "soc-primary" }),
        },
        role,
        user
      );

      if (res.output === "__CLEAR__") {
        setHistory([]);
      } else {
        setHistory((prev) => [
          ...prev,
          {
            id: `${Date.now()}-${Math.random()}`,
            command: trimmed,
            output: res.output,
            allowed: res.allowed,
            status: res.status,
            timeMs: res.execution_time_ms,
            timestamp: new Date().toLocaleTimeString(),
          },
        ]);
      }

      if (trimmed.startsWith("scan ") || trimmed === "optimize") {
        onScanTriggered();
      }
    } catch (err: any) {
      setHistory((prev) => [
        ...prev,
        {
          id: `${Date.now()}-${Math.random()}`,
          command: trimmed,
          output: `[ERROR] ${err.message || String(err)}`,
          allowed: false,
          status: "ERROR",
          timeMs: 0,
          timestamp: new Date().toLocaleTimeString(),
        },
      ]);
    } finally {
      setRunning(false);
      setInput("");
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") {
      executeCommand(input);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      if (cmdHistory.length > 0 && historyIdx + 1 < cmdHistory.length) {
        const nextIdx = historyIdx + 1;
        setHistoryIdx(nextIdx);
        setInput(cmdHistory[nextIdx]);
      }
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      if (historyIdx > 0) {
        const nextIdx = historyIdx - 1;
        setHistoryIdx(nextIdx);
        setInput(cmdHistory[nextIdx]);
      } else {
        setHistoryIdx(-1);
        setInput("");
      }
    }
  };

  return (
    <div className="space-y-4">
      {/* Header & Quick Commands */}
      <div className="rounded-xl border border-slate-800 bg-[#0b1120] p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2.5">
            <Terminal className="h-5 w-5 text-cyan-400" />
            <div>
              <h2 className="text-sm font-semibold text-white">
                Module 6 — Unrestricted Cybersecurity Engineer Command Terminal
              </h2>
              <p className="text-xs text-slate-400">
                Full Platform Telemetry Commands + Direct OS/Network CLI Execution + Inline AI Queries (ai &lt;question&gt;)
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="flex items-center gap-1 rounded-full bg-emerald-500/15 border border-emerald-500/30 px-2.5 py-0.5 text-xs text-emerald-300">
              <ShieldCheck className="h-3.5 w-3.5" />
              Unrestricted Engineer Mode Active
            </span>
            <button
              onClick={() => setHistory([])}
              className="flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1 text-xs text-slate-300 hover:bg-slate-700"
            >
              <Trash2 className="h-3.5 w-3.5" />
              Clear
            </button>
          </div>
        </div>

        {/* Clickable Platform & AI Command Chips */}
        <div>
          <div className="text-[11px] font-medium text-slate-400 mb-1.5">
            NETSENTINEL Intelligence & AI Commands:
          </div>
          <div className="flex flex-wrap gap-1.5">
            {PLATFORM_QUICK_COMMANDS.map((cmd) => (
              <button
                key={cmd}
                onClick={() => executeCommand(cmd)}
                disabled={running}
                className="rounded-md border border-cyan-500/30 bg-cyan-950/30 px-2.5 py-1 font-mono text-xs text-cyan-200 hover:bg-cyan-500/20 hover:border-cyan-400 transition"
              >
                $ {cmd}
              </button>
            ))}
          </div>
        </div>

        {/* Direct System & Network CLI Chips */}
        <div className="pt-1 border-t border-slate-800/80 flex flex-wrap items-center gap-2">
          <span className="text-[11px] text-emerald-400 font-medium flex items-center gap-1">
            <Cpu className="h-3 w-3" /> Direct System & Network CLI:
          </span>
          {ENGINEER_SHELL_COMMANDS.map((item) => (
            <button
              key={item.cmd}
              onClick={() => executeCommand(item.cmd)}
              disabled={running}
              className="rounded-md border border-emerald-500/30 bg-emerald-950/30 px-2 py-0.5 font-mono text-[11px] text-emerald-300 hover:bg-emerald-900/40 transition"
            >
              {item.label} ({item.cmd})
            </button>
          ))}
        </div>
      </div>

      {/* Terminal Screen */}
      <div className="rounded-xl border border-slate-800 bg-[#04070e] shadow-2xl overflow-hidden">
        <div className="flex items-center justify-between border-b border-slate-800 bg-slate-900/90 px-4 py-2 text-xs">
          <div className="flex items-center gap-2">
            <span className="h-2.5 w-2.5 rounded-full bg-red-500/80" />
            <span className="h-2.5 w-2.5 rounded-full bg-amber-500/80" />
            <span className="h-2.5 w-2.5 rounded-full bg-emerald-500/80" />
            <span className="ml-2 font-mono text-slate-300">
              {user}@netsentinel-command-center:~ ({role})
            </span>
          </div>
          <span className="font-mono text-[11px] text-emerald-400">
            FULL ENGINEER SHELL & AI ACCESS
          </span>
        </div>

        <div className="h-[430px] overflow-y-auto p-4 font-mono text-xs space-y-4">
          {history.map((entry) => (
            <div key={entry.id} className="space-y-1.5">
              <div className="flex items-center justify-between text-slate-400">
                <div className="flex items-center gap-2">
                  <span className="text-emerald-400 font-bold">
                    {user}@netsentinel
                  </span>
                  <span className="text-slate-500">$</span>
                  <span className="text-white font-semibold">{entry.command}</span>
                </div>
                <div className="flex items-center gap-2 text-[11px]">
                  <span
                    className={`rounded px-1.5 py-0.5 ${
                      entry.allowed
                        ? "bg-emerald-950/80 text-emerald-300 border border-emerald-500/30"
                        : "bg-red-950/80 text-red-300 border border-red-500/40"
                    }`}
                  >
                    {entry.status}
                  </span>
                  <span className="text-slate-500">{entry.timeMs}ms</span>
                  <span className="text-slate-600">{entry.timestamp}</span>
                </div>
              </div>
              <pre
                className={`whitespace-pre-wrap rounded-lg p-3 leading-relaxed overflow-x-auto ${
                  entry.allowed
                    ? "bg-slate-950/90 text-cyan-100 border border-slate-800/80"
                    : "bg-red-950/30 text-red-300 border border-red-500/40"
                }`}
              >
                {entry.output}
              </pre>
            </div>
          ))}
          <div ref={bottomRef} />
        </div>

        {/* Prompt Input Bar */}
        <div className="flex items-center gap-2 border-t border-slate-800 bg-slate-900/95 px-4 py-3 font-mono text-xs">
          <span className="text-emerald-400 font-bold">{user}@netsentinel:~$</span>
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            disabled={running}
            placeholder="Enter any command (e.g., scan 192.168.56.10, whoami, ipconfig, netstat -ano, ai <question>)..."
            className="flex-1 bg-transparent text-white placeholder-slate-500 focus:outline-none"
          />
          <button
            onClick={() => executeCommand(input)}
            disabled={running || !input.trim()}
            className="flex items-center gap-1 rounded-lg bg-cyan-600 px-3 py-1.5 font-sans text-xs font-semibold text-white hover:bg-cyan-500 disabled:opacity-40"
          >
            <Play className="h-3.5 w-3.5" />
            {running ? "Running..." : "Execute"}
          </button>
        </div>
      </div>
    </div>
  );
}
