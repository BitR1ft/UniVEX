"use client";

import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Card } from "@/components/ui/card";
import {
  Wrench,
  Loader2,
  CheckCircle2,
  XCircle,
  Clock,
  ChevronDown,
  ChevronUp,
  Terminal,
  Settings2,
  Shuffle,
  Network,
  Shield,
  Cloud,
} from "lucide-react";

type ToolStatus = "queued" | "running" | "completed" | "failed";
type ToolCategory = "recon" | "web" | "exploitation" | "post-exploitation" | "active-directory" | "cloud" | "proxy" | "network" | "default";

interface ToolExecutionCardProps {
  toolName: string;
  status: ToolStatus;
  category?: ToolCategory;
  input?: Record<string, unknown>;
  output?: string;
  error?: string;
  duration?: number;
  startTime?: Date;
}

const categoryConfig: Record<ToolCategory, { icon: React.ElementType; label: string; accentColor: string }> = {
  recon:              { icon: Network,  label: "Recon",            accentColor: "text-blue-400" },
  web:                { icon: Wrench,   label: "Web",              accentColor: "text-yellow-400" },
  exploitation:       { icon: Terminal, label: "Exploitation",     accentColor: "text-red-400" },
  "post-exploitation":{ icon: Shield,   label: "Post-Exploit",     accentColor: "text-orange-400" },
  "active-directory": { icon: Shield,   label: "Active Directory", accentColor: "text-purple-400" },
  cloud:              { icon: Cloud,    label: "Cloud",            accentColor: "text-sky-400" },
  proxy:              { icon: Shuffle,  label: "Proxy",            accentColor: "text-teal-400" },
  network:            { icon: Network,  label: "Network",          accentColor: "text-green-400" },
  default:            { icon: Wrench,   label: "Tool",             accentColor: "text-gray-400" },
};

const statusConfig: Record<
  ToolStatus,
  { label: string; color: string; borderColor: string; badgeBg: string }
> = {
  queued: {
    label: "Queued",
    color: "text-gray-400",
    borderColor: "border-gray-700",
    badgeBg: "bg-gray-800",
  },
  running: {
    label: "Running",
    color: "text-cyan-400",
    borderColor: "border-cyan-800",
    badgeBg: "bg-cyan-950",
  },
  completed: {
    label: "Completed",
    color: "text-green-400",
    borderColor: "border-green-900",
    badgeBg: "bg-green-950",
  },
  failed: {
    label: "Failed",
    color: "text-red-400",
    borderColor: "border-red-900",
    badgeBg: "bg-red-950",
  },
};

function StatusIcon({ status }: { status: ToolStatus }) {
  switch (status) {
    case "queued":
      return <Clock className="h-4 w-4 text-gray-400" />;
    case "running":
      return <Loader2 className="h-4 w-4 text-cyan-400 animate-spin" />;
    case "completed":
      return <CheckCircle2 className="h-4 w-4 text-green-400" />;
    case "failed":
      return <XCircle className="h-4 w-4 text-red-400" />;
  }
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  const mins = Math.floor(ms / 60000);
  const secs = Math.floor((ms % 60000) / 1000);
  return `${mins}m ${secs}s`;
}

export function ToolExecutionCard({
  toolName,
  status,
  category = "default",
  input,
  output,
  error,
  duration,
  startTime,
}: ToolExecutionCardProps) {
  const [outputOpen, setOutputOpen] = useState(false);
  const [inputOpen, setInputOpen] = useState(false);
  const [elapsed, setElapsed] = useState(0);

  const cfg = statusConfig[status];
  const catCfg = categoryConfig[category];
  const CategoryIcon = catCfg.icon;

  // Live elapsed timer for running tools
  useEffect(() => {
    if (status !== "running" || !startTime) return;
    const interval = setInterval(() => {
      setElapsed(Date.now() - startTime.getTime());
    }, 200);
    return () => clearInterval(interval);
  }, [status, startTime]);

  const displayDuration =
    status === "running" && startTime
      ? formatDuration(elapsed)
      : duration !== undefined
      ? formatDuration(duration)
      : null;

  const hasInput = input && Object.keys(input).length > 0;
  const hasOutput = output || error;

  return (
    <Card
      className={`bg-gray-900 border ${cfg.borderColor} overflow-hidden font-mono text-xs`}
    >
      {/* Header row */}
      <div className={`flex items-center gap-2 px-3 py-2 ${cfg.badgeBg} border-b ${cfg.borderColor}`}>
        <CategoryIcon className={`h-3.5 w-3.5 ${catCfg.accentColor}`} />
        <span className={`flex-1 font-semibold tracking-wide ${cfg.color}`}>
          {toolName}
        </span>

        {/* Category badge */}
        {category !== "default" && (
          <span className={`text-[10px] font-medium px-1.5 py-0.5 rounded ${catCfg.accentColor} bg-gray-900/50`}>
            {catCfg.label}
          </span>
        )}

        {/* Status badge */}
        <div className={`flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-gray-900/60 border ${cfg.borderColor}`}>
          <StatusIcon status={status} />
          <span className={`text-[10px] font-medium ${cfg.color}`}>
            {cfg.label}
          </span>
        </div>

        {/* Duration */}
        {displayDuration && (
          <span className="text-[10px] text-gray-600 tabular-nums">
            {displayDuration}
          </span>
        )}
      </div>

      {/* Input parameters */}
      {hasInput && (
        <div>
          <button
            onClick={() => setInputOpen((o) => !o)}
            className="w-full flex items-center gap-1.5 px-3 py-1.5 text-[10px] text-gray-500 hover:text-gray-300 hover:bg-gray-800/50 transition-colors"
          >
            <Settings2 className="h-3 w-3" />
            <span>Parameters</span>
            {inputOpen ? (
              <ChevronUp className="h-3 w-3 ml-auto" />
            ) : (
              <ChevronDown className="h-3 w-3 ml-auto" />
            )}
          </button>
          <AnimatePresence initial={false}>
            {inputOpen && (
              <motion.div
                key="input-panel"
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: "auto", opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.2 }}
                className="overflow-hidden"
              >
                <pre className="px-3 py-2 text-[10px] text-gray-400 bg-gray-950 border-t border-gray-800 overflow-x-auto whitespace-pre-wrap">
                  {JSON.stringify(input, null, 2)}
                </pre>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      )}

      {/* Output / error */}
      {hasOutput && (
        <div>
          <button
            onClick={() => setOutputOpen((o) => !o)}
            className="w-full flex items-center gap-1.5 px-3 py-1.5 text-[10px] text-gray-500 hover:text-gray-300 hover:bg-gray-800/50 transition-colors border-t border-gray-800"
          >
            <Terminal className="h-3 w-3" />
            <span>{error ? "Error output" : "Output"}</span>
            {outputOpen ? (
              <ChevronUp className="h-3 w-3 ml-auto" />
            ) : (
              <ChevronDown className="h-3 w-3 ml-auto" />
            )}
          </button>
          <AnimatePresence initial={false}>
            {outputOpen && (
              <motion.div
                key="output-panel"
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: "auto", opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.2 }}
                className="overflow-hidden"
              >
                <pre
                  className={`px-3 py-2 text-[10px] bg-gray-950 border-t border-gray-800 overflow-x-auto whitespace-pre-wrap break-all max-h-60 overflow-y-auto ${
                    error ? "text-red-400" : "text-green-400"
                  }`}
                >
                  {error ?? output}
                </pre>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      )}
    </Card>
  );
}
