"use client";

import React from "react";
import { Card } from "@/components/ui/card";
import { Loader, CheckCircle, XCircle, PauseCircle } from "lucide-react";

interface Progress {
  current_step: string;
  total_steps: number;
  completed_steps: number;
  percentage: number;
  elapsed_seconds: number;
  status: string;
}

interface ProgressStreamProps {
  progress: Progress | null;
}

const statusConfig = {
  running: {
    label: "Running",
    icon: Loader,
    color: "text-blue-600",
    bgColor: "bg-blue-100",
    barColor: "bg-blue-600",
    iconClass: "animate-spin",
  },
  completed: {
    label: "Completed",
    icon: CheckCircle,
    color: "text-green-600",
    bgColor: "bg-green-100",
    barColor: "bg-green-600",
    iconClass: "",
  },
  failed: {
    label: "Failed",
    icon: XCircle,
    color: "text-red-600",
    bgColor: "bg-red-100",
    barColor: "bg-red-600",
    iconClass: "",
  },
  paused: {
    label: "Paused",
    icon: PauseCircle,
    color: "text-yellow-600",
    bgColor: "bg-yellow-100",
    barColor: "bg-yellow-600",
    iconClass: "",
  },
} as const;

function formatElapsed(seconds: number): string {
  const mins = Math.floor(seconds / 60);
  const secs = Math.floor(seconds % 60);
  return `${mins}m ${secs}s`;
}

export function ProgressStream({ progress }: ProgressStreamProps) {
  if (!progress) return null;

  const config =
    statusConfig[progress.status as keyof typeof statusConfig] ||
    statusConfig.running;
  const Icon = config.icon;

  return (
    <Card className="p-4">
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-sm font-medium text-muted-foreground">
            {progress.current_step}
          </span>
          <span
            className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ${config.bgColor} ${config.color}`}
          >
            <Icon className={`h-3 w-3 ${config.iconClass}`} />
            {config.label}
          </span>
        </div>

        <div className="h-2 w-full rounded-full bg-gray-200 dark:bg-gray-700">
          <div
            className={`h-2 rounded-full ${config.barColor} transition-all duration-300`}
            style={{ width: `${Math.min(progress.percentage, 100)}%` }}
          />
        </div>

        <div className="flex items-center justify-between text-xs text-muted-foreground">
          <span>
            {progress.completed_steps} / {progress.total_steps} steps
          </span>
          <span>{formatElapsed(progress.elapsed_seconds)}</span>
        </div>
      </div>
    </Card>
  );
}
