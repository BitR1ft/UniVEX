"use client";

import React from "react";
import { Card } from "@/components/ui/card";
import { Info, Target, Shield, CheckCircle } from "lucide-react";

type Phase = "informational" | "exploitation" | "post_exploitation" | "complete";

interface PhaseIndicatorProps {
  currentPhase: Phase;
}

const phaseConfig = {
  informational: {
    label: "Informational",
    description: "Gathering intelligence about the target",
    icon: Info,
    color: "text-blue-600",
    bgColor: "bg-blue-50",
    borderColor: "border-blue-300",
  },
  exploitation: {
    label: "Exploitation",
    description: "Attempting to gain access to the target",
    icon: Target,
    color: "text-red-600",
    bgColor: "bg-red-50",
    borderColor: "border-red-300",
  },
  post_exploitation: {
    label: "Post-Exploitation",
    description: "Enumerating and escalating privileges",
    icon: Shield,
    color: "text-purple-600",
    bgColor: "bg-purple-50",
    borderColor: "border-purple-300",
  },
  complete: {
    label: "Complete",
    description: "Engagement finished",
    icon: CheckCircle,
    color: "text-green-600",
    bgColor: "bg-green-50",
    borderColor: "border-green-300",
  },
};

export function PhaseIndicator({ currentPhase }: PhaseIndicatorProps) {
  const config = phaseConfig[currentPhase] || phaseConfig.informational;
  const Icon = config.icon;

  return (
    <Card className={`p-4 ${config.bgColor} ${config.borderColor} border-2`}>
      <div className="flex items-center gap-3">
        <Icon className={`h-6 w-6 ${config.color}`} />
        <div>
          <div className={`font-semibold ${config.color}`}>{config.label} Phase</div>
          <div className="text-sm text-muted-foreground">{config.description}</div>
        </div>
      </div>
    </Card>
  );
}
