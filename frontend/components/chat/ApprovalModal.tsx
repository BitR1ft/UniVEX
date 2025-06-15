"use client";

import React from "react";
import { Card } from "@/components/ui/card";
import { AlertTriangle, Shield, CheckCircle, XCircle } from "lucide-react";

interface AttackPlan {
  category: string;
  risk_level: string;
  steps: string[];
  tools: string[];
  target: string;
}

interface ApprovalModalProps {
  isOpen: boolean;
  attackPlan: AttackPlan | null;
  onApprove: () => void;
  onReject: () => void;
}

const riskConfig: Record<string, { color: string; bgColor: string; borderColor: string }> = {
  critical: {
    color: "text-red-600",
    bgColor: "bg-red-100",
    borderColor: "border-red-400",
  },
  high: {
    color: "text-orange-600",
    bgColor: "bg-orange-100",
    borderColor: "border-orange-400",
  },
  medium: {
    color: "text-yellow-600",
    bgColor: "bg-yellow-100",
    borderColor: "border-yellow-400",
  },
};

export function ApprovalModal({ isOpen, attackPlan, onApprove, onReject }: ApprovalModalProps) {
  if (!isOpen || !attackPlan) return null;

  const risk = riskConfig[attackPlan.risk_level.toLowerCase()] || riskConfig.medium;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <Card className="w-full max-w-lg mx-4 p-6">
        {/* Header */}
        <div className="flex items-center gap-3 mb-4">
          <AlertTriangle className="h-6 w-6 text-yellow-600" />
          <h2 className="text-lg font-semibold">Approval Required</h2>
        </div>

        {/* Category & Risk Level */}
        <div className="flex items-center gap-3 mb-4">
          <Shield className="h-5 w-5 text-muted-foreground" />
          <span className="text-sm font-medium">{attackPlan.category}</span>
          <span
            className={`text-xs font-semibold px-2 py-0.5 rounded ${risk.bgColor} ${risk.color} ${risk.borderColor} border`}
          >
            {attackPlan.risk_level}
          </span>
        </div>

        {/* Target */}
        <div className="mb-4">
          <div className="text-sm font-semibold mb-1">Target</div>
          <div className="text-sm text-muted-foreground">{attackPlan.target}</div>
        </div>

        {/* Steps */}
        <div className="mb-4">
          <div className="text-sm font-semibold mb-1">Attack Steps</div>
          <ol className="list-decimal list-inside space-y-1">
            {attackPlan.steps.map((step, index) => (
              <li key={index} className="text-sm text-muted-foreground">
                {step}
              </li>
            ))}
          </ol>
        </div>

        {/* Tools */}
        <div className="mb-6">
          <div className="text-sm font-semibold mb-1">Required Tools</div>
          <div className="flex flex-wrap gap-2">
            {attackPlan.tools.map((tool, index) => (
              <span
                key={index}
                className="text-xs px-2 py-1 rounded bg-gray-100 border border-gray-300 text-gray-700 dark:bg-gray-800 dark:border-gray-600 dark:text-gray-300"
              >
                {tool}
              </span>
            ))}
          </div>
        </div>

        {/* Actions */}
        <div className="flex items-center justify-end gap-3">
          <button
            onClick={onReject}
            className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-md bg-red-600 text-white hover:bg-red-700 transition-colors"
          >
            <XCircle className="h-4 w-4" />
            Reject
          </button>
          <button
            onClick={onApprove}
            className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-md bg-green-600 text-white hover:bg-green-700 transition-colors"
          >
            <CheckCircle className="h-4 w-4" />
            Approve
          </button>
        </div>
      </Card>
    </div>
  );
}
