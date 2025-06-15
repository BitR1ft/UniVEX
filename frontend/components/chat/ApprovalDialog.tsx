"use client";

import React, { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Button } from "@/components/ui/button";
import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Shield,
  Clock,
} from "lucide-react";

type RiskLevel = "critical" | "high" | "medium" | "low";

interface ApprovalDialogProps {
  isOpen: boolean;
  title: string;
  description: string;
  riskLevel: RiskLevel;
  riskScore: number;
  evidence: string[];
  onApprove: () => void;
  onReject: () => void;
}

const riskConfig: Record<
  RiskLevel,
  { label: string; color: string; ringColor: string; textColor: string; bgBorder: string }
> = {
  critical: {
    label: "CRITICAL",
    color: "#ef4444",
    ringColor: "stroke-red-500",
    textColor: "text-red-400",
    bgBorder: "border-red-800",
  },
  high: {
    label: "HIGH",
    color: "#f97316",
    ringColor: "stroke-orange-500",
    textColor: "text-orange-400",
    bgBorder: "border-orange-800",
  },
  medium: {
    label: "MEDIUM",
    color: "#eab308",
    ringColor: "stroke-yellow-500",
    textColor: "text-yellow-400",
    bgBorder: "border-yellow-800",
  },
  low: {
    label: "LOW",
    color: "#22c55e",
    ringColor: "stroke-green-500",
    textColor: "text-green-400",
    bgBorder: "border-green-800",
  },
};

const AUTO_REJECT_SECONDS = 30;

interface RiskCircleProps {
  score: number;
  level: RiskLevel;
}

function RiskCircle({ score, level }: RiskCircleProps) {
  const cfg = riskConfig[level];
  const radius = 36;
  const circumference = 2 * Math.PI * radius;
  const progress = Math.min(Math.max(score, 0), 100) / 100;
  const strokeDashoffset = circumference * (1 - progress);

  return (
    <div className="relative flex items-center justify-center w-24 h-24">
      <svg className="w-24 h-24 -rotate-90" viewBox="0 0 88 88">
        {/* Track */}
        <circle
          cx="44"
          cy="44"
          r={radius}
          fill="none"
          stroke="#1f2937"
          strokeWidth="8"
        />
        {/* Progress */}
        <circle
          cx="44"
          cy="44"
          r={radius}
          fill="none"
          stroke={cfg.color}
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          style={{ transition: "stroke-dashoffset 0.6s ease" }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className={`text-xl font-bold tabular-nums ${cfg.textColor}`}>
          {score}
        </span>
        <span className={`text-[9px] font-semibold tracking-wider ${cfg.textColor}`}>
          {cfg.label}
        </span>
      </div>
    </div>
  );
}

export function ApprovalDialog({
  isOpen,
  title,
  description,
  riskLevel,
  riskScore,
  evidence,
  onApprove,
  onReject,
}: ApprovalDialogProps) {
  const [timeLeft, setTimeLeft] = useState(AUTO_REJECT_SECONDS);
  const [expandedEvidence, setExpandedEvidence] = useState<number | null>(null);
  const [confirmAction, setConfirmAction] = useState<"approve" | "reject" | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const cfg = riskConfig[riskLevel];

  useEffect(() => {
    if (!isOpen) {
      setTimeLeft(AUTO_REJECT_SECONDS);
      setConfirmAction(null);
      if (timerRef.current) clearInterval(timerRef.current);
      return;
    }

    timerRef.current = setInterval(() => {
      setTimeLeft((t) => {
        if (t <= 1) {
          clearInterval(timerRef.current ?? undefined);
          onReject();
          return 0;
        }
        return t - 1;
      });
    }, 1000);

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [isOpen, onReject]);

  const handleApprove = () => {
    if (confirmAction === "approve") {
      if (timerRef.current) clearInterval(timerRef.current);
      onApprove();
    } else {
      setConfirmAction("approve");
    }
  };

  const handleReject = () => {
    if (confirmAction === "reject") {
      if (timerRef.current) clearInterval(timerRef.current);
      onReject();
    } else {
      setConfirmAction("reject");
    }
  };

  const timerPercent = (timeLeft / AUTO_REJECT_SECONDS) * 100;

  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div
          key="approval-backdrop"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.2 }}
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4"
        >
          <motion.div
            key="approval-dialog"
            initial={{ scale: 0.92, opacity: 0, y: 16 }}
            animate={{ scale: 1, opacity: 1, y: 0 }}
            exit={{ scale: 0.92, opacity: 0, y: 16 }}
            transition={{ duration: 0.22, ease: "easeOut" }}
            className={`w-full max-w-lg bg-gray-900 rounded-xl border ${cfg.bgBorder} shadow-2xl overflow-hidden`}
          >
            {/* Auto-reject timer bar */}
            <div className="h-1 w-full bg-gray-800">
              <motion.div
                className="h-1 bg-red-500 origin-left"
                initial={{ scaleX: 1 }}
                animate={{ scaleX: timerPercent / 100 }}
                transition={{ duration: 0.9, ease: "linear" }}
                style={{ transformOrigin: "left" }}
              />
            </div>

            {/* Header */}
            <div className="px-5 pt-5 pb-4 flex items-start gap-4 border-b border-gray-800">
              <div className="flex-shrink-0">
                <RiskCircle score={riskScore} level={riskLevel} />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <AlertTriangle className={`h-4 w-4 ${cfg.textColor}`} />
                  <span className="text-xs font-semibold text-gray-500 tracking-widest uppercase">
                    Approval Required
                  </span>
                </div>
                <h2 className="text-base font-bold text-white leading-snug mb-1">
                  {title}
                </h2>
                <p className="text-sm text-gray-400 leading-relaxed">
                  {description}
                </p>
              </div>
            </div>

            {/* Evidence */}
            <div className="px-5 py-4 space-y-2">
              <div className="flex items-center gap-2 mb-2">
                <Shield className="h-3.5 w-3.5 text-gray-500" />
                <span className="text-xs font-semibold text-gray-500 uppercase tracking-widest">
                  Risk Evidence
                </span>
              </div>
              {evidence.length === 0 ? (
                <p className="text-xs text-gray-600">No evidence provided.</p>
              ) : (
                evidence.map((item, idx) => {
                  const isExpanded = expandedEvidence === idx;
                  const isLong = item.length > 80;
                  return (
                    <div
                      key={idx}
                      className={`rounded-md border border-gray-800 bg-gray-950 overflow-hidden transition-colors ${
                        isLong ? "cursor-pointer hover:border-gray-700" : ""
                      }`}
                      onClick={() =>
                        isLong &&
                        setExpandedEvidence(isExpanded ? null : idx)
                      }
                    >
                      <div className="flex items-start gap-2 px-3 py-2">
                        <span className={`text-[10px] font-bold mt-0.5 ${cfg.textColor}`}>
                          {String(idx + 1).padStart(2, "0")}
                        </span>
                        <p
                          className={`text-xs text-gray-400 flex-1 ${
                            !isExpanded && isLong ? "line-clamp-2" : ""
                          }`}
                        >
                          {item}
                        </p>
                        {isLong && (
                          <span className="flex-shrink-0 text-gray-600 mt-0.5">
                            {isExpanded ? (
                              <ChevronUp className="h-3 w-3" />
                            ) : (
                              <ChevronDown className="h-3 w-3" />
                            )}
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })
              )}
            </div>

            {/* Footer */}
            <div className="px-5 pb-5 pt-2 flex items-center justify-between border-t border-gray-800">
              {/* Timer */}
              <div className="flex items-center gap-1.5 text-xs text-gray-600">
                <Clock className="h-3.5 w-3.5" />
                <span>
                  Auto-reject in{" "}
                  <span className="text-red-400 font-semibold tabular-nums">
                    {timeLeft}s
                  </span>
                </span>
              </div>

              {/* Buttons */}
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleReject}
                  className={`border-red-800 text-red-400 hover:bg-red-950 hover:text-red-300 gap-1.5 ${
                    confirmAction === "reject"
                      ? "bg-red-950 border-red-600 ring-1 ring-red-600"
                      : ""
                  }`}
                >
                  <XCircle className="h-3.5 w-3.5" />
                  {confirmAction === "reject" ? "Confirm Reject" : "Reject"}
                </Button>
                <Button
                  size="sm"
                  onClick={handleApprove}
                  className={`bg-green-700 hover:bg-green-600 text-white border-0 gap-1.5 ${
                    confirmAction === "approve"
                      ? "ring-2 ring-green-400"
                      : ""
                  }`}
                >
                  <CheckCircle2 className="h-3.5 w-3.5" />
                  {confirmAction === "approve" ? "Confirm Approve" : "Approve"}
                </Button>
              </div>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
