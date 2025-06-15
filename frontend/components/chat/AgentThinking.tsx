"use client";

import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Brain } from "lucide-react";

interface AgentThinkingProps {
  thoughts: string[];
  isVisible: boolean;
}

export function AgentThinking({ thoughts, isVisible }: AgentThinkingProps) {
  const [thoughtIndex, setThoughtIndex] = useState(0);
  const [showThought, setShowThought] = useState(true);

  // Cycle through thoughts every 2.5s with a brief fade-out between
  useEffect(() => {
    if (!isVisible || thoughts.length === 0) return;

    const cycleThought = () => {
      setShowThought(false);
      setTimeout(() => {
        setThoughtIndex((i) => (i + 1) % thoughts.length);
        setShowThought(true);
      }, 400);
    };

    const interval = setInterval(cycleThought, 2500);
    return () => clearInterval(interval);
  }, [isVisible, thoughts.length]);

  // Reset when hidden
  useEffect(() => {
    if (!isVisible) {
      setThoughtIndex(0);
      setShowThought(true);
    }
  }, [isVisible]);

  const currentThought = thoughts[thoughtIndex] ?? "";

  return (
    <AnimatePresence>
      {isVisible && (
        <motion.div
          key="agent-thinking"
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -8 }}
          transition={{ duration: 0.25, ease: "easeOut" }}
          className="flex items-start gap-3 px-3 py-3 rounded-lg bg-gray-900 border border-gray-800"
        >
          {/* Brain icon with pulse */}
          <motion.div
            animate={{
              scale: [1, 1.12, 1],
              opacity: [0.7, 1, 0.7],
            }}
            transition={{
              duration: 1.6,
              repeat: Infinity,
              ease: "easeInOut",
            }}
            className="flex-shrink-0 mt-0.5"
          >
            <Brain className="h-5 w-5 text-cyan-400" />
          </motion.div>

          <div className="flex-1 min-w-0">
            {/* Label */}
            <span className="text-[10px] text-gray-600 font-semibold uppercase tracking-widest">
              Agent Thinking
            </span>

            {/* Thought text */}
            {currentThought && (
              <AnimatePresence mode="wait">
                {showThought && (
                  <motion.p
                    key={thoughtIndex}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    transition={{ duration: 0.35 }}
                    className="mt-1 text-xs text-gray-400 italic font-mono leading-relaxed truncate"
                  >
                    {currentThought}
                  </motion.p>
                )}
              </AnimatePresence>
            )}

            {/* Animated dots */}
            <div className="flex items-center gap-1 mt-2">
              {[0, 1, 2].map((i) => (
                <motion.span
                  key={i}
                  className="inline-block w-1.5 h-1.5 rounded-full bg-cyan-600"
                  animate={{ opacity: [0.3, 1, 0.3], y: [0, -3, 0] }}
                  transition={{
                    duration: 0.9,
                    repeat: Infinity,
                    delay: i * 0.18,
                    ease: "easeInOut",
                  }}
                />
              ))}
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
