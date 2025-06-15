"use client";

import React, { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Button } from "@/components/ui/button";
import {
  Plus,
  Search,
  MessageSquare,
  Trash2,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";

export interface ChatSession {
  id: string;
  name: string;
  timestamp: Date;
  messageCount: number;
}

interface ChatSidebarProps {
  sessions: ChatSession[];
  activeSessionId: string | null;
  onSelectSession: (id: string) => void;
  onNewSession: () => void;
  onDeleteSession: (id: string) => void;
  isCollapsed: boolean;
  onToggleCollapse: () => void;
}

function formatSessionTime(date: Date): string {
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffMins < 1) return "Just now";
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  return `${diffDays}d ago`;
}

export function ChatSidebar({
  sessions,
  activeSessionId,
  onSelectSession,
  onNewSession,
  onDeleteSession,
  isCollapsed,
  onToggleCollapse,
}: ChatSidebarProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [hoveredId, setHoveredId] = useState<string | null>(null);

  const filteredSessions = sessions.filter((s) =>
    s.name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="relative flex h-full">
      <AnimatePresence initial={false}>
        {!isCollapsed && (
          <motion.div
            key="sidebar"
            initial={{ width: 0, opacity: 0 }}
            animate={{ width: 260, opacity: 1 }}
            exit={{ width: 0, opacity: 0 }}
            transition={{ duration: 0.25, ease: "easeInOut" }}
            className="overflow-hidden flex-shrink-0"
          >
            <div className="w-[260px] h-full flex flex-col bg-gray-900 border-r border-gray-700">
              {/* Header */}
              <div className="p-3 border-b border-gray-700 space-y-2">
                <Button
                  onClick={onNewSession}
                  className="w-full bg-cyan-600 hover:bg-cyan-500 text-white border-0 gap-2"
                  size="sm"
                >
                  <Plus className="h-4 w-4" />
                  New Session
                </Button>

                {/* Search */}
                <div className="relative">
                  <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-500" />
                  <input
                    type="text"
                    placeholder="Search sessions..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-full pl-8 pr-3 py-1.5 text-xs bg-gray-800 border border-gray-700 rounded-md text-gray-300 placeholder-gray-600 focus:outline-none focus:border-cyan-600 focus:ring-1 focus:ring-cyan-600"
                  />
                </div>
              </div>

              {/* Session list */}
              <div className="flex-1 overflow-y-auto py-1">
                {filteredSessions.length === 0 ? (
                  <div className="px-4 py-8 text-center text-xs text-gray-600">
                    {searchQuery ? "No sessions match your search" : "No sessions yet"}
                  </div>
                ) : (
                  filteredSessions.map((session) => {
                    const isActive = session.id === activeSessionId;
                    const isHovered = hoveredId === session.id;
                    return (
                      <motion.div
                        key={session.id}
                        initial={{ opacity: 0, x: -12 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ duration: 0.15 }}
                        onMouseEnter={() => setHoveredId(session.id)}
                        onMouseLeave={() => setHoveredId(null)}
                        className={`group mx-2 my-0.5 rounded-md cursor-pointer transition-colors duration-150 ${
                          isActive
                            ? "bg-cyan-950 border border-cyan-700"
                            : "border border-transparent hover:bg-gray-800"
                        }`}
                        onClick={() => onSelectSession(session.id)}
                      >
                        <div className="flex items-start gap-2 p-2.5">
                          <MessageSquare
                            className={`h-4 w-4 mt-0.5 flex-shrink-0 ${
                              isActive ? "text-cyan-400" : "text-gray-600"
                            }`}
                          />
                          <div className="flex-1 min-w-0">
                            <div
                              className={`text-xs font-medium truncate ${
                                isActive ? "text-cyan-300" : "text-gray-300"
                              }`}
                            >
                              {session.name}
                            </div>
                            <div className="flex items-center gap-2 mt-0.5">
                              <span className="text-[10px] text-gray-600">
                                {formatSessionTime(session.timestamp)}
                              </span>
                              <span className="text-[10px] text-gray-700">
                                {session.messageCount} msg
                                {session.messageCount !== 1 ? "s" : ""}
                              </span>
                            </div>
                          </div>
                          {/* Delete button */}
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              onDeleteSession(session.id);
                            }}
                            className={`flex-shrink-0 p-0.5 rounded transition-opacity duration-150 ${
                              isHovered || isActive ? "opacity-100" : "opacity-0"
                            } hover:text-red-400 text-gray-600`}
                          >
                            <Trash2 className="h-3 w-3" />
                          </button>
                        </div>
                      </motion.div>
                    );
                  })
                )}
              </div>

              {/* Footer */}
              <div className="p-3 border-t border-gray-700">
                <div className="text-[10px] text-gray-700 text-center">
                  {sessions.length} session{sessions.length !== 1 ? "s" : ""}
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Toggle button */}
      <button
        onClick={onToggleCollapse}
        className="absolute -right-3 top-1/2 -translate-y-1/2 z-10 flex items-center justify-center w-6 h-10 rounded-full bg-gray-800 border border-gray-700 text-gray-400 hover:text-cyan-400 hover:border-cyan-700 transition-colors duration-150 shadow-lg"
        title={isCollapsed ? "Expand sidebar" : "Collapse sidebar"}
      >
        {isCollapsed ? (
          <ChevronRight className="h-3.5 w-3.5" />
        ) : (
          <ChevronLeft className="h-3.5 w-3.5" />
        )}
      </button>
    </div>
  );
}
