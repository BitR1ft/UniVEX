"use client";

import { AnimatePresence, motion } from "framer-motion";
import { X, Copy, ExternalLink, FileText, ChevronRight } from "lucide-react";
import type { GraphNode, GraphRelationship } from "@/lib/api";
import { NODE_COLORS } from "./AttackGraph";

interface NodeDetailProps {
  node: GraphNode | null;
  relationships: GraphRelationship[];
  allNodes: GraphNode[];
  onClose: () => void;
  onNavigate: (nodeId: string) => void;
  onCopyId: (id: string) => void;
  onAddToReport: (node: GraphNode) => void;
}

const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-red-900/50 text-red-400 border-red-700",
  high: "bg-orange-900/50 text-orange-400 border-orange-700",
  medium: "bg-yellow-900/50 text-yellow-400 border-yellow-700",
  low: "bg-blue-900/50 text-blue-400 border-blue-700",
  info: "bg-gray-800 text-gray-400 border-gray-600",
};

function SeverityBadge({ severity }: { severity: string }) {
  const normalized = severity.toLowerCase();
  const style = SEVERITY_STYLES[normalized] ?? SEVERITY_STYLES.info;
  const label = normalized.charAt(0).toUpperCase() + normalized.slice(1);
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold border uppercase tracking-wide ${style}`}
    >
      {label}
    </span>
  );
}

function nodeDisplayName(node: GraphNode): string {
  const p = node.properties;
  return p.name ?? p.domain ?? p.url ?? p.address ?? node.id;
}

export default function NodeDetail({
  node,
  relationships,
  allNodes,
  onClose,
  onNavigate,
  onCopyId,
  onAddToReport,
}: NodeDetailProps) {
  return (
    <AnimatePresence>
      {node && (
        <motion.div
          key={node.id}
          initial={{ x: "100%", opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          exit={{ x: "100%", opacity: 0 }}
          transition={{ type: "spring", stiffness: 320, damping: 32 }}
          className="absolute right-0 top-0 h-full w-96 bg-gray-900 border-l border-gray-700 flex flex-col z-20 shadow-2xl"
        >
          <NodeDetailContent
            node={node}
            relationships={relationships}
            allNodes={allNodes}
            onClose={onClose}
            onNavigate={onNavigate}
            onCopyId={onCopyId}
            onAddToReport={onAddToReport}
          />
        </motion.div>
      )}
    </AnimatePresence>
  );
}

function NodeDetailContent({
  node,
  relationships,
  allNodes,
  onClose,
  onNavigate,
  onCopyId,
  onAddToReport,
}: NodeDetailProps & { node: GraphNode }) {
  const nodeType = node.labels[0] ?? "Unknown";
  const nodeColor = NODE_COLORS[nodeType] ?? "#9CA3AF";
  const displayName = nodeDisplayName(node);
  const severity = node.properties.severity as string | undefined;

  const nodeIndex = Object.fromEntries(allNodes.map((n) => [n.id, n]));

  const incoming = relationships.filter((r) => r.endNode === node.id);
  const outgoing = relationships.filter((r) => r.startNode === node.id);

  const propertyEntries = Object.entries(node.properties).filter(
    ([k]) => k !== "severity"
  );

  return (
    <>
      {/* Color-coded header */}
      <div
        className="flex items-center justify-between px-4 py-3 border-b border-gray-700 flex-shrink-0"
        style={{ borderLeftColor: nodeColor, borderLeftWidth: 3 }}
      >
        <div className="flex items-center gap-2 min-w-0">
          <span
            className="w-3 h-3 rounded-full flex-shrink-0"
            style={{ backgroundColor: nodeColor }}
          />
          <span
            className="text-sm font-bold tracking-wide uppercase"
            style={{ color: nodeColor }}
          >
            {nodeType}
          </span>
          {severity && <SeverityBadge severity={severity} />}
        </div>
        <button
          onClick={onClose}
          className="p-1 text-gray-400 hover:text-white hover:bg-gray-700 rounded transition-colors flex-shrink-0"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      {/* Scrollable body */}
      <div className="flex-1 overflow-y-auto">
        {/* Name & ID */}
        <div className="px-4 py-3 border-b border-gray-800">
          <p className="text-white font-semibold text-sm break-all">{displayName}</p>
          <p className="text-gray-500 text-xs mt-0.5 font-mono break-all">{node.id}</p>
        </div>

        {/* Properties table */}
        {propertyEntries.length > 0 && (
          <section className="border-b border-gray-800">
            <h3 className="px-4 pt-3 pb-1.5 text-xs font-semibold text-gray-500 uppercase tracking-wider">
              Properties
            </h3>
            <div className="px-4 pb-3 space-y-2">
              {propertyEntries.map(([key, value]) => (
                <div key={key} className="flex flex-col gap-0.5">
                  <span className="text-gray-500 text-xs">{key}</span>
                  <span className="text-gray-200 text-sm break-all">
                    {typeof value === "object" ? JSON.stringify(value) : String(value)}
                  </span>
                </div>
              ))}
            </div>
          </section>
        )}

        {/* Connected nodes */}
        {(incoming.length > 0 || outgoing.length > 0) && (
          <section className="border-b border-gray-800">
            <h3 className="px-4 pt-3 pb-1.5 text-xs font-semibold text-gray-500 uppercase tracking-wider">
              Connections
            </h3>
            <div className="pb-3 space-y-0.5">
              {outgoing.map((rel) => {
                const neighbor = nodeIndex[rel.endNode];
                const neighborType = neighbor?.labels[0] ?? "Unknown";
                const neighborColor = NODE_COLORS[neighborType] ?? "#9CA3AF";
                return (
                  <button
                    key={`out-${rel.id}`}
                    onClick={() => onNavigate(rel.endNode)}
                    className="flex items-center gap-2 w-full px-4 py-1.5 text-left hover:bg-gray-800 transition-colors group"
                  >
                    <span className="text-green-500 text-xs font-mono flex-shrink-0">→</span>
                    <span className="text-gray-500 text-xs font-mono flex-shrink-0">{rel.type}</span>
                    <span
                      className="w-2 h-2 rounded-full flex-shrink-0"
                      style={{ backgroundColor: neighborColor }}
                    />
                    <span className="text-gray-300 text-xs truncate group-hover:text-white">
                      {neighbor ? nodeDisplayName(neighbor) : rel.endNode.substring(0, 14) + "…"}
                    </span>
                    <ChevronRight className="h-3 w-3 text-gray-600 ml-auto flex-shrink-0 group-hover:text-gray-400" />
                  </button>
                );
              })}
              {incoming.map((rel) => {
                const neighbor = nodeIndex[rel.startNode];
                const neighborType = neighbor?.labels[0] ?? "Unknown";
                const neighborColor = NODE_COLORS[neighborType] ?? "#9CA3AF";
                return (
                  <button
                    key={`in-${rel.id}`}
                    onClick={() => onNavigate(rel.startNode)}
                    className="flex items-center gap-2 w-full px-4 py-1.5 text-left hover:bg-gray-800 transition-colors group"
                  >
                    <span className="text-blue-500 text-xs font-mono flex-shrink-0">←</span>
                    <span className="text-gray-500 text-xs font-mono flex-shrink-0">{rel.type}</span>
                    <span
                      className="w-2 h-2 rounded-full flex-shrink-0"
                      style={{ backgroundColor: neighborColor }}
                    />
                    <span className="text-gray-300 text-xs truncate group-hover:text-white">
                      {neighbor ? nodeDisplayName(neighbor) : rel.startNode.substring(0, 14) + "…"}
                    </span>
                    <ChevronRight className="h-3 w-3 text-gray-600 ml-auto flex-shrink-0 group-hover:text-gray-400" />
                  </button>
                );
              })}
            </div>
          </section>
        )}
      </div>

      {/* Action buttons */}
      <div className="flex-shrink-0 flex items-center gap-2 px-4 py-3 border-t border-gray-700 bg-gray-900">
        <button
          onClick={() => onCopyId(node.id)}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium bg-gray-800 border border-gray-700 text-gray-300 hover:text-white hover:border-gray-500 transition-colors"
        >
          <Copy className="h-3.5 w-3.5" />
          Copy ID
        </button>
        <button
          onClick={() => onNavigate(node.id)}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium bg-gray-800 border border-gray-700 text-gray-300 hover:text-white hover:border-gray-500 transition-colors"
        >
          <ExternalLink className="h-3.5 w-3.5" />
          Inspector
        </button>
        <button
          onClick={() => onAddToReport(node)}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium bg-cyan-900/40 border border-cyan-700 text-cyan-400 hover:bg-cyan-800/50 hover:text-cyan-300 transition-colors ml-auto"
        >
          <FileText className="h-3.5 w-3.5" />
          Add to Report
        </button>
      </div>
    </>
  );
}
