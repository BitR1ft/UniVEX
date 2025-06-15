'use client';

import { useState } from 'react';
import { X, ChevronDown, ChevronRight, ArrowRight, ArrowLeft } from 'lucide-react';
import type { GraphNode, GraphRelationship } from '@/lib/api';
import { NODE_COLORS } from './AttackGraph';

interface NodeInspectorProps {
  node: GraphNode | null;
  relationships: GraphRelationship[];
  onClose: () => void;
  onNavigate: (nodeId: string) => void;
}

export default function NodeInspector({ node, relationships, onClose, onNavigate }: NodeInspectorProps) {
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    properties: true,
    incoming: true,
    outgoing: true,
  });

  if (!node) return null;

  const nodeType = node.labels[0] || 'Unknown';
  const nodeColor = NODE_COLORS[nodeType] || '#9CA3AF';

  const incoming = relationships.filter((r) => r.endNode === node.id);
  const outgoing = relationships.filter((r) => r.startNode === node.id);

  const toggleSection = (section: string) => {
    setExpandedSections((prev) => ({ ...prev, [section]: !prev[section] }));
  };

  const propertyEntries = Object.entries(node.properties);

  return (
    <div className="w-80 bg-gray-800 border-l border-gray-700 h-full overflow-y-auto flex flex-col animate-slide-in-right">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-gray-700">
        <div className="flex items-center gap-2 min-w-0">
          <span
            className="inline-block w-3 h-3 rounded-full flex-shrink-0"
            style={{ backgroundColor: nodeColor }}
          />
          <span className="text-sm font-semibold px-2 py-0.5 rounded" style={{ color: nodeColor }}>
            {nodeType}
          </span>
        </div>
        <button
          onClick={onClose}
          className="p-1 text-gray-400 hover:text-white hover:bg-gray-700 rounded transition-colors"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      {/* Node Name */}
      <div className="px-4 py-3 border-b border-gray-700">
        <p className="text-white text-sm font-medium break-all">
          {node.properties.name || node.properties.domain || node.properties.url || node.id}
        </p>
        <p className="text-gray-500 text-xs mt-1 break-all">{node.id}</p>
      </div>

      {/* Properties Section */}
      <div className="border-b border-gray-700">
        <button
          onClick={() => toggleSection('properties')}
          className="flex items-center gap-2 w-full px-4 py-3 text-left text-sm font-semibold text-gray-300 hover:bg-gray-750 transition-colors"
        >
          {expandedSections.properties ? (
            <ChevronDown className="h-4 w-4 flex-shrink-0" />
          ) : (
            <ChevronRight className="h-4 w-4 flex-shrink-0" />
          )}
          Properties
          <span className="text-gray-500 text-xs ml-auto">{propertyEntries.length}</span>
        </button>
        {expandedSections.properties && (
          <div className="px-4 pb-3 space-y-2">
            {propertyEntries.length === 0 ? (
              <p className="text-gray-500 text-xs italic">No properties</p>
            ) : (
              propertyEntries.map(([key, value]) => (
                <div key={key} className="flex flex-col gap-0.5">
                  <span className="text-gray-500 text-xs">{key}</span>
                  <span className="text-gray-200 text-sm break-all">
                    {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                  </span>
                </div>
              ))
            )}
          </div>
        )}
      </div>

      {/* Incoming Relationships */}
      <div className="border-b border-gray-700">
        <button
          onClick={() => toggleSection('incoming')}
          className="flex items-center gap-2 w-full px-4 py-3 text-left text-sm font-semibold text-gray-300 hover:bg-gray-750 transition-colors"
        >
          {expandedSections.incoming ? (
            <ChevronDown className="h-4 w-4 flex-shrink-0" />
          ) : (
            <ChevronRight className="h-4 w-4 flex-shrink-0" />
          )}
          <ArrowLeft className="h-3 w-3 flex-shrink-0 text-blue-400" />
          Incoming
          <span className="text-gray-500 text-xs ml-auto">{incoming.length}</span>
        </button>
        {expandedSections.incoming && (
          <div className="px-4 pb-3 space-y-1">
            {incoming.length === 0 ? (
              <p className="text-gray-500 text-xs italic">No incoming relationships</p>
            ) : (
              incoming.map((rel) => (
                <button
                  key={rel.id}
                  onClick={() => onNavigate(rel.startNode)}
                  className="flex items-center gap-2 w-full px-2 py-1.5 text-left text-sm rounded hover:bg-gray-700 transition-colors group"
                >
                  <span className="text-blue-400 text-xs font-mono flex-shrink-0">{rel.type}</span>
                  <ArrowLeft className="h-3 w-3 text-gray-500 flex-shrink-0" />
                  <span className="text-gray-300 text-xs truncate group-hover:text-white">
                    {rel.startNode.substring(0, 12)}…
                  </span>
                </button>
              ))
            )}
          </div>
        )}
      </div>

      {/* Outgoing Relationships */}
      <div className="border-b border-gray-700">
        <button
          onClick={() => toggleSection('outgoing')}
          className="flex items-center gap-2 w-full px-4 py-3 text-left text-sm font-semibold text-gray-300 hover:bg-gray-750 transition-colors"
        >
          {expandedSections.outgoing ? (
            <ChevronDown className="h-4 w-4 flex-shrink-0" />
          ) : (
            <ChevronRight className="h-4 w-4 flex-shrink-0" />
          )}
          <ArrowRight className="h-3 w-3 flex-shrink-0 text-green-400" />
          Outgoing
          <span className="text-gray-500 text-xs ml-auto">{outgoing.length}</span>
        </button>
        {expandedSections.outgoing && (
          <div className="px-4 pb-3 space-y-1">
            {outgoing.length === 0 ? (
              <p className="text-gray-500 text-xs italic">No outgoing relationships</p>
            ) : (
              outgoing.map((rel) => (
                <button
                  key={rel.id}
                  onClick={() => onNavigate(rel.endNode)}
                  className="flex items-center gap-2 w-full px-2 py-1.5 text-left text-sm rounded hover:bg-gray-700 transition-colors group"
                >
                  <span className="text-green-400 text-xs font-mono flex-shrink-0">{rel.type}</span>
                  <ArrowRight className="h-3 w-3 text-gray-500 flex-shrink-0" />
                  <span className="text-gray-300 text-xs truncate group-hover:text-white">
                    {rel.endNode.substring(0, 12)}…
                  </span>
                </button>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  );
}
