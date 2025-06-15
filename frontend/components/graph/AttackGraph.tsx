'use client';

import { useRef, useMemo, useCallback, useState, useEffect } from 'react';
import dynamic from 'next/dynamic';
import type { GraphNode, GraphRelationship } from '@/lib/api';

const ForceGraph2D = dynamic(() => import('react-force-graph-2d'), {
  ssr: false,
});

export const NODE_COLORS: Record<string, string> = {
  Domain: '#3B82F6',
  Subdomain: '#60A5FA',
  IP: '#8B5CF6',
  Port: '#F59E0B',
  Service: '#10B981',
  BaseURL: '#06B6D4',
  Endpoint: '#14B8A6',
  Parameter: '#A78BFA',
  Technology: '#F97316',
  Header: '#6B7280',
  Certificate: '#EC4899',
  DNSRecord: '#84CC16',
  Vulnerability: '#EF4444',
  CVE: '#DC2626',
  MitreData: '#B91C1C',
  Capec: '#991B1B',
  Exploit: '#7F1D1D',
};

const GLOW_TYPES = new Set(['Vulnerability', 'CVE']);

const MIN_NODE_RADIUS = 4;
const MAX_NODE_RADIUS = 12;
const RADIUS_SCALE_FACTOR = 0.8;
const MAX_LABEL_LENGTH = 20;

const LINK_COLORS: Record<string, string> = {
  HAS_SUBDOMAIN: '#60A5FA',
  RESOLVES_TO: '#8B5CF6',
  HAS_PORT: '#F59E0B',
  RUNS_SERVICE: '#10B981',
  HAS_URL: '#06B6D4',
  HAS_ENDPOINT: '#14B8A6',
  HAS_PARAMETER: '#A78BFA',
  USES_TECHNOLOGY: '#F97316',
  HAS_HEADER: '#6B7280',
  HAS_CERTIFICATE: '#EC4899',
  HAS_DNS_RECORD: '#84CC16',
  HAS_VULNERABILITY: '#EF4444',
  HAS_CVE: '#DC2626',
  MITIGATED_BY: '#B91C1C',
  EXPLOITED_BY: '#7F1D1D',
};

const DEFAULT_LINK_COLOR = '#4B5563';

interface ForceNode {
  id: string;
  name: string;
  type: string;
  [key: string]: any;
}

interface ForceLink {
  source: string;
  target: string;
  type: string;
  [key: string]: any;
}

interface AttackGraphProps {
  nodes: GraphNode[];
  relationships: GraphRelationship[];
  onNodeClick?: (node: GraphNode) => void;
  selectedNodeId?: string | null;
  highlightTypes?: string[];
  searchTerm?: string;
  width?: number;
  height?: number;
  graphRef?: React.RefObject<any>;
}

export default function AttackGraph({
  nodes,
  relationships,
  onNodeClick,
  selectedNodeId,
  highlightTypes,
  searchTerm,
  width,
  height,
  graphRef: externalRef,
}: AttackGraphProps) {
  const internalRef = useRef<any>(undefined);
  const graphRef = externalRef || internalRef;
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);

  const connectionCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const rel of relationships) {
      counts[rel.startNode] = (counts[rel.startNode] || 0) + 1;
      counts[rel.endNode] = (counts[rel.endNode] || 0) + 1;
    }
    return counts;
  }, [relationships]);

  const connectedNodes = useMemo(() => {
    if (!hoveredNode) return new Set<string>();
    const connected = new Set<string>([hoveredNode]);
    for (const rel of relationships) {
      if (rel.startNode === hoveredNode) connected.add(rel.endNode);
      if (rel.endNode === hoveredNode) connected.add(rel.startNode);
    }
    return connected;
  }, [hoveredNode, relationships]);

  const graphData = useMemo(() => {
    const filteredNodes = highlightTypes?.length
      ? nodes.filter((n) => highlightTypes.includes(n.labels[0]))
      : nodes;

    const nodeIds = new Set(filteredNodes.map((n) => n.id));

    const forceNodes: ForceNode[] = filteredNodes.map((node) => ({
      id: node.id,
      name:
        node.properties.name ||
        node.properties.domain ||
        node.properties.url ||
        node.id,
      type: node.labels[0] || 'Unknown',
      ...node.properties,
    }));

    const forceLinks: ForceLink[] = relationships
      .filter((rel) => nodeIds.has(rel.startNode) && nodeIds.has(rel.endNode))
      .map((rel) => ({
        source: rel.startNode,
        target: rel.endNode,
        type: rel.type,
        ...rel.properties,
      }));

    return { nodes: forceNodes, links: forceLinks };
  }, [nodes, relationships, highlightTypes]);

  const searchMatchNodes = useMemo(() => {
    if (!searchTerm) return new Set<string>();
    const term = searchTerm.toLowerCase();
    return new Set(
      graphData.nodes
        .filter((n) => n.name.toLowerCase().includes(term))
        .map((n) => n.id)
    );
  }, [searchTerm, graphData.nodes]);

  useEffect(() => {
    if (graphRef.current) {
      graphRef.current.d3ReheatSimulation();
      setTimeout(() => {
        graphRef.current?.zoomToFit(400, 50);
      }, 500);
    }
  }, [graphData]);

  const handleNodeClick = useCallback(
    (node: any) => {
      if (!onNodeClick) return;
      const original = nodes.find((n) => n.id === node.id);
      if (original) onNodeClick(original);
    },
    [onNodeClick, nodes]
  );

  const handleNodeHover = useCallback((node: any) => {
    setHoveredNode(node?.id ?? null);
  }, []);

  const nodeCanvasObject = useCallback(
    (node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const { id, name, type, x, y } = node;
      if (x == null || y == null) return;

      const count = connectionCounts[id] || 0;
      const radius = Math.min(Math.max(MIN_NODE_RADIUS, MIN_NODE_RADIUS + count * RADIUS_SCALE_FACTOR), MAX_NODE_RADIUS);
      const color = NODE_COLORS[type] || '#9CA3AF';

      const isSelected = selectedNodeId === id;
      const isHovered = hoveredNode === id;
      const isConnected = hoveredNode != null && connectedNodes.has(id);
      const isSearchMatch = searchMatchNodes.has(id);
      const isDimmed = hoveredNode != null && !isConnected;

      // Glow effect for Vulnerability/CVE nodes
      if (GLOW_TYPES.has(type)) {
        ctx.save();
        ctx.shadowColor = color;
        ctx.shadowBlur = 15;
        ctx.beginPath();
        ctx.arc(x, y, radius, 0, 2 * Math.PI);
        ctx.fillStyle = color;
        ctx.fill();
        ctx.restore();
      }

      // Node circle
      ctx.beginPath();
      ctx.arc(x, y, radius, 0, 2 * Math.PI);
      ctx.fillStyle = isDimmed ? `${color}40` : color;
      ctx.fill();

      // Selection / hover ring
      if (isSelected || isHovered) {
        ctx.strokeStyle = isSelected ? '#FFFFFF' : '#E5E7EB';
        ctx.lineWidth = 2 / globalScale;
        ctx.stroke();
      }

      // Search match ring
      if (isSearchMatch) {
        ctx.strokeStyle = '#FBBF24';
        ctx.lineWidth = 2.5 / globalScale;
        ctx.stroke();
      }

      // Label
      const fontSize = Math.max(10 / globalScale, 1.5);
      ctx.font = `${fontSize}px Sans-Serif`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';
      ctx.fillStyle = isDimmed ? '#9CA3AF80' : '#E5E7EB';
      const label =
        name.length > MAX_LABEL_LENGTH ? `${name.substring(0, MAX_LABEL_LENGTH - 2)}…` : name;
      ctx.fillText(label, x, y + radius + 2);
    },
    [connectionCounts, selectedNodeId, hoveredNode, connectedNodes, searchMatchNodes]
  );

  const nodePointerAreaPaint = useCallback(
    (node: any, paintColor: string, ctx: CanvasRenderingContext2D) => {
      const { id, x, y } = node;
      if (x == null || y == null) return;
      const count = connectionCounts[id] || 0;
      const radius = Math.min(Math.max(MIN_NODE_RADIUS, MIN_NODE_RADIUS + count * RADIUS_SCALE_FACTOR), MAX_NODE_RADIUS);
      ctx.beginPath();
      ctx.arc(x, y, radius + 2, 0, 2 * Math.PI);
      ctx.fillStyle = paintColor;
      ctx.fill();
    },
    [connectionCounts]
  );

  const linkColor = useCallback(
    (link: any) => {
      const color = LINK_COLORS[link.type] || DEFAULT_LINK_COLOR;
      if (hoveredNode == null) return color;
      const sourceId =
        typeof link.source === 'object' ? link.source.id : link.source;
      const targetId =
        typeof link.target === 'object' ? link.target.id : link.target;
      if (connectedNodes.has(sourceId) && connectedNodes.has(targetId))
        return color;
      return `${color}20`;
    },
    [hoveredNode, connectedNodes]
  );

  const linkWidth = useCallback(
    (link: any) => {
      if (hoveredNode == null) return 1;
      const sourceId =
        typeof link.source === 'object' ? link.source.id : link.source;
      const targetId =
        typeof link.target === 'object' ? link.target.id : link.target;
      if (connectedNodes.has(sourceId) && connectedNodes.has(targetId))
        return 2;
      return 0.5;
    },
    [hoveredNode, connectedNodes]
  );

  const nodeLabel = useCallback(
    (node: any) => {
      const type = node.type || 'Unknown';
      const name = node.name || node.id;
      return `<div style="background:#1F2937;color:#F9FAFB;padding:6px 10px;border-radius:6px;font-size:12px;max-width:280px;">
        <strong style="color:${NODE_COLORS[type] || '#9CA3AF'}">${type}</strong><br/>
        ${name}
      </div>`;
    },
    []
  );

  const isLargeGraph = graphData.nodes.length > 1000;

  return (
    <div style={{ width: width || '100%', height: height || '100%' }}>
      <ForceGraph2D
        ref={graphRef}
        graphData={graphData as any}
        nodeId="id"
        nodeLabel={nodeLabel}
        nodeCanvasObject={nodeCanvasObject}
        nodeCanvasObjectMode={() => 'replace' as const}
        nodePointerAreaPaint={nodePointerAreaPaint}
        linkColor={linkColor}
        linkWidth={linkWidth}
        linkLabel="type"
        linkDirectionalArrowLength={4}
        linkDirectionalArrowRelPos={1}
        onNodeClick={handleNodeClick}
        onNodeHover={handleNodeHover}
        d3AlphaDecay={isLargeGraph ? 0.05 : 0.02}
        d3VelocityDecay={isLargeGraph ? 0.4 : 0.3}
        cooldownTicks={isLargeGraph ? 50 : 100}
        enableNodeDrag={true}
        enableZoomInteraction={true}
        enablePanInteraction={true}
        width={width}
        height={height}
      />
    </div>
  );
}
