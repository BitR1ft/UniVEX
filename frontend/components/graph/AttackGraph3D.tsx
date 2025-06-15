'use client';

import { useRef, useMemo, useState, useEffect, useCallback } from 'react';
import type { GraphNode, GraphRelationship } from '@/lib/api';
import { NODE_COLORS } from './AttackGraph';

interface Node3D {
  id: string;
  name: string;
  type: string;
  x: number;
  y: number;
  z: number;
  vx: number;
  vy: number;
  vz: number;
  [key: string]: any;
}

interface Link3D {
  source: string;
  target: string;
  type: string;
}

interface AttackGraph3DProps {
  nodes: GraphNode[];
  relationships: GraphRelationship[];
  onNodeClick?: (node: GraphNode) => void;
  selectedNodeId?: string | null;
  highlightTypes?: string[];
  searchTerm?: string;
  width?: number;
  height?: number;
}

const MIN_R = 6;
const MAX_R = 14;

function sphereLayout(count: number): { x: number; y: number; z: number }[] {
  // Fibonacci sphere distribution for initial positions
  const positions: { x: number; y: number; z: number }[] = [];
  const phi = Math.PI * (3 - Math.sqrt(5));
  const radius = Math.min(300, 80 + count * 1.5);
  for (let i = 0; i < count; i++) {
    const y = 1 - (i / Math.max(count - 1, 1)) * 2;
    const r = Math.sqrt(1 - y * y);
    const theta = phi * i;
    positions.push({
      x: Math.cos(theta) * r * radius,
      y: y * radius,
      z: Math.sin(theta) * r * radius,
    });
  }
  return positions;
}

export default function AttackGraph3D({
  nodes,
  relationships,
  onNodeClick,
  selectedNodeId,
  highlightTypes,
  searchTerm,
  width = 800,
  height = 600,
}: AttackGraph3DProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animRef = useRef<number>(0);
  const rotationRef = useRef({ x: 0.3, y: 0, z: 0 });
  const isDraggingRef = useRef(false);
  const lastMouseRef = useRef({ x: 0, y: 0 });
  const autoRotateRef = useRef(true);
  const [hoveredId, setHoveredId] = useState<string | null>(null);
  const hoveredIdRef = useRef<string | null>(null);

  // Build 3D node/link data
  const { nodes3d, links3d } = useMemo(() => {
    const filtered = highlightTypes?.length
      ? nodes.filter((n) => highlightTypes.includes(n.labels[0]))
      : nodes;

    const positions = sphereLayout(filtered.length);
    const nodes3dList: Node3D[] = filtered.map((n, i) => ({
      id: n.id,
      name: n.properties.name || n.properties.domain || n.properties.url || n.id,
      type: n.labels[0] || 'Unknown',
      ...n.properties,
      x: positions[i].x,
      y: positions[i].y,
      z: positions[i].z,
      vx: 0,
      vy: 0,
      vz: 0,
    }));

    const nodeIds = new Set(filtered.map((n) => n.id));
    const links3dList: Link3D[] = relationships
      .filter((r) => nodeIds.has(r.startNode) && nodeIds.has(r.endNode))
      .map((r) => ({ source: r.startNode, target: r.endNode, type: r.type }));

    return { nodes3d: nodes3dList, links3d: links3dList };
  }, [nodes, relationships, highlightTypes]);

  const nodes3dRef = useRef<Node3D[]>(nodes3d);
  nodes3dRef.current = nodes3d;

  const searchMatches = useMemo(() => {
    if (!searchTerm) return new Set<string>();
    const t = searchTerm.toLowerCase();
    return new Set(nodes3d.filter((n) => n.name.toLowerCase().includes(t)).map((n) => n.id));
  }, [searchTerm, nodes3d]);

  // Project 3D -> 2D with perspective
  const project = useCallback(
    (x: number, y: number, z: number, rx: number, ry: number) => {
      // Rotate around Y axis
      const cosY = Math.cos(ry);
      const sinY = Math.sin(ry);
      const x1 = x * cosY + z * sinY;
      const z1 = -x * sinY + z * cosY;

      // Rotate around X axis
      const cosX = Math.cos(rx);
      const sinX = Math.sin(rx);
      const y2 = y * cosX - z1 * sinX;
      const z2 = y * sinX + z1 * cosX;

      // Perspective divide
      const fov = 600;
      const perspective = fov / (fov + z2 + 400);
      return {
        sx: x1 * perspective + width / 2,
        sy: y2 * perspective + height / 2,
        perspective,
        z: z2,
      };
    },
    [width, height]
  );

  // Main draw loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let lastTime = 0;

    const draw = (time: number) => {
      const dt = Math.min((time - lastTime) / 1000, 0.05);
      lastTime = time;

      if (autoRotateRef.current && !isDraggingRef.current) {
        rotationRef.current.y += 0.003;
      }

      const { x: rx, y: ry } = rotationRef.current;

      ctx.clearRect(0, 0, width, height);

      // Background
      ctx.fillStyle = '#111827';
      ctx.fillRect(0, 0, width, height);

      const ns = nodes3dRef.current;
      if (!ns.length) {
        ctx.fillStyle = '#6B7280';
        ctx.font = '14px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('No nodes to display', width / 2, height / 2);
        animRef.current = requestAnimationFrame(draw);
        return;
      }

      // Project all nodes
      const projected = ns.map((n) => ({
        ...n,
        ...project(n.x, n.y, n.z, rx, ry),
      }));

      // Sort back-to-front
      projected.sort((a, b) => a.z - b.z);

      const nodeMap = new Map(projected.map((n) => [n.id, n]));

      // Draw links
      ctx.save();
      for (const link of links3d) {
        const src = nodeMap.get(link.source);
        const tgt = nodeMap.get(link.target);
        if (!src || !tgt) continue;

        const alpha = hoveredIdRef.current
          ? src.id === hoveredIdRef.current || tgt.id === hoveredIdRef.current
            ? 0.8
            : 0.08
          : 0.25;

        ctx.beginPath();
        ctx.moveTo(src.sx, src.sy);
        ctx.lineTo(tgt.sx, tgt.sy);
        ctx.strokeStyle = `rgba(75, 85, 99, ${alpha})`;
        ctx.lineWidth = 1;
        ctx.stroke();
      }
      ctx.restore();

      // Draw nodes
      for (const n of projected) {
        const color = NODE_COLORS[n.type] || '#9CA3AF';
        const baseR = Math.min(MAX_R, MIN_R) * n.perspective;
        const r = Math.max(2, baseR);

        const isSelected = n.id === selectedNodeId;
        const isHovered = n.id === hoveredIdRef.current;
        const isSearch = searchMatches.has(n.id);
        const isDimmed = hoveredIdRef.current && !isHovered;

        const alpha = isDimmed ? 0.3 : 1;

        // Glow for vulnerability nodes
        if (n.type === 'Vulnerability' || n.type === 'CVE') {
          ctx.save();
          ctx.shadowColor = color;
          ctx.shadowBlur = 12 * n.perspective;
          ctx.beginPath();
          ctx.arc(n.sx, n.sy, r, 0, Math.PI * 2);
          ctx.fillStyle = color;
          ctx.globalAlpha = alpha;
          ctx.fill();
          ctx.restore();
        }

        ctx.globalAlpha = alpha;
        ctx.beginPath();
        ctx.arc(n.sx, n.sy, r, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.fill();
        ctx.globalAlpha = 1;

        if (isSelected) {
          ctx.strokeStyle = '#FFFFFF';
          ctx.lineWidth = 2;
          ctx.beginPath();
          ctx.arc(n.sx, n.sy, r + 2, 0, Math.PI * 2);
          ctx.stroke();
        }

        if (isSearch) {
          ctx.strokeStyle = '#FBBF24';
          ctx.lineWidth = 2;
          ctx.beginPath();
          ctx.arc(n.sx, n.sy, r + 3, 0, Math.PI * 2);
          ctx.stroke();
        }

        // Label
        if (n.perspective > 0.7 || isHovered || isSelected) {
          const fontSize = Math.max(9, 10 * n.perspective);
          ctx.font = `${fontSize}px sans-serif`;
          ctx.fillStyle = isDimmed ? '#6B7280' : '#E5E7EB';
          ctx.textAlign = 'center';
          ctx.textBaseline = 'top';
          const label = n.name.length > 18 ? n.name.slice(0, 16) + '…' : n.name;
          ctx.globalAlpha = isDimmed ? 0.3 : 1;
          ctx.fillText(label, n.sx, n.sy + r + 2);
          ctx.globalAlpha = 1;
        }
      }

      animRef.current = requestAnimationFrame(draw);
    };

    animRef.current = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(animRef.current);
  }, [nodes3d, links3d, project, selectedNodeId, searchMatches]);

  // Hit testing for clicks / hover
  const hitTest = useCallback(
    (mx: number, my: number): string | null => {
      const { x: rx, y: ry } = rotationRef.current;
      let best: string | null = null;
      let bestDist = 20;
      for (const n of nodes3dRef.current) {
        const { sx, sy, perspective } = project(n.x, n.y, n.z, rx, ry);
        const r = Math.max(2, Math.min(MAX_R, MIN_R) * perspective) + 4;
        const d = Math.hypot(mx - sx, my - sy);
        if (d < r && d < bestDist) {
          bestDist = d;
          best = n.id;
        }
      }
      return best;
    },
    [project]
  );

  const handleMouseDown = (e: React.MouseEvent) => {
    isDraggingRef.current = true;
    autoRotateRef.current = false;
    lastMouseRef.current = { x: e.clientX, y: e.clientY };
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (isDraggingRef.current) {
      const dx = e.clientX - lastMouseRef.current.x;
      const dy = e.clientY - lastMouseRef.current.y;
      rotationRef.current.y += dx * 0.005;
      rotationRef.current.x += dy * 0.005;
      lastMouseRef.current = { x: e.clientX, y: e.clientY };
    } else {
      const rect = canvasRef.current!.getBoundingClientRect();
      const id = hitTest(e.clientX - rect.left, e.clientY - rect.top);
      hoveredIdRef.current = id;
      setHoveredId(id);
    }
  };

  const handleMouseUp = () => {
    isDraggingRef.current = false;
  };

  const handleClick = (e: React.MouseEvent) => {
    if (!onNodeClick) return;
    const rect = canvasRef.current!.getBoundingClientRect();
    const id = hitTest(e.clientX - rect.left, e.clientY - rect.top);
    if (id) {
      const original = nodes.find((n) => n.id === id);
      if (original) onNodeClick(original);
    }
  };

  const handleMouseLeave = () => {
    isDraggingRef.current = false;
    hoveredIdRef.current = null;
    setHoveredId(null);
  };

  return (
    <div style={{ width, height, position: 'relative' }}>
      <canvas
        ref={canvasRef}
        width={width}
        height={height}
        style={{ display: 'block', cursor: hoveredId ? 'pointer' : 'grab' }}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseLeave}
        onClick={handleClick}
        aria-label="3D Attack Surface Graph – drag to rotate"
        role="img"
      />
      {/* Overlay hint */}
      <div
        style={{
          position: 'absolute',
          bottom: 8,
          left: '50%',
          transform: 'translateX(-50%)',
          pointerEvents: 'none',
        }}
        className="bg-gray-900/70 text-gray-400 text-xs px-2 py-1 rounded"
        aria-hidden="true"
      >
        Drag to rotate · Click node to inspect
      </div>
    </div>
  );
}
