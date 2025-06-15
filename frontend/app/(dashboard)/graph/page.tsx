'use client';

import { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { Network, Maximize, RotateCcw, Loader2, AlertCircle, Layers } from 'lucide-react';
import Link from 'next/link';
import type { GraphNode } from '@/lib/api';
import { useAttackSurface, useGraphStats } from '@/hooks/useGraph';
import { useProjects, useProject } from '@/hooks/useProjects';
import AttackGraph from '@/components/graph/AttackGraph';
import AttackGraph3D from '@/components/graph/AttackGraph3D';
import NodeInspector from '@/components/graph/NodeInspector';
import GraphFilterPanel from '@/components/graph/GraphFilterPanel';
import GraphExport from '@/components/graph/GraphExport';

const FILTER_PANEL_WIDTH = 224; // w-56 = 14rem = 224px
const INSPECTOR_WIDTH = 320;   // w-80 = 20rem = 320px
const TOOLBAR_HEIGHT = 48;

export default function GraphExplorerPage() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const projectId = searchParams.get('project_id');

  // Graph ref for zoom controls and export
  const graphRef = useRef<any>(undefined);

  // Container dimensions
  const containerRef = useRef<HTMLDivElement>(null);
  const [containerSize, setContainerSize] = useState({ width: 800, height: 600 });

  // Node inspector state
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  // Filter state
  const [selectedTypes, setSelectedTypes] = useState<string[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [typesInitialized, setTypesInitialized] = useState(false);

  // 2D / 3D toggle
  const [is3D, setIs3D] = useState(false);
  const { data: surfaceData, isLoading: surfaceLoading, error: surfaceError } = useAttackSurface(projectId || '');
  const { data: statsData } = useGraphStats(projectId || '');
  const { data: projectData } = useProject(projectId || '');

  const nodes = surfaceData?.nodes ?? [];
  const relationships = surfaceData?.relationships ?? [];

  // Derive available node types
  const nodeTypes = useMemo(() => {
    const types = new Set<string>();
    for (const n of nodes) {
      if (n.labels[0]) types.add(n.labels[0]);
    }
    return Array.from(types).sort();
  }, [nodes]);

  // Initialize selected types when data loads
  useEffect(() => {
    if (nodeTypes.length > 0 && !typesInitialized) {
      setSelectedTypes(nodeTypes);
      setTypesInitialized(true);
    }
  }, [nodeTypes, typesInitialized]);

  // Reset types initialization when project changes
  useEffect(() => {
    setTypesInitialized(false);
    setSelectedNode(null);
    setSearchTerm('');
  }, [projectId]);

  // Resize observer for graph container
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;

    const observer = new ResizeObserver((entries) => {
      for (const entry of entries) {
        setContainerSize({
          width: entry.contentRect.width,
          height: entry.contentRect.height,
        });
      }
    });
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  // Computed graph dimensions
  const graphWidth = useMemo(() => {
    let w = containerSize.width - FILTER_PANEL_WIDTH;
    if (selectedNode) w -= INSPECTOR_WIDTH;
    return Math.max(w, 200);
  }, [containerSize.width, selectedNode]);

  const graphHeight = useMemo(() => {
    return Math.max(containerSize.height - TOOLBAR_HEIGHT, 200);
  }, [containerSize.height]);

  // Handlers
  const handleNodeClick = useCallback((node: GraphNode) => {
    setSelectedNode(node);
  }, []);

  const handleNavigate = useCallback(
    (nodeId: string) => {
      const target = nodes.find((n) => n.id === nodeId);
      if (target) {
        setSelectedNode(target);
        // Center graph on node
        if (graphRef.current) {
          const forceNode = graphRef.current.graphData?.().nodes?.find((n: any) => n.id === nodeId);
          if (forceNode) {
            graphRef.current.centerAt(forceNode.x, forceNode.y, 400);
            graphRef.current.zoom(2, 400);
          }
        }
      }
    },
    [nodes]
  );

  const handleZoomToFit = useCallback(() => {
    graphRef.current?.zoomToFit(400, 50);
  }, []);

  const handleResetView = useCallback(() => {
    graphRef.current?.centerAt(0, 0, 400);
    graphRef.current?.zoom(1, 400);
  }, []);

  const handleCloseInspector = useCallback(() => {
    setSelectedNode(null);
  }, []);

  const stats = statsData?.node_counts;
  const totalNodes = nodes.length;
  const totalLinks = relationships.length;

  // Project selector view
  if (!projectId) {
    return <ProjectSelector />;
  }

  // Loading state
  if (surfaceLoading) {
    return (
      <div className="flex items-center justify-center h-[calc(100vh-4rem)]">
        <div className="text-center">
          <Loader2 className="h-10 w-10 text-blue-500 animate-spin mx-auto mb-3" />
          <p className="text-gray-400 text-sm">Loading attack surface graph…</p>
        </div>
      </div>
    );
  }

  // Error state
  if (surfaceError) {
    return (
      <div className="flex items-center justify-center h-[calc(100vh-4rem)]">
        <div className="text-center max-w-md">
          <AlertCircle className="h-10 w-10 text-red-500 mx-auto mb-3" />
          <h3 className="text-lg font-semibold text-white mb-2">Failed to load graph</h3>
          <p className="text-gray-400 text-sm mb-4">
            {(surfaceError as Error).message || 'An unexpected error occurred'}
          </p>
          <Link
            href={`/projects/${projectId}`}
            className="inline-block px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white text-sm rounded transition-colors"
          >
            ← Back to Project
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div ref={containerRef} className="h-[calc(100vh-4rem)] flex flex-col bg-gray-900 -m-6 -mt-6">
      {/* Toolbar */}
      <div className="flex items-center justify-between px-4 h-12 border-b border-gray-700 bg-gray-800 flex-shrink-0">
        <div className="flex items-center gap-3">
          <Network className="h-4 w-4 text-blue-400" />
          <span className="text-sm font-medium text-white truncate max-w-[200px]">
            {projectData?.name || 'Graph Explorer'}
          </span>
          <span className="text-xs text-gray-500">
            {totalNodes} nodes · {totalLinks} links
          </span>
        </div>
        <div className="flex items-center gap-2">
          <GraphExport graphRef={graphRef} nodes={nodes} relationships={relationships} />
          <div className="w-px h-5 bg-gray-700" />
          {/* 2D / 3D toggle */}
          <button
            onClick={() => setIs3D((v) => !v)}
            title={is3D ? 'Switch to 2D view' : 'Switch to 3D view'}
            className={`flex items-center gap-1 px-2 py-1 rounded text-xs font-medium transition-colors ${
              is3D
                ? 'bg-blue-600 text-white'
                : 'text-gray-400 hover:text-white hover:bg-gray-700'
            }`}
            aria-pressed={is3D}
            aria-label={is3D ? 'Switch to 2D view' : 'Switch to 3D view'}
          >
            <Layers className="h-4 w-4" />
            {is3D ? '3D' : '2D'}
          </button>
          <div className="w-px h-5 bg-gray-700" />
          <button
            onClick={handleZoomToFit}
            title="Zoom to fit"
            className="p-1.5 text-gray-400 hover:text-white hover:bg-gray-700 rounded transition-colors"
          >
            <Maximize className="h-4 w-4" />
          </button>
          <button
            onClick={handleResetView}
            title="Reset view"
            className="p-1.5 text-gray-400 hover:text-white hover:bg-gray-700 rounded transition-colors"
          >
            <RotateCcw className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Main content */}
      <div className="flex flex-1 min-h-0">
        {/* Left filter panel */}
        <GraphFilterPanel
          nodeTypes={nodeTypes}
          selectedTypes={selectedTypes}
          onTypesChange={setSelectedTypes}
          searchTerm={searchTerm}
          onSearchChange={setSearchTerm}
          stats={stats}
        />

        {/* Center graph */}
        <div className="flex-1 min-w-0 bg-gray-900">
          {is3D ? (
            <AttackGraph3D
              nodes={nodes}
              relationships={relationships}
              onNodeClick={handleNodeClick}
              selectedNodeId={selectedNode?.id ?? null}
              highlightTypes={selectedTypes.length === nodeTypes.length ? undefined : selectedTypes}
              searchTerm={searchTerm}
              width={graphWidth}
              height={graphHeight}
            />
          ) : (
            <AttackGraph
              nodes={nodes}
              relationships={relationships}
              onNodeClick={handleNodeClick}
              selectedNodeId={selectedNode?.id ?? null}
              highlightTypes={selectedTypes.length === nodeTypes.length ? undefined : selectedTypes}
              searchTerm={searchTerm}
              width={graphWidth}
              height={graphHeight}
              graphRef={graphRef}
            />
          )}
        </div>

        {/* Right inspector panel */}
        {selectedNode && (
          <NodeInspector
            node={selectedNode}
            relationships={relationships}
            onClose={handleCloseInspector}
            onNavigate={handleNavigate}
          />
        )}
      </div>
    </div>
  );
}

function ProjectSelector() {
  const { data: projects, isLoading } = useProjects();
  const router = useRouter();

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-[calc(100vh-4rem)]">
        <Loader2 className="h-8 w-8 text-blue-500 animate-spin" />
      </div>
    );
  }

  const projectList = Array.isArray(projects) ? projects : [];

  return (
    <div className="max-w-2xl mx-auto py-12">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">Attack Surface Graph Explorer</h1>
        <p className="text-gray-400">Select a project to visualize its attack surface</p>
      </div>

      {projectList.length === 0 ? (
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-12 text-center">
          <Network className="h-12 w-12 text-gray-600 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-white mb-2">No Projects</h3>
          <p className="text-gray-400 mb-6">Create a project first to view its graph</p>
          <Link
            href="/projects"
            className="inline-block px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg transition-colors"
          >
            Go to Projects
          </Link>
        </div>
      ) : (
        <div className="space-y-2">
          {projectList.map((project: any) => (
            <button
              key={project.id}
              onClick={() => router.push(`/graph?project_id=${project.id}`)}
              className="w-full flex items-center gap-4 p-4 bg-gray-800 border border-gray-700 rounded-lg hover:border-blue-500 hover:bg-gray-750 transition-colors text-left"
            >
              <Network className="h-5 w-5 text-blue-400 flex-shrink-0" />
              <div className="min-w-0 flex-1">
                <p className="text-white font-medium truncate">{project.name}</p>
                {project.target && (
                  <p className="text-gray-500 text-sm truncate">{project.target}</p>
                )}
              </div>
              <span className="text-xs text-gray-500 flex-shrink-0">{project.status}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
