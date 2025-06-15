"use client";

import { motion } from "framer-motion";
import {
  ZoomIn,
  ZoomOut,
  Maximize2,
  Minimize2,
  Download,
  Map,
  LayoutGrid,
  RotateCcw,
  Route,
} from "lucide-react";
import { NODE_COLORS } from "./AttackGraph";

export type GraphLayout = "force" | "sphere" | "hierarchical";

interface GraphControlsProps {
  nodeTypes: string[];
  nodeStats?: Record<string, number>;
  activeLayout: GraphLayout;
  onLayoutChange: (layout: GraphLayout) => void;
  onZoomIn: () => void;
  onZoomOut: () => void;
  onResetView: () => void;
  onExportPNG: () => void;
  onExportSVG: () => void;
  onToggleFullscreen: () => void;
  isFullscreen: boolean;
  totalNodes: number;
  totalEdges: number;
  showAttackPaths?: boolean;
  onToggleAttackPaths?: () => void;
}

const LAYOUT_OPTIONS: { value: GraphLayout; label: string; icon: React.ReactNode }[] = [
  { value: "force", label: "Force", icon: <Map className="h-3.5 w-3.5" /> },
  { value: "sphere", label: "Sphere", icon: <Route className="h-3.5 w-3.5" /> },
  { value: "hierarchical", label: "Tree", icon: <LayoutGrid className="h-3.5 w-3.5" /> },
];

export default function GraphControls({
  nodeTypes,
  nodeStats,
  activeLayout,
  onLayoutChange,
  onZoomIn,
  onZoomOut,
  onResetView,
  onExportPNG,
  onExportSVG,
  onToggleFullscreen,
  isFullscreen,
  totalNodes,
  totalEdges,
  showAttackPaths = false,
  onToggleAttackPaths,
}: GraphControlsProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: -8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2 }}
      className="flex items-center gap-3 px-3 py-2 bg-gray-900 border-b border-gray-700 flex-wrap"
    >
      {/* Node Type Legend */}
      <div className="flex items-center gap-2 flex-wrap">
        {nodeTypes.map((type) => {
          const color = NODE_COLORS[type] ?? "#9CA3AF";
          const count = nodeStats?.[type];
          return (
            <div key={type} className="flex items-center gap-1.5" title={type}>
              <span
                className="w-2.5 h-2.5 rounded-full flex-shrink-0"
                style={{ backgroundColor: color }}
              />
              <span className="text-xs text-gray-400 hidden sm:inline">{type}</span>
              {count != null && (
                <span className="text-xs text-gray-600 tabular-nums hidden sm:inline">
                  {count}
                </span>
              )}
            </div>
          );
        })}
      </div>

      <div className="h-4 w-px bg-gray-700 hidden sm:block" />

      {/* Layout Toggle */}
      <div className="flex items-center gap-0.5 bg-gray-800 rounded-md p-0.5 border border-gray-700">
        {LAYOUT_OPTIONS.map(({ value, label, icon }) => (
          <button
            key={value}
            onClick={() => onLayoutChange(value)}
            title={`${label} layout`}
            className={`flex items-center gap-1.5 px-2 py-1 rounded text-xs font-medium transition-colors ${
              activeLayout === value
                ? "bg-cyan-600 text-white"
                : "text-gray-400 hover:text-white hover:bg-gray-700"
            }`}
          >
            {icon}
            <span className="hidden md:inline">{label}</span>
          </button>
        ))}
      </div>

      <div className="h-4 w-px bg-gray-700" />

      {/* Zoom Controls */}
      <div className="flex items-center gap-0.5">
        <button
          onClick={onZoomIn}
          title="Zoom in"
          className="p-1.5 text-gray-400 hover:text-white hover:bg-gray-700 rounded transition-colors"
        >
          <ZoomIn className="h-4 w-4" />
        </button>
        <button
          onClick={onZoomOut}
          title="Zoom out"
          className="p-1.5 text-gray-400 hover:text-white hover:bg-gray-700 rounded transition-colors"
        >
          <ZoomOut className="h-4 w-4" />
        </button>
        <button
          onClick={onResetView}
          title="Reset view"
          className="p-1.5 text-gray-400 hover:text-white hover:bg-gray-700 rounded transition-colors"
        >
          <RotateCcw className="h-4 w-4" />
        </button>
      </div>

      <div className="h-4 w-px bg-gray-700" />

      {/* Attack Path Toggle */}
      {onToggleAttackPaths && (
        <>
          <button
            onClick={onToggleAttackPaths}
            title="Highlight attack paths"
            className={`flex items-center gap-1.5 px-2 py-1.5 rounded text-xs font-medium border transition-colors ${
              showAttackPaths
                ? "bg-red-900/40 border-red-600 text-red-400"
                : "bg-gray-800 border-gray-700 text-gray-400 hover:text-white hover:border-gray-500"
            }`}
          >
            <Route className="h-3.5 w-3.5" />
            <span className="hidden md:inline">Attack Paths</span>
          </button>
          <div className="h-4 w-px bg-gray-700" />
        </>
      )}

      {/* Export Buttons */}
      <div className="flex items-center gap-0.5">
        <button
          onClick={onExportPNG}
          title="Export as PNG"
          className="flex items-center gap-1.5 px-2 py-1.5 rounded text-xs font-medium bg-gray-800 border border-gray-700 text-gray-400 hover:text-white hover:border-gray-500 transition-colors"
        >
          <Download className="h-3.5 w-3.5" />
          <span>PNG</span>
        </button>
        <button
          onClick={onExportSVG}
          title="Export as SVG"
          className="flex items-center gap-1.5 px-2 py-1.5 rounded text-xs font-medium bg-gray-800 border border-gray-700 text-gray-400 hover:text-white hover:border-gray-500 transition-colors"
        >
          <Download className="h-3.5 w-3.5" />
          <span>SVG</span>
        </button>
      </div>

      <div className="h-4 w-px bg-gray-700" />

      {/* Fullscreen Toggle */}
      <button
        onClick={onToggleFullscreen}
        title={isFullscreen ? "Exit fullscreen" : "Enter fullscreen"}
        className="p-1.5 text-gray-400 hover:text-white hover:bg-gray-700 rounded transition-colors"
      >
        {isFullscreen ? (
          <Minimize2 className="h-4 w-4" />
        ) : (
          <Maximize2 className="h-4 w-4" />
        )}
      </button>

      {/* Graph Stats */}
      <div className="ml-auto flex items-center gap-3 text-xs text-gray-500 tabular-nums">
        <span>
          <span className="text-cyan-400 font-semibold">{totalNodes}</span> nodes
        </span>
        <span>
          <span className="text-cyan-400 font-semibold">{totalEdges}</span> edges
        </span>
      </div>
    </motion.div>
  );
}
