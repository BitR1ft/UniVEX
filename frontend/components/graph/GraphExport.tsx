'use client';

import { useCallback } from 'react';
import { ImageDown, FileJson, FileSpreadsheet, FileCode2, Link2 } from 'lucide-react';
import type { GraphNode, GraphRelationship } from '@/lib/api';
import { toast } from '@/store/toastStore';

interface GraphExportProps {
  graphRef: React.RefObject<any>;
  nodes: GraphNode[];
  relationships: GraphRelationship[];
}

export default function GraphExport({ graphRef, nodes, relationships }: GraphExportProps) {
  const exportPNG = useCallback(() => {
    const fg = graphRef.current;
    if (!fg) return;
    // Try the ForceGraph2D canvas accessor first, then query the DOM
    const canvas =
      (fg.canvas?.() as HTMLCanvasElement | undefined) ??
      document.querySelector<HTMLCanvasElement>('.force-graph-container canvas');
    if (!canvas) return;
    downloadDataURL(canvas.toDataURL('image/png'), 'attack-graph.png');
  }, [graphRef]);

  const exportJSON = useCallback(() => {
    const data = JSON.stringify({ nodes, relationships }, null, 2);
    downloadBlob(data, 'attack-graph.json', 'application/json');
  }, [nodes, relationships]);

  const exportCSV = useCallback(() => {
    if (nodes.length === 0) return;
    const allKeys = new Set<string>();
    allKeys.add('id');
    allKeys.add('labels');
    for (const node of nodes) {
      for (const key of Object.keys(node.properties)) {
        allKeys.add(key);
      }
    }
    const headers = Array.from(allKeys);
    const rows = nodes.map((node) => {
      return headers.map((h) => {
        if (h === 'id') return csvEscape(node.id);
        if (h === 'labels') return csvEscape(node.labels.join(';'));
        const val = node.properties[h];
        return val != null ? csvEscape(String(val)) : '';
      }).join(',');
    });
    const csv = [headers.join(','), ...rows].join('\n');
    downloadBlob(csv, 'attack-graph-nodes.csv', 'text/csv');
  }, [nodes]);

  const exportGEXF = useCallback(() => {
    const lines: string[] = [];
    lines.push('<?xml version="1.0" encoding="UTF-8"?>');
    lines.push('<gexf xmlns="http://gexf.net/1.2" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"');
    lines.push('  xsi:schemaLocation="http://gexf.net/1.2 http://gexf.net/1.2/gexf.xsd" version="1.2">');
    lines.push('  <meta>');
    lines.push(`    <creator>UniVex</creator>`);
    lines.push(`    <description>Attack Surface Graph</description>`);
    lines.push('  </meta>');
    lines.push('  <graph defaultedgetype="directed">');

    // Collect all node attribute keys
    const nodeAttrKeys = new Set<string>();
    for (const n of nodes) {
      Object.keys(n.properties).forEach((k) => nodeAttrKeys.add(k));
    }
    const nodeAttrList = Array.from(nodeAttrKeys);

    lines.push('    <attributes class="node">');
    nodeAttrList.forEach((k, i) => {
      lines.push(`      <attribute id="${i}" title="${xmlEscape(k)}" type="string"/>`);
    });
    lines.push('    </attributes>');

    // Nodes
    lines.push('    <nodes>');
    for (const n of nodes) {
      const label = xmlEscape(n.labels[0] ?? n.id);
      lines.push(`      <node id="${xmlEscape(n.id)}" label="${label}">`);
      if (nodeAttrList.length > 0) {
        lines.push('        <attvalues>');
        nodeAttrList.forEach((k, i) => {
          const v = n.properties[k];
          if (v != null) {
            lines.push(`          <attvalue for="${i}" value="${xmlEscape(String(v))}"/>`);
          }
        });
        lines.push('        </attvalues>');
      }
      lines.push('      </node>');
    }
    lines.push('    </nodes>');

    // Edges
    lines.push('    <edges>');
    relationships.forEach((r, idx) => {
      lines.push(
        `      <edge id="${idx}" source="${xmlEscape(r.startNode)}" target="${xmlEscape(r.endNode)}" label="${xmlEscape(r.type)}"/>`
      );
    });
    lines.push('    </edges>');

    lines.push('  </graph>');
    lines.push('</gexf>');

    downloadBlob(lines.join('\n'), 'attack-graph.gexf', 'application/gexf+xml');
  }, [nodes, relationships]);

  const copyLink = useCallback(() => {
    if (typeof window !== 'undefined') {
      navigator.clipboard
        .writeText(window.location.href)
        .then(() => {
          toast.success('Link copied', 'Graph URL copied to clipboard');
        })
        .catch(() => {
          toast.error('Copy failed', 'Could not copy link to clipboard');
        });
    }
  }, []);

  return (
    <div className="flex items-center gap-1">
      <button
        onClick={exportPNG}
        title="Export as PNG"
        className="p-1.5 text-gray-400 hover:text-white hover:bg-gray-700 rounded transition-colors"
      >
        <ImageDown className="h-4 w-4" />
      </button>
      <button
        onClick={exportJSON}
        title="Export as JSON"
        className="p-1.5 text-gray-400 hover:text-white hover:bg-gray-700 rounded transition-colors"
      >
        <FileJson className="h-4 w-4" />
      </button>
      <button
        onClick={exportCSV}
        title="Export as CSV"
        className="p-1.5 text-gray-400 hover:text-white hover:bg-gray-700 rounded transition-colors"
      >
        <FileSpreadsheet className="h-4 w-4" />
      </button>
      <button
        onClick={exportGEXF}
        title="Export as GEXF"
        className="p-1.5 text-gray-400 hover:text-white hover:bg-gray-700 rounded transition-colors"
      >
        <FileCode2 className="h-4 w-4" />
      </button>
      <button
        onClick={copyLink}
        title="Copy graph link"
        className="p-1.5 text-gray-400 hover:text-white hover:bg-gray-700 rounded transition-colors"
      >
        <Link2 className="h-4 w-4" />
      </button>
    </div>
  );
}

function csvEscape(value: string): string {
  if (value.includes(',') || value.includes('"') || value.includes('\n')) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

function xmlEscape(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function downloadDataURL(dataURL: string, filename: string) {
  const a = document.createElement('a');
  a.href = dataURL;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

function downloadBlob(content: string, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

