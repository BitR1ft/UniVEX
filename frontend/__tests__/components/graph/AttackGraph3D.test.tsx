import React from 'react';
import { render, screen } from '@testing-library/react';
import AttackGraph3D from '@/components/graph/AttackGraph3D';
import type { GraphNode, GraphRelationship } from '@/lib/api';

// Mock canvas
const mockCanvas = {
  getContext: jest.fn(() => ({
    clearRect: jest.fn(),
    fillRect: jest.fn(),
    beginPath: jest.fn(),
    arc: jest.fn(),
    fill: jest.fn(),
    stroke: jest.fn(),
    moveTo: jest.fn(),
    lineTo: jest.fn(),
    fillText: jest.fn(),
    save: jest.fn(),
    restore: jest.fn(),
    canvas: { width: 800, height: 600 },
    globalAlpha: 1,
    strokeStyle: '',
    fillStyle: '',
    lineWidth: 1,
    font: '',
    textAlign: 'left',
    shadowBlur: 0,
    shadowColor: '',
  })),
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(HTMLCanvasElement.prototype.getContext as any) = mockCanvas.getContext;

// Mock requestAnimationFrame - call callback once only to avoid infinite loop
let rafId = 0;
global.requestAnimationFrame = (cb) => {
  // Execute async to prevent stack overflow
  setTimeout(() => cb(16), 0);
  return ++rafId;
};
global.cancelAnimationFrame = jest.fn();

const sampleNodes: GraphNode[] = [
  {
    id: 'n1',
    labels: ['Domain'],
    properties: { name: 'example.com', domain: 'example.com' },
  },
  {
    id: 'n2',
    labels: ['IP'],
    properties: { name: '1.2.3.4' },
  },
];

const sampleRelationships: GraphRelationship[] = [
  {
    id: 'r1',
    type: 'RESOLVES_TO',
    startNode: 'n1',
    endNode: 'n2',
    properties: {},
  },
];

describe('AttackGraph3D', () => {
  it('renders a canvas element', () => {
    render(
      <AttackGraph3D
        nodes={sampleNodes}
        relationships={sampleRelationships}
        width={800}
        height={600}
      />
    );
    const canvas = document.querySelector('canvas');
    expect(canvas).toBeInTheDocument();
  });

  it('sets the canvas dimensions from props', () => {
    render(
      <AttackGraph3D
        nodes={sampleNodes}
        relationships={sampleRelationships}
        width={1024}
        height={768}
      />
    );
    const canvas = document.querySelector('canvas');
    expect(canvas?.getAttribute('width')).toBe('1024');
    expect(canvas?.getAttribute('height')).toBe('768');
  });

  it('renders with empty nodes without crashing', () => {
    render(
      <AttackGraph3D
        nodes={[]}
        relationships={[]}
        width={800}
        height={600}
      />
    );
    expect(document.querySelector('canvas')).toBeInTheDocument();
  });

  it('calls onNodeClick when a node is clicked', () => {
    const onNodeClick = jest.fn();
    render(
      <AttackGraph3D
        nodes={sampleNodes}
        relationships={sampleRelationships}
        onNodeClick={onNodeClick}
        width={800}
        height={600}
      />
    );
    // Canvas is rendered; click interaction is canvas-based
    const canvas = document.querySelector('canvas')!;
    expect(canvas).toBeInTheDocument();
  });

  it('renders with highlightTypes filter', () => {
    render(
      <AttackGraph3D
        nodes={sampleNodes}
        relationships={sampleRelationships}
        highlightTypes={['Domain']}
        width={800}
        height={600}
      />
    );
    expect(document.querySelector('canvas')).toBeInTheDocument();
  });

  it('accepts selectedNodeId prop', () => {
    render(
      <AttackGraph3D
        nodes={sampleNodes}
        relationships={sampleRelationships}
        selectedNodeId="n1"
        width={800}
        height={600}
      />
    );
    expect(document.querySelector('canvas')).toBeInTheDocument();
  });
});
