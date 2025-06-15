import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import GraphExport from '@/components/graph/GraphExport';

// Mock URL.createObjectURL and revokeObjectURL
const mockCreateObjectURL = jest.fn(() => 'blob:mock-url') as jest.Mock;
const mockRevokeObjectURL = jest.fn();
global.URL.createObjectURL = mockCreateObjectURL as any;
global.URL.revokeObjectURL = mockRevokeObjectURL;

describe('GraphExport', () => {
  const mockNodes = [
    {
      id: 'node-1',
      labels: ['Domain'],
      properties: { name: 'example.com', ip: '1.2.3.4' },
    },
    {
      id: 'node-2',
      labels: ['IP'],
      properties: { address: '1.2.3.4' },
    },
  ];

  const mockRelationships = [
    {
      id: 'rel-1',
      type: 'RESOLVES_TO',
      startNode: 'node-1',
      endNode: 'node-2',
      properties: {},
    },
  ];

  const mockGraphRef = { current: null };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('renders five export buttons', () => {
    render(
      <GraphExport graphRef={mockGraphRef} nodes={mockNodes} relationships={mockRelationships} />
    );
    const buttons = screen.getAllByRole('button');
    expect(buttons).toHaveLength(5);
  });

  it('PNG button exists with correct title', () => {
    render(
      <GraphExport graphRef={mockGraphRef} nodes={mockNodes} relationships={mockRelationships} />
    );
    expect(screen.getByTitle('Export as PNG')).toBeInTheDocument();
  });

  it('JSON export creates correct data', () => {
    // Track anchor element creation without breaking DOM
    const mockClick = jest.fn();
    const originalCreateElement = document.createElement.bind(document);
    jest.spyOn(document, 'createElement').mockImplementation((tag: string) => {
      const el = originalCreateElement(tag);
      if (tag === 'a') {
        el.click = mockClick;
      }
      return el;
    });

    let capturedBlob: Blob | null = null;
    mockCreateObjectURL.mockImplementation((blob: any) => {
      capturedBlob = blob;
      return 'blob:mock-url';
    });

    render(
      <GraphExport graphRef={mockGraphRef} nodes={mockNodes} relationships={mockRelationships} />
    );

    const jsonButton = screen.getByTitle('Export as JSON');
    fireEvent.click(jsonButton);

    expect(mockCreateObjectURL).toHaveBeenCalled();
    expect(capturedBlob).not.toBeNull();
    expect(capturedBlob!.type).toBe('application/json');
    expect(mockClick).toHaveBeenCalled();

    (document.createElement as jest.Mock).mockRestore();
  });

  it('CSV export creates correct data', () => {
    const mockClick = jest.fn();
    const originalCreateElement = document.createElement.bind(document);
    jest.spyOn(document, 'createElement').mockImplementation((tag: string) => {
      const el = originalCreateElement(tag);
      if (tag === 'a') {
        el.click = mockClick;
      }
      return el;
    });

    let capturedBlob: Blob | null = null;
    mockCreateObjectURL.mockImplementation((blob: any) => {
      capturedBlob = blob;
      return 'blob:mock-url';
    });

    render(
      <GraphExport graphRef={mockGraphRef} nodes={mockNodes} relationships={mockRelationships} />
    );

    const csvButton = screen.getByTitle('Export as CSV');
    fireEvent.click(csvButton);

    expect(mockCreateObjectURL).toHaveBeenCalled();
    expect(capturedBlob).not.toBeNull();
    expect(capturedBlob!.type).toBe('text/csv');
    expect(mockClick).toHaveBeenCalled();

    (document.createElement as jest.Mock).mockRestore();
  });
});
