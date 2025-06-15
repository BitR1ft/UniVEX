import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { DataTable, Column } from '@/components/ui/DataTable';

jest.mock('framer-motion', () => ({
  motion: {
    tr: ({ children, ...props }: any) => <tr {...props}>{children}</tr>,
    div: ({ children, ...props }: any) => <div {...props}>{children}</div>,
  },
  AnimatePresence: ({ children }: any) => <>{children}</>,
}));

interface Row { id: string; name: string; status: string; score: number; }
const columns: Column<Row>[] = [
  { key: 'name', header: 'Name', sortable: true },
  { key: 'status', header: 'Status' },
  { key: 'score', header: 'Score', sortable: true, align: 'right' },
];
const data: Row[] = [
  { id: '1', name: 'Alpha', status: 'active', score: 90 },
  { id: '2', name: 'Beta',  status: 'idle',   score: 45 },
  { id: '3', name: 'Gamma', status: 'active', score: 70 },
];

describe('DataTable', () => {
  it('renders column headers', () => {
    render(<DataTable data={data} columns={columns} keyExtractor={(r) => r.id} />);
    expect(screen.getByText('Name')).toBeInTheDocument();
    expect(screen.getByText('Status')).toBeInTheDocument();
    expect(screen.getByText('Score')).toBeInTheDocument();
  });

  it('renders all rows', () => {
    render(<DataTable data={data} columns={columns} keyExtractor={(r) => r.id} />);
    expect(screen.getByText('Alpha')).toBeInTheDocument();
    expect(screen.getByText('Beta')).toBeInTheDocument();
    expect(screen.getByText('Gamma')).toBeInTheDocument();
  });

  it('shows empty message when data is empty', () => {
    render(<DataTable data={[]} columns={columns} keyExtractor={(r) => r.id} emptyMessage="No items" />);
    expect(screen.getByText('No items')).toBeInTheDocument();
  });

  it('shows search input when searchable', () => {
    render(<DataTable data={data} columns={columns} keyExtractor={(r) => r.id} searchable searchKeys={['name']} />);
    expect(screen.getByPlaceholderText('Search\u2026')).toBeInTheDocument();
  });

  it('filters rows on search', () => {
    render(<DataTable data={data} columns={columns} keyExtractor={(r) => r.id} searchable searchKeys={['name']} />);
    fireEvent.change(screen.getByPlaceholderText('Search\u2026'), { target: { value: 'Alpha' } });
    expect(screen.getByText('Alpha')).toBeInTheDocument();
    expect(screen.queryByText('Beta')).not.toBeInTheDocument();
  });

  it('clears search', () => {
    render(<DataTable data={data} columns={columns} keyExtractor={(r) => r.id} searchable searchKeys={['name']} />);
    fireEvent.change(screen.getByPlaceholderText('Search\u2026'), { target: { value: 'Alpha' } });
    fireEvent.click(screen.getByLabelText('Clear search'));
    expect(screen.getByText('Beta')).toBeInTheDocument();
  });

  it('calls onRowClick when row is clicked', () => {
    const onClick = jest.fn();
    render(<DataTable data={data} columns={columns} keyExtractor={(r) => r.id} onRowClick={onClick} />);
    fireEvent.click(screen.getByText('Alpha').closest('tr')!);
    expect(onClick).toHaveBeenCalledWith(data[0]);
  });

  it('shows loading skeletons', () => {
    const { container } = render(<DataTable data={[]} columns={columns} keyExtractor={(r) => r.id} isLoading />);
    expect(container.querySelectorAll('.animate-pulse').length).toBeGreaterThan(0);
  });

  it('sorts ascending on column header click', () => {
    render(<DataTable data={data} columns={columns} keyExtractor={(r) => r.id} />);
    fireEvent.click(screen.getByText('Name'));
    const rows = screen.getAllByRole('row');
    expect(rows[1]).toHaveTextContent('Alpha');
  });

  it('sorts descending on second column header click', () => {
    render(<DataTable data={data} columns={columns} keyExtractor={(r) => r.id} />);
    fireEvent.click(screen.getByText('Name'));
    fireEvent.click(screen.getByText('Name'));
    const rows = screen.getAllByRole('row');
    expect(rows[1]).toHaveTextContent('Gamma');
  });

  it('shows custom render in cell', () => {
    const colsWithRender: Column<Row>[] = [
      ...columns,
      { key: 'id', header: 'Action', render: (r) => <button>Edit {r.name}</button> },
    ];
    render(<DataTable data={data} columns={colsWithRender} keyExtractor={(r) => r.id} />);
    expect(screen.getByText('Edit Alpha')).toBeInTheDocument();
  });
});
