import { describe, it, expect, vi, afterEach } from 'vitest';
import React from 'react';
import { render, screen, cleanup, fireEvent } from '@testing-library/react';
import NodeDetailPanel from '../src/components/NodeDetailPanel.jsx';

afterEach(cleanup);

const sampleData = {
  label: 'SQL Injection',
  nodeId: 'A1',
  description: 'Attacker injects malicious SQL queries.',
  ttcMappings: [
    {
      technique_id: 'T1190',
      technique_name: 'Exploit Public-Facing Application',
      confidence: 0.85,
      tactics: ['Initial Access'],
    },
  ],
  mitigations: [
    { name: 'Input Validation', description: 'Validate all user inputs.' },
  ],
};

describe('NodeDetailPanel', () => {
  it('renders the panel with correct absolute positioning', () => {
    render(
      <NodeDetailPanel data={sampleData} position={{ x: 100, y: 200 }} onClose={() => {}} zIndex={1500} />
    );
    const panel = screen.getByTestId('node-detail-panel');
    expect(panel.style.position).toBe('absolute');
    expect(panel.style.top).toBe('200px');
    expect(panel.style.left).toBe('100px');
    expect(panel.style.zIndex).toBe('1500');
  });

  it('renders the node label and description from NodePopoverContent', () => {
    render(
      <NodeDetailPanel data={sampleData} position={{ x: 0, y: 0 }} onClose={() => {}} zIndex={1000} />
    );
    expect(screen.getByText('SQL Injection')).toBeTruthy();
    expect(screen.getByText('Attacker injects malicious SQL queries.')).toBeTruthy();
  });

  it('renders MITRE technique mappings', () => {
    render(
      <NodeDetailPanel data={sampleData} position={{ x: 0, y: 0 }} onClose={() => {}} zIndex={1000} />
    );
    expect(screen.getByText(/T1190/)).toBeTruthy();
    expect(screen.getByText(/Exploit Public-Facing Application/)).toBeTruthy();
  });

  it('calls onClose when the close button is clicked', () => {
    const onClose = vi.fn();
    render(
      <NodeDetailPanel data={sampleData} position={{ x: 0, y: 0 }} onClose={onClose} zIndex={1000} />
    );
    const closeBtn = screen.getByLabelText('Close panel');
    fireEvent.click(closeBtn);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('renders with default position and zIndex when not provided', () => {
    render(
      <NodeDetailPanel data={sampleData} position={null} onClose={() => {}} />
    );
    const panel = screen.getByTestId('node-detail-panel');
    expect(panel.style.top).toBe('0px');
    expect(panel.style.left).toBe('0px');
    expect(panel.style.zIndex).toBe('1000');
  });

  it('renders card styling with shadow and border', () => {
    render(
      <NodeDetailPanel data={sampleData} position={{ x: 0, y: 0 }} onClose={() => {}} zIndex={1000} />
    );
    const panel = screen.getByTestId('node-detail-panel');
    expect(panel.style.borderRadius).toBe('12px');
    expect(panel.style.border).toMatch(/1px solid/i);
    expect(panel.style.boxShadow).toBeTruthy();
  });

  it('shows empty state when data has no details', () => {
    render(
      <NodeDetailPanel data={{ label: 'Empty', nodeId: 'X' }} position={{ x: 0, y: 0 }} onClose={() => {}} zIndex={1000} />
    );
    expect(screen.getByText('No additional details available')).toBeTruthy();
  });
});
