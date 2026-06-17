'use client';

/**
 * RiskDashboard — the executive risk hero for the Threat Model Summary.
 *
 * Replaces the old flat 5-number metric strip with:
 *   - a risk-posture call-out (overall level + high-severity count),
 *   - a severity-breakdown donut (High / Medium / Low),
 *   - the top critical threats, deep-linking into the per-threat dashboard,
 *   - a row of KPI cards (Threats / Attack Trees / TTP Mappings / Mitigations),
 *   - a mitigation-coverage progress bar.
 *
 * Everything is derived from the already-fetched `/data` bundle via
 * `risk-posture.ts` — no new endpoint, no extra round-trip.
 */

import { useMemo } from 'react';
import { useRouter } from 'next/navigation';
import Container from '@cloudscape-design/components/container';
import Box from '@cloudscape-design/components/box';
import Grid from '@cloudscape-design/components/grid';
import SpaceBetween from '@cloudscape-design/components/space-between';
import PieChart from '@cloudscape-design/components/pie-chart';
import ProgressBar from '@cloudscape-design/components/progress-bar';
import Badge from '@cloudscape-design/components/badge';
import Link from '@cloudscape-design/components/link';
import Header from '@cloudscape-design/components/header';
import type { ReportAttackTree, ThreatRow } from '@/utils/mitigation-aggregator';
import {
  severityCounts,
  riskLevel,
  topThreats,
  coverageStats,
  type RiskLevel,
  type Severity,
} from '@/utils/risk-posture';

interface RiskDashboardProps {
  threats: ThreatRow[];
  attackTrees: ReportAttackTree[];
  ttpMappings: number;
  totalMitigations: number;
  appId: string;
  versionId: string;
}

const RISK_META: Record<RiskLevel, { label: string; color: string; text: string }> = {
  critical: { label: 'Critical', color: '#d91515', text: '#ffffff' },
  high: { label: 'High', color: '#d13212', text: '#ffffff' },
  medium: { label: 'Medium', color: '#b2911c', text: '#ffffff' },
  low: { label: 'Low', color: '#037f0c', text: '#ffffff' },
  none: { label: 'No threats', color: '#5f6b7a', text: '#ffffff' },
};

const SEVERITY_COLOR: Record<Severity, string> = {
  high: '#d13212',
  medium: '#b2911c',
  low: '#5f6b7a',
};

const SEVERITY_BADGE: Record<Severity, 'severity-high' | 'severity-medium' | 'severity-low'> = {
  high: 'severity-high',
  medium: 'severity-medium',
  low: 'severity-low',
};

/** A single KPI tile. */
function Kpi({ label, value, accent }: { label: string; value: number; accent?: string }) {
  return (
    <div
      style={{
        border: '1px solid #e9ebed',
        borderRadius: 12,
        padding: '14px 16px',
        background: '#ffffff',
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        gap: 4,
      }}
    >
      <Box variant="awsui-key-label">{label}</Box>
      <div style={{ fontSize: 30, fontWeight: 700, lineHeight: 1.1, color: accent || '#0f1b2d' }}>
        {value.toLocaleString()}
      </div>
    </div>
  );
}

export default function RiskDashboard({
  threats,
  attackTrees,
  ttpMappings,
  totalMitigations,
  appId,
  versionId,
}: RiskDashboardProps) {
  const router = useRouter();

  const counts = useMemo(() => severityCounts(threats, attackTrees), [threats, attackTrees]);
  const level = useMemo(() => riskLevel(counts), [counts]);
  const top = useMemo(() => topThreats(threats, attackTrees, 3), [threats, attackTrees]);
  const coverage = useMemo(() => coverageStats(attackTrees), [attackTrees]);
  const risk = RISK_META[level];

  const pieData = useMemo(
    () =>
      (
        [
          { title: 'High', value: counts.high, color: SEVERITY_COLOR.high, key: 'high' as const },
          { title: 'Medium', value: counts.medium, color: SEVERITY_COLOR.medium, key: 'medium' as const },
          { title: 'Low', value: counts.low, color: SEVERITY_COLOR.low, key: 'low' as const },
        ] satisfies Array<{ title: string; value: number; color: string; key: Severity }>
      ).filter((d) => d.value > 0),
    [counts],
  );

  return (
    <Container>
      <SpaceBetween size="l">
        {/* Top band: risk posture + severity donut + top threats */}
        <Grid
          gridDefinition={[{ colspan: { default: 12, s: 3 } }, { colspan: { default: 12, s: 4 } }, { colspan: { default: 12, s: 5 } }]}
        >
          {/* Risk posture call-out */}
          <div key="posture">
            <Box variant="awsui-key-label">Risk posture</Box>
            <div
              style={{
                marginTop: 8,
                borderRadius: 12,
                padding: '18px 16px',
                background: risk.color,
                color: risk.text,
                display: 'flex',
                flexDirection: 'column',
                gap: 2,
                minHeight: 120,
                justifyContent: 'center',
              }}
            >
              <div style={{ fontSize: 13, opacity: 0.9, letterSpacing: 0.4, textTransform: 'uppercase' }}>
                Overall risk
              </div>
              <div style={{ fontSize: 30, fontWeight: 700, lineHeight: 1.1 }}>{risk.label}</div>
              <div style={{ fontSize: 13, opacity: 0.95 }}>
                {counts.high > 0
                  ? `${counts.high} high-severity ${counts.high === 1 ? 'threat' : 'threats'}`
                  : counts.total > 0
                    ? `${counts.total} ${counts.total === 1 ? 'threat' : 'threats'}, none high-severity`
                    : 'No threats identified'}
              </div>
            </div>
          </div>

          {/* Severity donut */}
          <div key="severity">
            <Box variant="awsui-key-label">Severity breakdown</Box>
            <PieChart
              data={pieData}
              variant="donut"
              size="small"
              hideFilter
              hideLegend={false}
              innerMetricValue={String(counts.total)}
              innerMetricDescription="threats"
              segmentDescription={(datum, sum) =>
                `${datum.value} (${sum > 0 ? Math.round((datum.value / sum) * 100) : 0}%)`
              }
              detailPopoverContent={(datum, sum) => [
                { key: 'Count', value: String(datum.value) },
                { key: 'Percentage', value: `${sum > 0 ? Math.round((datum.value / sum) * 100) : 0}%` },
              ]}
              ariaLabel="Threat severity breakdown"
              empty={<Box color="text-status-inactive">No threats</Box>}
            />
          </div>

          {/* Top critical threats */}
          <div key="top">
            <Box variant="awsui-key-label">Top threats</Box>
            <div style={{ marginTop: 8 }}>
              {top.length === 0 ? (
                <Box color="text-status-inactive">No threats identified.</Box>
              ) : (
                <SpaceBetween size="xs">
                  {top.map((t) => (
                    <div
                      key={t.id}
                      style={{
                        display: 'flex',
                        alignItems: 'flex-start',
                        gap: 8,
                        padding: '8px 10px',
                        border: '1px solid #e9ebed',
                        borderRadius: 8,
                        background: '#fbfbfb',
                      }}
                    >
                      <Badge color={SEVERITY_BADGE[t.severity]}>{t.severity}</Badge>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <Link
                          onFollow={(e) => {
                            e.preventDefault();
                            router.push(
                              `/applications/${appId}/versions/${versionId}/threats/${t.index}`,
                            );
                          }}
                        >
                          <span style={{ fontWeight: 600 }}>{t.id}</span>{' '}
                          <span>{t.title}</span>
                        </Link>
                      </div>
                    </div>
                  ))}
                </SpaceBetween>
              )}
            </div>
          </div>
        </Grid>

        {/* KPI cards */}
        <Grid
          gridDefinition={[
            { colspan: { default: 6, s: 3 } },
            { colspan: { default: 6, s: 3 } },
            { colspan: { default: 6, s: 3 } },
            { colspan: { default: 6, s: 3 } },
          ]}
        >
          <div key="k-threats"><Kpi label="Total threats" value={counts.total} /></div>
          <div key="k-trees"><Kpi label="Attack trees" value={attackTrees.length} /></div>
          <div key="k-ttp"><Kpi label="TTP mappings" value={ttpMappings} /></div>
          <div key="k-mit"><Kpi label="Mitigations" value={totalMitigations} accent="#037f0c" /></div>
        </Grid>

        {/* Mitigation coverage */}
        <div>
          <ProgressBar
            value={coverage.percent}
            status={coverage.percent >= 100 ? 'success' : 'in-progress'}
            variant="key-value"
            label="Mitigation coverage"
            description={
              coverage.stepsTotal > 0
                ? `${coverage.stepsCovered} of ${coverage.stepsTotal} attack steps have at least one mitigation`
                : `${coverage.treesCovered} of ${coverage.treesTotal} attack trees have mitigations`
            }
            additionalInfo={
              coverage.percent >= 100
                ? 'Every attack step is addressed by a recommended control.'
                : coverage.percent === 0
                  ? 'No attack steps are addressed yet.'
                  : `${100 - coverage.percent}% of attack steps still need a control.`
            }
            resultText={`${coverage.percent}%`}
          />
        </div>
      </SpaceBetween>
    </Container>
  );
}
