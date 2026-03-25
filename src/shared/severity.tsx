import React from "react";

const SEVERITY_CONFIG = {
  low: { color: "var(--severity-low)", bg: "var(--severity-low-bg)", border: "var(--severity-low-border)", label: "LOW" },
  medium: { color: "var(--severity-medium)", bg: "var(--severity-medium-bg)", border: "var(--severity-medium-border)", label: "MED" },
  high: { color: "var(--severity-high)", bg: "var(--severity-high-bg)", border: "var(--severity-high-border)", label: "HIGH" },
  critical: { color: "var(--severity-critical)", bg: "var(--severity-critical-bg)", border: "var(--severity-critical-border)", label: "CRIT" },
} as const;

type SeverityLevel = keyof typeof SEVERITY_CONFIG;

export function severityColor(severity: string): string {
  const key = severity.toLowerCase() as SeverityLevel;
  return SEVERITY_CONFIG[key]?.color || SEVERITY_CONFIG.low.color;
}

export function SeverityBadge({ severity, compact }: { severity: string; compact?: boolean }) {
  const key = severity.toLowerCase() as SeverityLevel;
  const config = SEVERITY_CONFIG[key] || SEVERITY_CONFIG.low;

  if (compact) {
    return (
      <span style={{
        display: "inline-block",
        width: 7, height: 7,
        borderRadius: "50%",
        backgroundColor: config.color,
        flexShrink: 0,
      }} title={severity} />
    );
  }

  return (
    <span style={{
      display: "inline-flex",
      alignItems: "center",
      padding: "1px 7px",
      borderRadius: "var(--radius-sm)",
      fontSize: 10,
      fontWeight: 700,
      letterSpacing: "0.6px",
      backgroundColor: config.bg,
      color: config.color,
      border: `1px solid ${config.border}`,
      lineHeight: "18px",
    }}>
      {config.label}
    </span>
  );
}

export function RiskScore({ score }: { score: number }) {
  const color =
    score >= 80 ? "var(--severity-critical)"
      : score >= 60 ? "var(--severity-high)"
        : score >= 30 ? "var(--severity-medium)"
          : "var(--severity-low)";

  const circumference = 31.4;
  const filled = (score / 100) * circumference;

  return (
    <span style={{
      display: "inline-flex",
      alignItems: "center",
      gap: 4,
      fontSize: 12,
      color,
      fontWeight: 700,
      fontVariantNumeric: "tabular-nums",
      fontFamily: "var(--font-mono)",
    }}>
      <svg width="16" height="16" viewBox="0 0 16 16">
        <circle cx="8" cy="8" r="6" fill="none" stroke="currentColor" strokeWidth="2" opacity="0.15" />
        <circle cx="8" cy="8" r="6" fill="none" stroke="currentColor" strokeWidth="2"
          strokeDasharray={`${filled} ${circumference}`}
          strokeLinecap="round"
          transform="rotate(-90 8 8)" />
      </svg>
      {score}
    </span>
  );
}

export function SeverityDot({ severity, count }: { severity: string; count: number }) {
  const key = severity.toLowerCase() as SeverityLevel;
  const config = SEVERITY_CONFIG[key] || SEVERITY_CONFIG.low;

  return (
    <span style={{
      display: "inline-flex",
      alignItems: "center",
      gap: 5,
      fontSize: 12,
      color: "var(--text-secondary)",
      fontVariantNumeric: "tabular-nums",
    }}>
      <span style={{
        width: 8, height: 8,
        borderRadius: "50%",
        backgroundColor: config.color,
        boxShadow: `0 0 6px ${config.color}40`,
      }} />
      <span style={{ fontWeight: 600, color: config.color }}>{count}</span>
      <span style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.5px" }}>{severity}</span>
    </span>
  );
}
