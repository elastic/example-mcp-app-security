// Severity colors and labels for EUI-based components.
// Separate from shared/severity.tsx which uses CSS variables (for non-EUI views).

export const SEVERITY_COLORS: Record<string, { color: string; label: string }> = {
  low: { color: "#40c790", label: "LOW" },
  medium: { color: "#f0b840", label: "MED" },
  high: { color: "#f07840", label: "HIGH" },
  critical: { color: "#f04040", label: "CRIT" },
};

export function severityColor(severity: string): string {
  return SEVERITY_COLORS[severity.toLowerCase()]?.color || SEVERITY_COLORS.low.color;
}

export function severityLabel(severity: string): string {
  return SEVERITY_COLORS[severity.toLowerCase()]?.label || "LOW";
}

export function riskScoreColor(score: number): string {
  if (score >= 80) return SEVERITY_COLORS.critical.color;
  if (score >= 60) return SEVERITY_COLORS.high.color;
  if (score >= 30) return SEVERITY_COLORS.medium.color;
  return SEVERITY_COLORS.low.color;
}
