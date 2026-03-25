import React, { useState } from "react";
import type { App as McpApp } from "@modelcontextprotocol/ext-apps";
import type { SecurityAlert } from "../../../shared/types";

interface ThreatClassifierProps {
  alert: SecurityAlert;
  onAcknowledge: () => void;
  app: McpApp;
}

type Classification = "benign" | "suspicious" | "malicious";

const VERDICT_CONFIG: Record<Classification, {
  color: string; bg: string; border: string; icon: string; label: string; action: string;
}> = {
  benign: {
    color: "var(--severity-low)", bg: "var(--severity-low-bg)", border: "var(--severity-low-border)",
    icon: "\u2713", label: "Benign", action: "Alert acknowledged — false positive",
  },
  suspicious: {
    color: "var(--severity-medium)", bg: "var(--severity-medium-bg)", border: "var(--severity-medium-border)",
    icon: "?", label: "Suspicious", action: "Case created — needs further investigation",
  },
  malicious: {
    color: "var(--severity-critical)", bg: "var(--severity-critical-bg)", border: "var(--severity-critical-border)",
    icon: "!", label: "Malicious", action: "Case created — immediate response required",
  },
};

export function ThreatClassifier({ alert, onAcknowledge, app }: ThreatClassifierProps) {
  const [classification, setClassification] = useState<Classification | null>(null);
  const [creating, setCreating] = useState(false);
  const [caseCreated, setCaseCreated] = useState(false);

  const classify = async (cls: Classification) => {
    setClassification(cls);

    if (cls === "benign") {
      onAcknowledge();
      return;
    }

    setCreating(true);
    try {
      const src = alert._source;
      const severity = cls === "malicious"
        ? src["kibana.alert.risk_score"] >= 80 ? "critical" : "high"
        : "medium";

      const tags = [
        `classification:${cls}`,
        ...(src.host?.name ? [`host:${src.host.name}`] : []),
        ...(src["kibana.alert.rule.threat"]?.flatMap((t) =>
          t.technique?.map((tech) => `mitre:${tech.id}`) || []
        ) || []),
      ];

      await app.callServerTool({
        name: "create-case",
        arguments: {
          title: `[${cls.toUpperCase()}] ${src["kibana.alert.rule.name"]}`,
          description: [
            `## Alert Details`,
            `- **Rule:** ${src["kibana.alert.rule.name"]}`,
            `- **Severity:** ${src["kibana.alert.severity"]}`,
            `- **Risk Score:** ${src["kibana.alert.risk_score"]}`,
            `- **Host:** ${src.host?.name || "N/A"}`,
            `- **User:** ${src.user?.name || "N/A"}`,
            ``,
            `## Reason`,
            src["kibana.alert.reason"],
            ``,
            `## Classification`,
            `Classified as **${cls}** during triage.`,
          ].join("\n"),
          tags: tags.join(","),
          severity,
        },
      });

      setCaseCreated(true);

      await app.updateModelContext({
        content: [{
          type: "text",
          text: `Alert "${src["kibana.alert.rule.name"]}" classified as ${cls}. Case created (${severity}).`,
        }],
      });
    } catch (e) {
      console.error("Failed to create case:", e);
    } finally {
      setCreating(false);
    }
  };

  if (classification) {
    const v = VERDICT_CONFIG[classification];
    const src = alert._source;
    return (
      <div style={{
        background: v.bg,
        border: `1px solid ${v.border}`,
        borderLeft: `4px solid ${v.color}`,
        borderRadius: "var(--radius-md)",
        padding: "14px 16px",
        marginBottom: 16,
        animation: "fadeIn 0.3s ease-out",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
          <span style={{
            display: "inline-flex", alignItems: "center", justifyContent: "center",
            width: 28, height: 28, borderRadius: "50%",
            background: v.color, color: "white",
            fontSize: 14, fontWeight: 800,
          }}>
            {v.icon}
          </span>
          <div>
            <div style={{ fontSize: 14, fontWeight: 700, color: v.color, letterSpacing: "-0.2px" }}>
              Verdict: {v.label}
            </div>
            <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
              {creating ? "Creating case..." : v.action}
            </div>
          </div>
        </div>

        <div style={{
          display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(120px, 1fr))",
          gap: 8, fontSize: 11, color: "var(--text-secondary)",
          paddingTop: 8, borderTop: `1px solid ${v.border}`,
        }}>
          <div>
            <span style={{ color: "var(--text-dim)", fontSize: 9.5, textTransform: "uppercase", letterSpacing: "0.5px" }}>Rule</span>
            <div style={{ fontWeight: 600, marginTop: 1 }}>{src["kibana.alert.rule.name"]}</div>
          </div>
          {src.host?.name && (
            <div>
              <span style={{ color: "var(--text-dim)", fontSize: 9.5, textTransform: "uppercase", letterSpacing: "0.5px" }}>Host</span>
              <div style={{ fontFamily: "var(--font-mono)", marginTop: 1 }}>{src.host.name}</div>
            </div>
          )}
          <div>
            <span style={{ color: "var(--text-dim)", fontSize: 9.5, textTransform: "uppercase", letterSpacing: "0.5px" }}>Risk Score</span>
            <div style={{ fontFamily: "var(--font-mono)", fontWeight: 700, color: v.color, marginTop: 1 }}>{src["kibana.alert.risk_score"]}</div>
          </div>
          {caseCreated && (
            <div>
              <span style={{ color: "var(--text-dim)", fontSize: 9.5, textTransform: "uppercase", letterSpacing: "0.5px" }}>Case</span>
              <div style={{ color: "var(--accent)", fontWeight: 600, marginTop: 1 }}>Created</div>
            </div>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="classifier-bar">
      <button className="classify-btn benign" onClick={() => classify("benign")}>
        Benign
      </button>
      <button className="classify-btn suspicious" onClick={() => classify("suspicious")}>
        Suspicious
      </button>
      <button className="classify-btn malicious" onClick={() => classify("malicious")}>
        Malicious
      </button>
    </div>
  );
}
