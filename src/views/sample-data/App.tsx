import React, { useState, useEffect, useRef } from "react";
import { App as McpApp } from "@modelcontextprotocol/ext-apps";
import { applyTheme } from "../../shared/theme";
import { extractCallResult } from "../../shared/extract-tool-text";
import "./styles.css";

const SCENARIOS = [
  { id: "windows-credential-theft", name: "Windows Credential Theft", desc: "Mimikatz, procdump, and credential dumping on a Windows endpoint", icon: "\u{1F511}" },
  { id: "aws-privilege-escalation", name: "AWS Privilege Escalation", desc: "IAM policy changes, role assumption, and access key creation", icon: "\u{2601}\u{FE0F}" },
  { id: "okta-identity-takeover", name: "Okta Identity Takeover", desc: "MFA factor reset, password change, and session hijacking", icon: "\u{1FAAA}" },
  { id: "ransomware-kill-chain", name: "Ransomware Kill Chain", desc: "PowerShell execution, C2 beaconing, and mass file encryption", icon: "\u{1F480}" },
];

interface GenerateResult { indexed: number; scenario: string; indices: string[] }

export function App() {
  const appRef = useRef<McpApp | null>(null);
  const [connected, setConnected] = useState(false);
  const [selectedScenario, setSelectedScenario] = useState<string | null>(null);
  const [count, setCount] = useState(50);
  const [generating, setGenerating] = useState(false);
  const [cleaning, setCleaning] = useState(false);
  const [result, setResult] = useState<GenerateResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const app = new McpApp({ name: "sample-data", version: "0.1.0" });
    appRef.current = app;
    applyTheme(app);

    app.ontoolresult = (toolResult) => {
      try {
        const text = extractCallResult(toolResult);
        if (text) {
          const data = JSON.parse(text);
          if (data.indexed !== undefined) setResult(data);
        }
      } catch { /* ignore */ }
    };

    app.connect().then(() => setConnected(true));
    return () => { app.close(); };
  }, []);

  const generate = async () => {
    if (!appRef.current) return;
    setGenerating(true); setResult(null); setError(null);
    try {
      const toolResult = await appRef.current.callServerTool({
        name: "generate-scenario",
        arguments: selectedScenario ? { scenario: selectedScenario, count } : { count },
      });
      const text = extractCallResult(toolResult);
      if (text) setResult(JSON.parse(text));
    } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
    finally { setGenerating(false); }
  };

  const cleanup = async () => {
    if (!appRef.current) return;
    setCleaning(true); setError(null);
    try {
      const toolResult = await appRef.current.callServerTool({ name: "cleanup-sample-data", arguments: {} });
      const text = extractCallResult(toolResult);
      if (text) {
        const data = JSON.parse(text);
        setResult({ indexed: 0, scenario: "cleanup", indices: [] });
        alert(`Cleaned up ${data.deleted} documents`);
      }
    } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
    finally { setCleaning(false); }
  };

  if (!connected) return <div className="loading">Connecting...</div>;

  return (
    <div className="sample-app">
      <div className="sample-header">
        <h1>Security Sample Data Generator</h1>
        <p>Generate ECS-compliant security events and synthetic alerts for demos, testing, and rule development. All data is tagged for safe cleanup.</p>
      </div>
      <div className="scenario-grid">
        {SCENARIOS.map((s) => (
          <div key={s.id} className={`scenario-card ${selectedScenario === s.id ? "selected" : ""}`}
            onClick={() => setSelectedScenario(selectedScenario === s.id ? null : s.id)}>
            <div className="scenario-icon">{s.icon}</div>
            <div className="scenario-name">{s.name}</div>
            <div className="scenario-desc">{s.desc}</div>
          </div>
        ))}
      </div>
      <div className="generate-controls">
        <div className="control-row">
          <label>Events</label>
          <input type="number" value={count} onChange={(e) => setCount(parseInt(e.target.value) || 50)} min={10} max={1000} />
          <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
            {selectedScenario ? `Generate ${count} events for ${selectedScenario}` : `Generate ${count} events per scenario (all)`}
          </span>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <button className="btn btn-primary" onClick={generate} disabled={generating}>{generating ? "Generating..." : "Generate Data"}</button>
          <button className="btn btn-danger" onClick={cleanup} disabled={cleaning}>{cleaning ? "Cleaning..." : "Cleanup All Sample Data"}</button>
        </div>
      </div>
      {result && result.scenario !== "cleanup" && (
        <div className="result-banner success">
          Successfully indexed <strong>{result.indexed}</strong> documents
          {result.scenario !== "all" && <> for scenario <strong>{result.scenario}</strong></>}
          <div className="indices-list">Indices: {result.indices.join(", ")}</div>
        </div>
      )}
      {error && <div className="result-banner error">{error}</div>}
    </div>
  );
}
