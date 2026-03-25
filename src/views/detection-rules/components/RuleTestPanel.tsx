import React, { useState, useEffect } from "react";

interface RuleTestPanelProps {
  query: string;
  language: string;
  onValidate: (query: string, language: string) => Promise<{ valid: boolean; error?: string }>;
}

export function RuleTestPanel({ query, language, onValidate }: RuleTestPanelProps) {
  const [testQuery, setTestQuery] = useState(query);
  const [result, setResult] = useState<{ valid: boolean; error?: string } | null>(null);
  const [testing, setTesting] = useState(false);

  useEffect(() => {
    setTestQuery(query);
  }, [query]);

  const handleValidate = async () => {
    setTesting(true);
    setResult(null);
    try {
      const res = await onValidate(testQuery, language);
      setResult(res);
    } finally {
      setTesting(false);
    }
  };

  return (
    <section className="test-panel" aria-label="Query validation">
      <div className="test-panel-header">
        <h3 className="test-panel-title">Validate query</h3>
        <span className="test-panel-lang">{language}</span>
      </div>
      <textarea
        className="test-panel-textarea"
        value={testQuery}
        onChange={(e) => setTestQuery(e.target.value)}
        spellCheck={false}
        aria-label="Rule query to validate"
      />
      <div className="test-panel-footer">
        <button type="button" className="btn btn-primary btn-sm" onClick={handleValidate} disabled={testing}>
          {testing ? "Validating…" : "Validate"}
        </button>
      </div>
      {result ? (
        <div className={`test-result ${result.valid ? "valid" : "invalid"}`} role="status">
          <span className="test-result-badge">{result.valid ? "Valid" : "Invalid"}</span>
          <span>{result.valid ? "Query parses successfully." : result.error ?? "Validation failed."}</span>
        </div>
      ) : null}
    </section>
  );
}
