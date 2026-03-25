import React, { useRef, useEffect } from "react";

interface QueryEditorProps {
  query: string;
  onChange: (q: string) => void;
  onExecute: () => void;
  executing: boolean;
}

export function QueryEditor({ query, onChange, onExecute, executing }: QueryEditorProps) {
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
        e.preventDefault();
        onExecute();
      }
    };
    const el = textareaRef.current;
    el?.addEventListener("keydown", handler);
    return () => el?.removeEventListener("keydown", handler);
  }, [onExecute]);

  return (
    <div className="query-editor">
      <div className="query-editor-header">
        <span className="query-editor-label">ES|QL Query</span>
        <span className="query-editor-hint">Cmd+Enter to execute</span>
      </div>
      <textarea
        ref={textareaRef}
        className="query-textarea"
        value={query}
        onChange={(e) => onChange(e.target.value)}
        placeholder="FROM logs-* | WHERE @timestamp > NOW() - 1 hour | LIMIT 100"
        spellCheck={false}
        aria-label="ES|QL query"
      />
      <div className="query-actions">
        <button type="button" className="btn btn-primary" onClick={onExecute} disabled={executing || !query.trim()}>
          {executing ? "Executing…" : "Execute"}
        </button>
        <button type="button" className="btn btn-ghost" onClick={() => onChange("")} disabled={executing}>
          Clear
        </button>
      </div>
    </div>
  );
}
