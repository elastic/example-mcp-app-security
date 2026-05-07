/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useCallback, useMemo } from "react";
import Editor, { type BeforeMount, type OnMount } from "@monaco-editor/react";
import type { editor } from "monaco-editor";
import { language as monarchLanguage } from "@elastic/monaco-esql/lib/monarch-shared";

interface QueryEditorProps {
  readonly query: string;
  readonly onChange: (q: string) => void;
  readonly onExecute: () => void;
  readonly executing: boolean;
}

const ESQL_THEME = "threat-hunt-esql";
const LINE_HEIGHT = 19;
const MIN_LINES = 5;

let esqlLanguageRegistered = false;

function registerEsqlLanguage(monacoInstance: Parameters<BeforeMount>[0]): void {
  if (esqlLanguageRegistered) return;
  esqlLanguageRegistered = true;

  monacoInstance.languages.register({ id: "esql" });
  monacoInstance.languages.setMonarchTokensProvider("esql", monarchLanguage);

  monacoInstance.editor.defineTheme(ESQL_THEME, {
    base: "vs-dark",
    inherit: true,
    rules: [
      { token: "delimiter.pipe", foreground: "f0b840", fontStyle: "bold" },
      { token: "keyword.command", foreground: "5c7cfa", fontStyle: "bold" },
      { token: "keyword.option", foreground: "5c7cfa", fontStyle: "bold" },
      { token: "keyword.literal", foreground: "a085e0", fontStyle: "bold" },
      { token: "keyword.operator", foreground: "a085e0", fontStyle: "bold" },
      { token: "identifier.function", foreground: "4cbfa6" },
      { token: "identifier.timestamp", foreground: "e6e6e5" },
      { token: "identifier.column", foreground: "e6e6e5" },
      { token: "identifier", foreground: "e6e6e5" },
      { token: "string", foreground: "d1a54a" },
      { token: "string.triple", foreground: "d1a54a" },
      { token: "number", foreground: "ff8a50" },
      { token: "number.float", foreground: "ff8a50" },
      { token: "number.time", foreground: "ff8a50" },
      { token: "comment", foreground: "817f78", fontStyle: "italic" },
      { token: "comment.doc", foreground: "817f78", fontStyle: "italic" },
      { token: "type", foreground: "4cbfa6" },
      { token: "variable.name", foreground: "e6e6e5" },
    ],
    colors: {
      "editor.background": "#1f1f1e",
      "editor.foreground": "#e6e6e5",
      "editorLineNumber.foreground": "#817f78",
      "editorLineNumber.activeForeground": "#b9b9ae",
      "editorGutter.background": "#1f1f1e",
      "editorCursor.foreground": "#e6e6e5",
      "editor.selectionBackground": "rgba(92, 124, 250, 0.3)",
    },
  });
}

/**
 * ES|QL query editor — Figma design node-id 3-2984.
 *
 * Syntax highlighting is provided by `@elastic/monaco-esql` (Monarch grammar),
 * not a hand-maintained tokenizer.
 */
export function QueryEditor({ query, onChange, onExecute, executing }: QueryEditorProps) {
  const lineCount = Math.max(MIN_LINES, query.split("\n").length);
  const heightPx = lineCount * LINE_HEIGHT;

  const beforeMount = useCallback<BeforeMount>((monacoInstance) => {
    registerEsqlLanguage(monacoInstance);
  }, []);

  const onMount = useCallback<OnMount>(
    (editor, monacoInstance) => {
      editor.addCommand(monacoInstance.KeyMod.CtrlCmd | monacoInstance.KeyCode.Enter, () => {
        onExecute();
      });
    },
    [onExecute],
  );

  const options = useMemo(
    (): editor.IStandaloneEditorConstructionOptions => ({
      fontFamily: 'var(--font-sans, "Fira Sans", system-ui, sans-serif)',
      fontSize: 14,
      lineHeight: LINE_HEIGHT,
      lineNumbers: "on",
      lineNumbersMinChars: 2,
      minimap: { enabled: false },
      scrollBeyondLastLine: false,
      wordWrap: "off",
      padding: { top: 0, bottom: 0 },
      overviewRulerLanes: 0,
      scrollbar: {
        vertical: "auto",
        horizontal: "auto",
        verticalScrollbarSize: 8,
        horizontalScrollbarSize: 8,
      },
      automaticLayout: true,
      tabSize: 2,
      insertSpaces: true,
      renderLineHighlight: "none",
      folding: false,
      glyphMargin: false,
      contextmenu: false,
      quickSuggestions: false,
      suggestOnTriggerCharacters: false,
      acceptSuggestionOnEnter: "off",
      wordBasedSuggestions: "off",
      ariaLabel: "ES|QL query",
    }),
    [],
  );

  return (
    <div className="query-editor">
      <div className="query-editor-header">
        <span className="query-editor-label">ES|QL Query</span>
        <button
          type="button"
          className="query-editor-clear"
          onClick={() => onChange("")}
          disabled={!query}
        >
          Clear
        </button>
      </div>

      <div className="query-editor-code">
        <div className="query-monaco-wrap" style={{ minHeight: MIN_LINES * LINE_HEIGHT }}>
          {query === "" && (
            <div className="query-monaco-placeholder" aria-hidden="true">
              {"FROM logs-*\n| WHERE @timestamp > NOW() - 1 hour\n| LIMIT 100"}
            </div>
          )}
          <Editor
            height={`${heightPx}px`}
            theme={ESQL_THEME}
            language="esql"
            value={query}
            options={options}
            beforeMount={beforeMount}
            onMount={onMount}
            onChange={(v) => onChange(v ?? "")}
          />
        </div>
      </div>

      <div className="query-editor-footer">
        <div className="query-editor-divider" aria-hidden="true" />
        <div className="query-actions">
          <button
            type="button"
            className="btn btn-primary btn-execute"
            onClick={onExecute}
            disabled={executing || !query.trim()}
          >
            {executing ? "Executing…" : "Execute"}
          </button>
          <span className="query-editor-hint">Cmd+Enter to execute</span>
        </div>
      </div>
    </div>
  );
}
