/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useRef, useEffect, useMemo } from "react";

interface QueryEditorProps {
  query: string;
  onChange: (q: string) => void;
  onExecute: () => void;
  executing: boolean;
}

/* ─── ES|QL syntax highlighting ────────────────────────────────────────
 *
 * We render a <pre> of coloured <span>s behind a transparent <textarea>.
 * The textarea handles input + caret + selection; the <pre> shows the
 * highlighted output. Both use the identical font/line-height/padding so
 * they line up pixel-perfect.
 *
 * Colours are picked from the app's dark palette:
 *   commands   (FROM, WHERE, STATS, BY, ...)  → accent blue  #5c7cfa
 *   operators  (AND, OR, NOT, IN, NULL, ...)  → violet       #a085e0
 *   functions  (COUNT, NOW, TO_STRING, ...)   → teal         #4cbfa6
 *   strings    ("...", '...')                 → warm amber   #d1a54a
 *   numbers                                    → orange       #ff8a50
 *   pipes      |                               → warning gold #f0b840 bold
 *   comments   // ..., /* ... *\/              → muted        #817f78 italic
 *   plain identifiers / fields                → default text #e6e6e5
 *
 * Keyword lists drawn from the Elasticsearch ES|QL reference. Not exhaustive,
 * but covers the vocabulary a hunter reaches for in a query bar.
 */

// Source + processing commands and their modifiers.
const ESQL_COMMANDS = [
  "FROM", "ROW", "SHOW", "WHERE", "STATS", "SORT", "LIMIT", "KEEP", "DROP",
  "RENAME", "DISSECT", "GROK", "ENRICH", "EVAL", "MV_EXPAND", "LOOKUP",
  "INLINESTATS", "BY", "DESC", "ASC", "AS", "WITH", "ON", "NULLS",
  "FIRST", "LAST", "METADATA",
];

// Logical operators and boolean / null literals.
const ESQL_OPERATORS = [
  "AND", "OR", "NOT", "IN", "IS", "NULL", "TRUE", "FALSE", "LIKE", "RLIKE",
];

// Common ES|QL built-in functions (aggregations + scalar). Not exhaustive.
const ESQL_FUNCTIONS = [
  // Aggregations
  "COUNT", "COUNT_DISTINCT", "SUM", "AVG", "MIN", "MAX", "MEDIAN",
  "PERCENTILE", "VALUES", "TOP",
  // Date / time
  "NOW", "DATE_TRUNC", "DATE_FORMAT", "DATE_PARSE", "DATE_EXTRACT", "DATE_DIFF",
  "BUCKET", "AUTO_BUCKET",
  // Conversion
  "TO_STRING", "TO_INTEGER", "TO_INT", "TO_LONG", "TO_DOUBLE", "TO_DATETIME",
  "TO_BOOLEAN", "TO_IP", "TO_VERSION", "TO_UNSIGNED_LONG", "TO_RADIANS",
  "TO_DEGREES", "TO_CARTESIANPOINT", "TO_CARTESIANSHAPE", "TO_GEOPOINT",
  "TO_GEOSHAPE",
  // Control flow
  "CASE", "COALESCE", "GREATEST", "LEAST",
  // String
  "LENGTH", "TRIM", "LTRIM", "RTRIM", "CONCAT", "SUBSTRING", "SPLIT",
  "REPLACE", "STARTS_WITH", "ENDS_WITH", "TO_LOWER", "TO_UPPER", "LEFT",
  "RIGHT", "LOCATE",
  // Math
  "ABS", "ROUND", "CEIL", "FLOOR", "POW", "SQRT", "LOG", "LOG10", "EXP",
  "SIN", "COS", "TAN", "ASIN", "ACOS", "ATAN", "ATAN2", "PI", "E", "TAU",
  // Multi-value
  "MV_COUNT", "MV_SUM", "MV_AVG", "MV_MIN", "MV_MAX", "MV_MEDIAN",
  "MV_DEDUPE", "MV_FIRST", "MV_LAST", "MV_CONCAT", "MV_SORT", "MV_SLICE",
  "MV_ZIP",
  // IP / CIDR
  "CIDR_MATCH", "IP_PREFIX",
];

// Build one master regex that matches any of the interesting tokens, falling
// back to plain text between matches. Order matters inside the alternation —
// earlier groups win when positions overlap.
function buildTokenRegex(): RegExp {
  const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const cmd = ESQL_COMMANDS.map(escape).join("|");
  const op = ESQL_OPERATORS.map(escape).join("|");
  const fn = ESQL_FUNCTIONS.map(escape).join("|");

  return new RegExp(
    "(\\/\\/[^\\n]*)"                                // 1: // line comment
    + "|(\\/\\*[\\s\\S]*?\\*\\/)"                    // 2: /* block comment */
    + "|(\"(?:\\\\.|[^\"\\\\])*\")"                  // 3: "double-quoted"
    + "|('(?:\\\\.|[^'\\\\])*')"                     // 4: 'single-quoted'
    + "|(\\b\\d+(?:\\.\\d+)?\\b)"                    // 5: number
    + "|(\\|)"                                        // 6: pipe
    + `|\\b(${cmd})\\b`                              // 7: command
    + `|\\b(${op})\\b`                               // 8: operator
    + `|\\b(${fn})\\b`,                              // 9: function
    "gi",
  );
}

type TokenType =
  | "plain" | "comment" | "string" | "number" | "pipe"
  | "command" | "operator" | "function";
interface Token { type: TokenType; text: string }

function tokenize(query: string): Token[] {
  const tokens: Token[] = [];
  const re = buildTokenRegex();
  let lastIndex = 0;
  let m: RegExpExecArray | null;

  while ((m = re.exec(query)) !== null) {
    if (m.index > lastIndex) {
      tokens.push({ type: "plain", text: query.slice(lastIndex, m.index) });
    }
    const [ , lineCmt, blockCmt, dStr, sStr, num, pipe, cmd, op, fn] = m;
    if (lineCmt || blockCmt)     tokens.push({ type: "comment",  text: m[0] });
    else if (dStr || sStr)       tokens.push({ type: "string",   text: m[0] });
    else if (num)                tokens.push({ type: "number",   text: m[0] });
    else if (pipe)               tokens.push({ type: "pipe",     text: m[0] });
    else if (cmd)                tokens.push({ type: "command",  text: m[0] });
    else if (op)                 tokens.push({ type: "operator", text: m[0] });
    else if (fn)                 tokens.push({ type: "function", text: m[0] });
    lastIndex = m.index + m[0].length;
  }
  if (lastIndex < query.length) {
    tokens.push({ type: "plain", text: query.slice(lastIndex) });
  }
  return tokens;
}

function renderHighlighted(query: string): React.ReactNode {
  // Trailing newline guarantees the <pre> has the same height as the
  // textarea when the user's input ends with a newline (browsers skip
  // layout for a trailing \n otherwise).
  const text = query.endsWith("\n") ? query + " " : query;
  const tokens = tokenize(text);
  return tokens.map((tok, i) => {
    if (tok.type === "plain") return tok.text;
    return <span key={i} className={`esql-${tok.type}`}>{tok.text}</span>;
  });
}

/**
 * ES|QL query editor — Figma design node-id 3-2984.
 *
 * Flat full-width panel with three stacked rows:
 *   1. Header row  — "ES|QL Query" label on the left, "Clear" text-button on the right
 *   2. Code row    — line-number gutter (1..N) + textarea, gap 26px
 *   3. Footer      — 1px horizontal divider, then action row with Execute on the
 *                    left and "Cmd+Enter to execute" hint on the right.
 *
 * The code row uses a transparent textarea layered over a syntax-highlighted
 * <pre>. Scroll position syncs so the highlighted text always tracks the
 * caret.
 */
export function QueryEditor({ query, onChange, onExecute, executing }: QueryEditorProps) {
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const highlightRef = useRef<HTMLPreElement>(null);

  // Cmd/Ctrl+Enter submits the query — matches the Figma hint.
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

  // Keep the highlighted <pre> scroll-aligned with the textarea so the
  // coloured text always lines up with the caret when the user scrolls
  // horizontally in a long-line query.
  const syncScroll = () => {
    const ta = textareaRef.current;
    const pre = highlightRef.current;
    if (!ta || !pre) return;
    pre.scrollTop = ta.scrollTop;
    pre.scrollLeft = ta.scrollLeft;
  };

  // Gutter shows one number per newline-separated line of the current query.
  const lineNumbers = useMemo(() => {
    const count = Math.max(1, query.split("\n").length);
    return Array.from({ length: count }, (_, i) => String(i + 1)).join("\n");
  }, [query]);

  // Tokenize + render highlighted content whenever the query changes.
  const highlighted = useMemo(() => renderHighlighted(query), [query]);

  // Keep the textarea at least 5 rows tall so the panel doesn't collapse on an
  // empty / short query — matches the Figma's 5-line baseline.
  const rows = Math.max(5, query.split("\n").length);

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
        <div className="query-editor-gutter" aria-hidden="true">{lineNumbers}</div>
        {/* Wrap has an explicit pixel height derived from rows × line-height so
            the two absolutely-positioned children (pre + textarea) always have
            a non-zero, well-defined box to paint into. Flow-layout was causing
            the highlight layer to collapse to zero height on some browsers. */}
        <div className="query-textarea-wrap" style={{ height: rows * 19 }}>
          <pre ref={highlightRef} className="query-highlight" aria-hidden="true">
            {highlighted}
          </pre>
          <textarea
            ref={textareaRef}
            className="query-textarea"
            value={query}
            onChange={(e) => onChange(e.target.value)}
            onScroll={syncScroll}
            placeholder={"FROM logs-*\n| WHERE @timestamp > NOW() - 1 hour\n| LIMIT 100"}
            spellCheck={false}
            rows={rows}
            aria-label="ES|QL query"
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
