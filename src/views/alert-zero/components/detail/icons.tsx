/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";

type IconProps = { readonly size?: number };

function Svg({ size = 12, children }: IconProps & { readonly children: React.ReactNode }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {children}
    </svg>
  );
}

export const CaretIcon = ({ open = false, size = 10 }: IconProps & { readonly open?: boolean }) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 10 10"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.5"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
    className="azd-caret"
    style={{ transform: open ? "rotate(90deg)" : "none" }}
  >
    <path d="M3.75 2.5 6.25 5 3.75 7.5" />
  </svg>
);

export const CopyIcon = (p: IconProps) => (
  <Svg {...p}>
    <rect x="5.5" y="5.5" width="8" height="8" rx="1.5" />
    <path d="M10.5 3.5v-.5a1 1 0 0 0-1-1H3.5a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h.5" />
  </Svg>
);

export const CheckIcon = (p: IconProps) => (
  <Svg {...p}>
    <path d="m3 8.5 3 3 7-7" />
  </Svg>
);

export const ExternalIcon = (p: IconProps) => (
  <Svg {...p}>
    <path d="M9 2.5h4.5V7" />
    <path d="M13.5 2.5 7.5 8.5" />
    <path d="M11.5 9.5v3a1 1 0 0 1-1 1h-7a1 1 0 0 1-1-1v-7a1 1 0 0 1 1-1h3" />
  </Svg>
);

export const SparkleIcon = (p: IconProps) => (
  <Svg {...p}>
    <path d="M8 1.5 9.4 6.6 14.5 8 9.4 9.4 8 14.5 6.6 9.4 1.5 8l5.1-1.4z" />
  </Svg>
);

export const BotIcon = (p: IconProps) => (
  <Svg {...p}>
    <rect x="2.5" y="5" width="11" height="8" rx="2" />
    <path d="M8 5V2.5M6 9h.01M10 9h.01" />
  </Svg>
);

export const PaperclipIcon = (p: IconProps) => (
  <Svg {...p}>
    <path d="m13 7.5-5.3 5.3a3 3 0 0 1-4.2-4.2l5.6-5.6a2 2 0 0 1 2.8 2.8L6.3 11.4a1 1 0 0 1-1.4-1.4l5-5" />
  </Svg>
);

export const WarningIcon = (p: IconProps) => (
  <Svg {...p}>
    <path d="M8 2.5 1.5 13.5h13z" />
    <path d="M8 7v3M8 12h.01" />
  </Svg>
);

export const ToolIcon = (p: IconProps) => (
  <Svg {...p}>
    <path d="M10.5 2.5a3 3 0 0 0-2.9 3.8L2.5 11.4a1.4 1.4 0 0 0 2 2l5.2-5.1a3 3 0 0 0 3.8-3.8L11.6 6.4 9.6 4.4l1.9-1.9z" />
  </Svg>
);

export const ThinkIcon = (p: IconProps) => (
  <Svg {...p}>
    <path d="M5.5 13.5h5M6 11.5h4M8 2a4 4 0 0 0-2.5 7.1c.3.3.5.7.5 1.1v.3h4v-.3c0-.4.2-.8.5-1.1A4 4 0 0 0 8 2z" />
  </Svg>
);

export const DotIcon = (p: IconProps) => (
  <Svg {...p}>
    <circle cx="8" cy="8" r="2.5" fill="currentColor" stroke="none" />
  </Svg>
);

export const DownloadIcon = (p: IconProps) => (
  <Svg {...p}>
    <path d="M8 2.5v8M4.5 7 8 10.5 11.5 7M3 13.5h10" />
  </Svg>
);

export const CodeIcon = (p: IconProps) => (
  <Svg {...p}>
    <path d="m5.5 4.5-3 3.5 3 3.5M10.5 4.5l3 3.5-3 3.5" />
  </Svg>
);
