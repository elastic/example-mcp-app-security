/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useCallback, useRef, useState } from "react";
import classNames from "classnames";
import { ChevronDownIcon } from "../icons/icons";
import { useClickOutside } from "../../hooks/useClickOutside";
import { useSpaces } from "../../hooks/useSpaces";
import { spaceDisplayName } from "../../space-calls";
import type { SpaceSummary } from "../../spaces";
import "../Dropdown/Dropdown.css";

const FALLBACK_AVATAR_COLOR = "#61a2ff";

function initialsOf(space: SpaceSummary): string {
  if (space.initials) return space.initials;
  return space.name
    .split(/[\s-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((w) => w[0]?.toUpperCase())
    .join("");
}

/** Black or white, whichever reads better on a `#rgb` / `#rrggbb` background. */
function avatarTextColor(background: string): string {
  const hex = background.replace(/^#/, "");
  const full = hex.length === 3 ? [...hex].map((c) => c + c).join("") : hex;
  if (!/^[0-9a-f]{6}$/i.test(full)) return "#000";
  const [r, g, b] = [0, 2, 4].map((i) => Number.parseInt(full.slice(i, i + 2), 16));
  return (0.299 * r + 0.587 * g + 0.114 * b) / 255 > 0.55 ? "#000" : "#fff";
}

function SpaceAvatar({ space }: { space: SpaceSummary }) {
  const background = space.color ?? FALLBACK_AVATAR_COLOR;
  return (
    <span
      className="app-header-space-avatar"
      style={{ background, color: avatarTextColor(background) }}
      aria-hidden="true"
    >
      {initialsOf(space)}
    </span>
  );
}

/**
 * Kibana space pill for the app header. Lets the analyst view another space
 * for this session and switch back to the configured one. Renders nothing
 * unless the API key can access at least two spaces.
 */
export function SpaceControl() {
  const { configured, active, spaces, setActiveSpace } = useSpaces();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement | null>(null);
  const close = useCallback(() => setOpen(false), []);
  useClickOutside(ref, open, close);

  if (spaces.length < 2) return null;

  const current = spaces.find((s) => s.id === active) ?? { id: active, name: active };
  const configuredName = spaceDisplayName(spaces, configured);
  const viewingOther = active !== configured;

  return (
    <div
      ref={ref}
      className={classNames("app-header-space", { "app-header-space-viewing": viewingOther })}
      title={
        viewingOther
          ? `Viewing ${current.name} for this session. Your configured space is ${configuredName}.`
          : `Kibana space: ${current.name} (${current.id})`
      }
    >
      <button
        type="button"
        className="app-header-space-trigger"
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label={`Kibana space: ${current.name}`}
      >
        <SpaceAvatar space={current} />
        <span className="app-header-space-label">{viewingOther ? "Viewing" : "Space"}</span>
        <span className="app-header-space-name">{current.name}</span>
        <ChevronDownIcon open={open} />
      </button>
      {viewingOther && (
        <button
          type="button"
          className="app-header-space-back"
          onClick={() => void setActiveSpace(configured)}
        >
          <span aria-hidden="true">↩</span> Back to {configuredName}
        </button>
      )}
      {open && (
        <div className="dropdown-menu app-header-space-menu" role="listbox" aria-label="Kibana spaces">
          {spaces.map((space) => (
            <button
              key={space.id}
              type="button"
              role="option"
              aria-selected={space.id === active}
              className={classNames("dropdown-option", "app-header-space-option", {
                active: space.id === active,
              })}
              onClick={() => {
                setOpen(false);
                void setActiveSpace(space.id);
              }}
            >
              <SpaceAvatar space={space} />
              <span className="app-header-space-option-name">{space.name}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
