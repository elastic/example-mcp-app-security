/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

import React from "react";

function hashString(str: string): number {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash + str.charCodeAt(i)) | 0;
  }
  return Math.abs(hash);
}

function seededRandom(seed: number): () => number {
  let s = seed;
  return () => {
    s = (s * 16807 + 0) % 2147483647;
    return (s - 1) / 2147483646;
  };
}

const PALETTES = [
  ["#5c7cfa", "#748ffc", "#91a7ff"],
  ["#40c790", "#63dca5", "#96f2d7"],
  ["#f0b840", "#ffd43b", "#ffe066"],
  ["#f04040", "#ff6b6b", "#ffa8a8"],
  ["#b07cfa", "#cc5de8", "#e599f7"],
  ["#20c997", "#38d9a9", "#63e6be"],
  ["#fd7e14", "#ff922b", "#ffa94d"],
  ["#4dabf7", "#74c0fc", "#a5d8ff"],
  ["#e64980", "#f06595", "#faa2c1"],
  ["#845ef7", "#9775fa", "#b197fc"],
];

export function GeneratedAvatar({ name, size = 28 }: { name: string; size?: number }) {
  const hash = hashString(name || "unknown");
  const rand = seededRandom(hash);
  const palette = PALETTES[hash % PALETTES.length];

  const shapes: React.ReactNode[] = [];
  const cellSize = size / 5;

  // Generate a 5x5 symmetric grid (like identicons)
  for (let y = 0; y < 5; y++) {
    for (let x = 0; x < 3; x++) {
      if (rand() > 0.45) {
        const color = palette[Math.floor(rand() * palette.length)];
        const opacity = 0.7 + rand() * 0.3;

        // Left side
        shapes.push(
          <rect key={`${x}-${y}`} x={x * cellSize} y={y * cellSize}
            width={cellSize} height={cellSize}
            fill={color} opacity={opacity} />
        );

        // Mirror right side
        if (x < 2) {
          shapes.push(
            <rect key={`${4 - x}-${y}`} x={(4 - x) * cellSize} y={y * cellSize}
              width={cellSize} height={cellSize}
              fill={color} opacity={opacity} />
          );
        }
      }
    }
  }

  const bgColor = palette[0] + "18";

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}
      style={{ borderRadius: "50%", flexShrink: 0, background: bgColor }}>
      <clipPath id={`clip-${hash}`}>
        <circle cx={size / 2} cy={size / 2} r={size / 2} />
      </clipPath>
      <g clipPath={`url(#clip-${hash})`}>
        <rect width={size} height={size} fill={bgColor} />
        {shapes}
      </g>
    </svg>
  );
}
