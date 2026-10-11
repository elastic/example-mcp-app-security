/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";
import type { ResolvedUser } from "../../../../shared/alert-zero-types";
import { avatarColor, userDisplayName, userInitials } from "./list-model";

const MAX_AVATARS = 3;

export interface AssigneeAvatarsProps {
  readonly assignees: readonly ResolvedUser[];
}

export function AssigneeAvatars({ assignees }: AssigneeAvatarsProps) {
  if (assignees.length === 0) {
    return <span className="az-assignees az-assignees--none">Unassigned</span>;
  }
  const shown = assignees.slice(0, MAX_AVATARS);
  const extra = assignees.length - shown.length;
  const label = `Assigned to ${assignees.map(userDisplayName).join(", ")}`;
  return (
    <span className="az-assignees" role="img" aria-label={label} title={label}>
      {shown.map((user) => (
        <span
          key={user.uid}
          className="az-avatar"
          style={{ background: avatarColor(user.uid) }}
          aria-hidden="true"
        >
          {userInitials(user)}
        </span>
      ))}
      {extra > 0 && (
        <span className="az-avatar az-avatar--more" aria-hidden="true">
          +{extra}
        </span>
      )}
    </span>
  );
}
