/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

export type LogMessage = string | (() => string) | Error;

export interface Logger {
  debug(message: LogMessage): void;
  info(message: LogMessage): void;
  warn(message: LogMessage): void;
  error(message: LogMessage): void;
  child(context: string): Logger;
  get(...context: string[]): Logger;
}

function messageToString(message: LogMessage): string {
  if (message instanceof Error) {
    return message.stack ?? message.message;
  }
  return typeof message === "function" ? message() : message;
}

function formatLine(context: readonly string[], message: LogMessage): string {
  const prefix = context.length > 0 ? `[${context.join(":")}] ` : "";
  return `${prefix}${messageToString(message)}\n`;
}

export function createStderrLogger(context: readonly string[] = []): Logger {
  return {
    debug(message): void {
      process.stderr.write(formatLine(context, message));
    },
    info(message): void {
      process.stderr.write(formatLine(context, message));
    },
    warn(message): void {
      process.stderr.write(formatLine(context, message));
    },
    error(message): void {
      process.stderr.write(formatLine(context, message));
    },
    child(childContext): Logger {
      return createStderrLogger([...context, childContext]);
    },
    get(...childContext): Logger {
      return createStderrLogger([...context, ...childContext]);
    },
  };
}
