/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import tseslint from 'typescript-eslint';
import { requireLicenseHeader } from './lint-license-rule.mjs';

export default tseslint.config(
  {
    ignores: ['dist/**', 'node_modules/**'],
  },
  {
    files: [
      'src/**/*.ts',
      'src/**/*.tsx',
      '*.ts',
      'scripts/**/*.js',
      '*.mjs',
    ],
    languageOptions: {
      parser: tseslint.parser,
    },
    plugins: {
      'local-rules': {
        rules: {
          'require-license-header': requireLicenseHeader,
        },
      },
    },
    rules: {
      'local-rules/require-license-header': 'error',
    },
  },
);
