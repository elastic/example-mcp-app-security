/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

const licenseHeader = `/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */`;

function normalizeWhitespace(string) {
  return string.replace(/\s+/g, ' ');
}

function isHashbang(text) {
  return text.trim().startsWith('#!') && !text.trim().includes('\n');
}

export const requireLicenseHeader = {
  meta: {
    type: 'problem',
    fixable: 'code',
    schema: [],
  },
  create(context) {
    return {
      Program() {
        const sourceCode = context.sourceCode;
        const comments = sourceCode.getAllComments();

        const licenseComment = comments.find(
          (node) =>
            node.type === 'Block' &&
            normalizeWhitespace(node.value) ===
              normalizeWhitespace(licenseHeader.replace(/^\/\*/, '').replace(/\*\/$/, ''))
        );

        if (!licenseComment) {
          context.report({
            message: 'File must start with a license header',
            loc: {
              start: { line: 1, column: 0 },
              end: { line: 1, column: sourceCode.lines[0].length - 1 },
            },
            fix(fixer) {
              if (isHashbang(sourceCode.lines[0])) {
                return fixer.replaceTextRange(
                  [sourceCode.lines[0].length, sourceCode.lines[0].length],
                  '\n' + licenseHeader + '\n'
                );
              }
              return fixer.replaceTextRange([0, 0], licenseHeader + '\n\n');
            },
          });
          return;
        }

        const sourceBeforeNode = sourceCode
          .getText()
          .slice(0, sourceCode.getIndexFromLoc(licenseComment.loc.start));
        if (sourceBeforeNode.length && !isHashbang(sourceBeforeNode)) {
          context.report({
            node: licenseComment,
            message: 'License header must be at the very beginning of the file',
            fix(fixer) {
              if (sourceBeforeNode.trim() === '') {
                return fixer.replaceTextRange([0, sourceBeforeNode.length], '');
              }
              return [
                fixer.remove(licenseComment),
                fixer.replaceTextRange([0, 0], licenseHeader + '\n\n'),
              ];
            },
          });
        }
      },
    };
  },
};
