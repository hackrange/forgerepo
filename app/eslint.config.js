// Lint rules for ForgeRepo. Starts as warnings on purpose, the refactor phases pay them down.
// Author: Tim Rice

const js = require('@eslint/js');
const globals = require('globals');

module.exports = [
  {
    ignores: ['node_modules/**', 'test/**']
  },
  js.configs.recommended,
  {
    files: ['src/**/*.js'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'commonjs',
      globals: { ...globals.node }
    },
    rules: {
      // never, not even once
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      // the logger does redaction, console doesn't
      'no-console': 'warn',
      'no-empty': ['warn', { allowEmptyCatch: false }],
      'no-unused-vars': ['warn', { args: 'after-used', caughtErrors: 'none', ignoreRestSiblings: true }],
      eqeqeq: ['warn', 'always', { null: 'ignore' }],
      'prefer-const': 'warn',
      'no-var': 'warn',
      'max-lines': ['warn', { max: 500, skipBlankLines: true, skipComments: true }]
    }
  },
  {
    files: ['src/healthcheck.js', 'src/migrate-db.js'],
    rules: { 'no-console': 'off' }
  },
  {
    files: ['public/**/*.js'],
    languageOptions: {
      ecmaVersion: 2020,
      sourceType: 'module',
      globals: { ...globals.browser }
    },
    rules: {
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-unused-vars': ['warn', { args: 'after-used', caughtErrors: 'none' }],
      eqeqeq: ['warn', 'always', { null: 'ignore' }],
      'max-lines': ['warn', { max: 800, skipBlankLines: true, skipComments: true }]
    }
  }
];
