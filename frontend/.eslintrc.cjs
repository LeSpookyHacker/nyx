/* ESLint 8 (eslintrc) configuration for the Nyx dashboard. */
module.exports = {
  root: true,
  env: { browser: true, es2020: true },
  parser: '@typescript-eslint/parser',
  parserOptions: { ecmaVersion: 'latest', sourceType: 'module', ecmaFeatures: { jsx: true } },
  plugins: ['@typescript-eslint', 'react', 'react-hooks'],
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:react-hooks/recommended',
  ],
  settings: { react: { version: 'detect' } },
  ignorePatterns: ['dist', 'node_modules', '.eslintrc.cjs'],
  rules: {
    // Every dangerouslySetInnerHTML must carry an explicit, reviewed eslint-disable
    // (e.g. MarkdownContent sanitises with DOMPurify first). With --max-warnings 0
    // an unreviewed new use fails lint.
    'react/no-danger': 'warn',
  },
}
