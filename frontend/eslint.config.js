const nextConfig = require('eslint-config-next/core-web-vitals');

module.exports = [
  ...nextConfig,
  {
    rules: {
      // React Compiler rules — set to warn while codebase adopts the patterns
      'react-hooks/static-components': 'warn',
      'react-hooks/set-state-in-effect': 'warn',
      'react-hooks/immutability': 'warn',
      'react-hooks/refs': 'warn',
      'react-hooks/purity': 'warn',
      // Anonymous components in test helpers don't need display names
      'react/display-name': 'warn',
    },
  },
];
