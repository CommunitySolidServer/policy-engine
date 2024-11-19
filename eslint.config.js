const opinionated = require('opinionated-eslint-config');

module.exports = opinionated({
  // Don't want to lint test assets, or TS snippets in markdown files
  ignores: [ '**/*.md' ],
  typescript: {
    tsconfigPath: [ './tsconfig.json', './scripts/tsconfig.json', './test/tsconfig.json' ],
  },
});
