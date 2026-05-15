#!/usr/bin/env bash
# Publish @identities-ai/ratify-protocol to npm
# Run: npm login --scope=@identities-ai (one-time)
# Then: ./publish.sh

set -euo pipefail

echo "Building..."
npm run build

echo "Checking dist..."
ls dist/index.js dist/index.d.ts

echo "Publishing @identities-ai/ratify-protocol@$(node -p "require('./package.json').version")..."
VERSION=$(node -p "require('./package.json').version")
if [[ "$VERSION" == *"-"* ]]; then
  TAG=$(echo "$VERSION" | sed 's/.*-\([a-zA-Z]*\).*/\1/')
  npm publish --access public --tag "$TAG"
else
  npm publish --access public
fi

echo "Done. Verify at: https://www.npmjs.com/package/@identities-ai/ratify-protocol"
