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
npm publish --access public

echo "Done. Verify at: https://www.npmjs.com/package/@identities-ai/ratify-protocol"
