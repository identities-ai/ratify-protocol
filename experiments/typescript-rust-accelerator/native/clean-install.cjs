const { execFileSync } = require('node:child_process')
const { mkdtempSync, readdirSync } = require('node:fs')
const { tmpdir } = require('node:os')
const { join, resolve } = require('node:path')

const packageDir = __dirname
const outputDir = mkdtempSync(join(tmpdir(), 'ratify-node-pack-'))
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm'
const npmOptions = (cwd, stdio) => ({ cwd, stdio, shell: process.platform === 'win32' })
execFileSync(npm, ['pack', '--pack-destination', outputDir], npmOptions(packageDir, 'inherit'))
const tarball = join(outputDir, readdirSync(outputDir).find((name) => name.endsWith('.tgz')))
const consumer = mkdtempSync(join(tmpdir(), 'ratify-node-consumer-'))
execFileSync(npm, ['init', '-y'], npmOptions(consumer, 'ignore'))
execFileSync(npm, ['install', '--ignore-scripts', tarball], npmOptions(consumer, 'inherit'))
const installed = require.resolve('ratify-node-rust-accelerator-experiment', { paths: [consumer] })
const native = require(installed)
if (typeof native.verifyBundleJsonAsync !== 'function') throw new Error('async native export missing')
native.verifyBundleJsonAsync('{}', '{}').then(
  () => { throw new Error('malformed bundle unexpectedly accepted') },
  () => console.log(`clean_install_ok ${resolve(installed)}`),
)
