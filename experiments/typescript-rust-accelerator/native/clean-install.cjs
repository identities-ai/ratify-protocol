const { execFileSync } = require('node:child_process')
const { mkdtempSync, readdirSync } = require('node:fs')
const { tmpdir } = require('node:os')
const { join, resolve } = require('node:path')

const packageDir = __dirname
const outputDir = mkdtempSync(join(tmpdir(), 'ratify-node-pack-'))
execFileSync('npm', ['pack', '--pack-destination', outputDir], { cwd: packageDir, stdio: 'inherit' })
const tarball = join(outputDir, readdirSync(outputDir).find((name) => name.endsWith('.tgz')))
const consumer = mkdtempSync(join(tmpdir(), 'ratify-node-consumer-'))
execFileSync('npm', ['init', '-y'], { cwd: consumer, stdio: 'ignore' })
execFileSync('npm', ['install', '--ignore-scripts', tarball], { cwd: consumer, stdio: 'inherit' })
const installed = require.resolve('ratify-node-rust-accelerator-experiment', { paths: [consumer] })
const native = require(installed)
if (typeof native.verifyBundleJsonAsync !== 'function') throw new Error('async native export missing')
native.verifyBundleJsonAsync('{}', '{}').then(
  () => { throw new Error('malformed bundle unexpectedly accepted') },
  () => console.log(`clean_install_ok ${resolve(installed)}`),
)
