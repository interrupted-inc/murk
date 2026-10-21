// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from 'node:assert'
import { execFileSync, spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { add, exportAll, get, hasIdentity, load } from '../index.js'

// Find the murk binary.
const murkBin = join(process.cwd(), '..', 'target', 'release', 'murk')

// Run the murk binary directly with an argv array (no shell), so command
// arguments can never be reinterpreted as shell syntax.
const PATH_WITH_TARGET = `${join(process.cwd(), '..', 'target', 'release')}:${process.env.PATH}`

// murk keeps keys and trust pins under HOME: never touch the real one. The
// binding reads HOME from this process's environment, the binary inherits it.
const testHome = mkdtempSync(join(tmpdir(), 'murk-node-home-'))
process.env.HOME = testHome

function runMurk(dir, args, input = '', extraEnv = {}) {
  return execFileSync(murkBin, args, {
    cwd: dir,
    input,
    env: { ...process.env, PATH: PATH_WITH_TARGET, ...extraEnv },
    stdio: ['pipe', 'pipe', 'pipe'],
  })
}

// Read the operator key murk init wrote to .env (inline MURK_KEY or a key file).
function readKeyFromDotenv(dir) {
  const dotenv = readFileSync(join(dir, '.env'), 'utf8')
  for (const line of dotenv.split('\n')) {
    if (line.startsWith('export MURK_KEY_FILE=')) {
      const keyFile = line
        .split('=')[1]
        .trim()
        .replace(/^['"]|['"]$/g, '')
      return readFileSync(keyFile, 'utf8').trim()
    }
    if (line.startsWith('export MURK_KEY=')) {
      return line
        .split('=')[1]
        .trim()
        .replace(/^['"]|['"]$/g, '')
    }
  }
  throw new Error('could not find MURK_KEY in .env')
}

function setupVault() {
  const dir = mkdtempSync(join(tmpdir(), 'murk-node-test-'))

  runMurk(dir, ['init', '--vault', '.murk'], 'testuser\n')
  const murkKey = readKeyFromDotenv(dir)

  const keyEnv = { MURK_KEY: murkKey }
  runMurk(dir, ['add', 'DATABASE_URL', '--vault', '.murk'], 'postgres://localhost/mydb\n', keyEnv)
  runMurk(dir, ['add', 'API_KEY', '--vault', '.murk'], 'sk-test-123\n', keyEnv)
  runMurk(dir, ['add', 'STRIPE_SECRET', '--vault', '.murk'], 'sk_live_abc\n', keyEnv)
  // A group the operator belongs to, so the write API's group tier has a
  // destination to encrypt to.
  runMurk(dir, ['group', 'create', 'backend', '--vault', '.murk'], '', keyEnv)

  return { dir, murkKey }
}

// Build a vault with an agent policy and a granted agent identity, so we can
// prove the bindings enforce the same policy the CLI applies at `agent exec`.
function setupAgentVault() {
  const dir = mkdtempSync(join(tmpdir(), 'murk-node-agent-'))

  runMurk(dir, ['init', '--vault', '.murk'], 'agentowner\n')
  const opKey = readKeyFromDotenv(dir)

  const opEnv = { MURK_KEY: opKey }
  runMurk(dir, ['add', 'AGENT_DB', '--vault', '.murk'], 'postgres://agent\n', opEnv)
  runMurk(dir, ['add', 'PROD_DB', '--vault', '.murk'], 'postgres://prod\n', opEnv)
  runMurk(
    dir,
    ['describe', 'AGENT_DB', 'agent db', '--tag', 'agents', '--vault', '.murk'],
    '',
    opEnv,
  )
  runMurk(dir, ['describe', 'PROD_DB', 'prod db', '--tag', 'prod', '--vault', '.murk'], '', opEnv)
  runMurk(dir, ['policy', 'set', '--allow-tag', 'agents', '--vault', '.murk'], '', opEnv)
  runMurk(
    dir,
    [
      'agent',
      'grant',
      '--name',
      'codex',
      '--only',
      'AGENT_DB',
      '--out',
      'agent.key',
      '--vault',
      '.murk',
    ],
    '',
    opEnv,
  )
  const agentKey = readFileSync(join(dir, 'agent.key'), 'utf8').trim()

  // Tightening the policy to drop the `agents` tag leaves the agent's scoped
  // ciphertext in place — the crypto still works, but policy should now refuse.
  const tightenPolicy = () =>
    runMurk(dir, ['policy', 'set', '--allow-tag', 'prod', '--vault', '.murk'], '', opEnv)

  return { dir, opKey, agentKey, tightenPolicy }
}

let testDir, testKey

// Setup
console.log('Setting up test vault...')
const setup = setupVault()
testDir = setup.dir
testKey = setup.murkKey
process.env.MURK_KEY = testKey
process.chdir(testDir)

// Tests
let passed = 0
let failed = 0

function test(name, fn) {
  try {
    fn()
    console.log(`  ✓ ${name}`)
    passed++
  } catch (e) {
    console.log(`  ✗ ${name}: ${e.message}`)
    failed++
  }
}

console.log('\nRunning tests...\n')

test('load returns a vault', () => {
  const vault = load()
  assert.ok(vault)
})

test('load with explicit path', () => {
  const vault = load(join(testDir, '.murk'))
  assert.ok(vault)
})

test('vault.get returns correct value', () => {
  const vault = load()
  assert.strictEqual(vault.get('DATABASE_URL'), 'postgres://localhost/mydb')
  assert.strictEqual(vault.get('API_KEY'), 'sk-test-123')
})

test('vault.get returns null for missing key', () => {
  const vault = load()
  assert.strictEqual(vault.get('NONEXISTENT'), null)
})

test('vault.export returns all secrets', () => {
  const vault = load()
  const secrets = vault.export()
  assert.strictEqual(secrets.DATABASE_URL, 'postgres://localhost/mydb')
  assert.strictEqual(secrets.API_KEY, 'sk-test-123')
  assert.strictEqual(secrets.STRIPE_SECRET, 'sk_live_abc')
  assert.strictEqual(Object.keys(secrets).length, 3)
})

test('vault.keys returns all key names', () => {
  const vault = load()
  const keys = vault.keys().sort()
  assert.deepStrictEqual(keys, ['API_KEY', 'DATABASE_URL', 'STRIPE_SECRET'])
})

test('vault.length returns count', () => {
  const vault = load()
  assert.strictEqual(vault.length, 3)
})

test('vault.has returns true for existing key', () => {
  const vault = load()
  assert.strictEqual(vault.has('DATABASE_URL'), true)
  assert.strictEqual(vault.has('NONEXISTENT'), false)
})

test('get one-liner works', () => {
  assert.strictEqual(get('DATABASE_URL'), 'postgres://localhost/mydb')
})

test('get one-liner returns null for missing', () => {
  assert.strictEqual(get('NONEXISTENT'), null)
})

test('exportAll one-liner works', () => {
  const secrets = exportAll()
  assert.strictEqual(Object.keys(secrets).length, 3)
})

test('hasIdentity returns true when key set', () => {
  assert.strictEqual(hasIdentity(), true)
})

test('load with missing vault throws', () => {
  assert.throws(() => load('/nonexistent/.murk'))
})

// Write API. Each add is a full read-modify-write against the on-disk vault, so
// every assertion re-loads from disk to prove the value actually persisted.
test('vault.add stores a shared (everyone) secret', () => {
  const vault = load()
  vault.add('SHARED_TOKEN', 'shared-value')
  // Persisted to disk, readable by a fresh operator load.
  assert.strictEqual(get('SHARED_TOKEN'), 'shared-value')
  // The handle refreshes its own snapshot too.
  assert.strictEqual(vault.get('SHARED_TOKEN'), 'shared-value')
})

test('vault.add with desc and tags records schema metadata', () => {
  const vault = load()
  vault.add('TAGGED_TOKEN', 'tagged-value', {
    desc: 'a tagged token',
    tags: ['agents'],
  })
  assert.strictEqual(get('TAGGED_TOKEN'), 'tagged-value')
  assert.strictEqual(load().has('TAGGED_TOKEN'), true)
})

test('vault.add stores a personal (me) scoped secret', () => {
  const vault = load()
  vault.add('PERSONAL', 'my-value', { tier: 'me' })
  // The scoped value takes priority for the caller.
  assert.strictEqual(get('PERSONAL'), 'my-value')
})

test('vault.add stores a group secret the operator can read back', () => {
  const vault = load()
  vault.add('GROUP_SECRET', 'group-value', { tier: 'backend' })
  assert.strictEqual(get('GROUP_SECRET'), 'group-value')
})

// Tier aliases mirror the CLI's resolve_secret_tier table. A mapping
// regression would route an alias into the named-group arm, where these
// reserved words name no group and the add throws 'group not found'.
test("tier aliases 'all' and 'shared' route to the everyone tier", () => {
  const vault = load()
  vault.add('ALIAS_ALL', 'alias-all-value', { tier: 'all' })
  vault.add('ALIAS_SHARED', 'alias-shared-value', { tier: 'shared' })
  assert.strictEqual(get('ALIAS_ALL'), 'alias-all-value')
  assert.strictEqual(get('ALIAS_SHARED'), 'alias-shared-value')
})

test("tier aliases 'self' and 'mine' route to the me tier", () => {
  const vault = load()
  vault.add('ALIAS_SELF', 'alias-self-value', { tier: 'self' })
  vault.add('ALIAS_MINE', 'alias-mine-value', { tier: 'mine' })
  assert.strictEqual(get('ALIAS_SELF'), 'alias-self-value')
  assert.strictEqual(get('ALIAS_MINE'), 'alias-mine-value')
})

test('vault.add to a nonexistent group throws', () => {
  const vault = load()
  assert.throws(() => vault.add('NOPE', 'x', { tier: 'no-such-group' }), /group not found/)
})

test('vault.add rejects an invalid key name', () => {
  const vault = load()
  assert.throws(() => vault.add('1BAD', 'x'), /invalid key name/)
})

test('add one-liner stores a secret', () => {
  add('ONELINER', 'oneliner-value')
  assert.strictEqual(get('ONELINER'), 'oneliner-value')
})

test('vault.describe documents a key without a value', () => {
  const vault = load()
  vault.describe('DOCUMENTED', 'documented but unset', { tags: ['agents'] })
  const reloaded = load()
  assert.strictEqual(reloaded.has('DOCUMENTED'), true)
  assert.strictEqual(reloaded.get('DOCUMENTED'), null)
})

// Agent policy enforcement: a granted agent identity is gated by the vault's
// policy from the binding, just like the CLI gates it at `agent exec`.
console.log('\nSetting up agent policy vault...')
const agent = setupAgentVault()
const agentVault = join(agent.dir, '.murk')

test('agent reads an in-scope, policy-allowed key', () => {
  process.env.MURK_KEY = agent.agentKey
  assert.strictEqual(get('AGENT_DB', agentVault), 'postgres://agent')
})

test('agent cannot decrypt an out-of-scope key (crypto boundary)', () => {
  process.env.MURK_KEY = agent.agentKey
  assert.strictEqual(get('PROD_DB', agentVault), null)
})

test('agent export returns only its scoped, allowed keys', () => {
  process.env.MURK_KEY = agent.agentKey
  const secrets = load(agentVault).export()
  assert.deepStrictEqual(Object.keys(secrets), ['AGENT_DB'])
  assert.strictEqual(secrets.AGENT_DB, 'postgres://agent')
})

// Write path: a granted agent can't write at all, whatever the key or tier, and
// the vault on disk is left byte-identical.
test('agent add and describe are refused and leave the vault unchanged', () => {
  const before = readFileSync(agentVault)
  process.env.MURK_KEY = agent.agentKey
  const readOnly = /agent grants are read-only/
  const writes = [
    ['AGENT_WRITE', { tier: 'me', tags: ['agents'] }],
    ['AGENT_WRITE', { tier: 'everyone', tags: ['agents'] }],
    ['EXFIL', { tags: ['prod'] }],
  ]
  for (const [key, opts] of writes) {
    assert.throws(() => add(key, 'agent-authored', opts, agentVault), readOnly)
  }
  assert.throws(
    () => load(agentVault).describe('AGENT_DB', 'changed', { tags: ['agents'] }),
    readOnly,
  )
  assert.deepStrictEqual(readFileSync(agentVault), before)
  // Reads still work for the agent.
  assert.strictEqual(get('AGENT_DB', agentVault), 'postgres://agent')
})

test('an expired grant key is refused by the binding', () => {
  runMurk(
    agent.dir,
    [
      'agent',
      'grant',
      '--name',
      'short',
      '--only',
      'AGENT_DB',
      '--ttl',
      '1s',
      '--out',
      'short.key',
      '--vault',
      '.murk',
    ],
    '',
    { MURK_KEY: agent.opKey },
  )
  const shortKey = readFileSync(join(agent.dir, 'short.key'), 'utf8')
  assert.match(shortKey, /^# murk-trusted-signer: /)
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1100)
  process.env.MURK_KEY = shortKey
  assert.throws(() => get('AGENT_DB', agentVault), /grant short expired/)
})

test('tightening the policy retroactively blocks the agent get', () => {
  agent.tightenPolicy()
  process.env.MURK_KEY = agent.agentKey
  assert.throws(() => get('AGENT_DB', agentVault), /policy forbids/)
})

test('tightening the policy retroactively blocks the agent export', () => {
  process.env.MURK_KEY = agent.agentKey
  assert.throws(() => load(agentVault).export(), /policy forbids/)
})

// ── Trust: the binding applies the CLI's rules ──
//
// One HOME per person (the trust pin lives under HOME). Each scenario checks
// that the binding accepts or refuses exactly as `murk get` does, with the
// same message, and that a refusal is an error with code 'MURK_TRUST'.

const CONTEXT_VARS = [
  'MURK_KEY',
  'MURK_KEY_FILE',
  'MURK_VAULT',
  'MURK_AGENT',
  'MURK_STRICT',
  'MURK_NO_SIGNER_PIN',
  'MURK_TRUSTED_SIGNERS',
  'CI',
]

function person(base, name) {
  const home = join(base, `${name}-home`)
  mkdirSync(home)
  const env = (extra) => {
    const e = { ...process.env, PATH: PATH_WITH_TARGET, HOME: home, NO_COLOR: '1' }
    for (const v of CONTEXT_VARS) delete e[v]
    return { ...e, ...extra }
  }
  const keyFile = () => {
    const dir = join(home, '.config', 'murk', 'keys')
    return join(dir, readdirSync(dir)[0])
  }
  return {
    home,
    keyFile,
    murk: (dir, args, input = '', extra = {}) =>
      execFileSync(murkBin, args, { cwd: dir, input, env: env(extra), stdio: 'pipe' }).toString(),
    // The CLI's exit status and output, for a command expected to fail.
    attempt: (dir, args, extra = {}) =>
      spawnSync(murkBin, args, { cwd: dir, env: env(extra), encoding: 'utf8' }),
    // This person's trusted-signer entry (`age1…:<verifying key>`).
    signerEntry: (dir) =>
      execFileSync(murkBin, ['trust', '--print-key'], {
        cwd: dir,
        env: env({ MURK_KEY_FILE: keyFile() }),
        stdio: 'pipe',
      })
        .toString()
        .trim(),
  }
}

// Run `fn` with the binding acting as `who` in `repo`: their HOME plus `extra`.
function as(who, repo, extra, fn) {
  const saved = { ...process.env }
  const cwd = process.cwd()
  for (const v of CONTEXT_VARS) delete process.env[v]
  Object.assign(process.env, { HOME: who.home }, extra)
  process.chdir(repo)
  try {
    return fn()
  } finally {
    for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k]
    Object.assign(process.env, saved)
    process.chdir(cwd)
  }
}

function refusal(fn = () => load()) {
  try {
    fn()
  } catch (e) {
    assert.strictEqual(e.code, 'MURK_TRUST', e.message)
    return e.message
  }
  assert.fail('expected the vault to be refused')
}

// The CLI refused with this exact message: its first line, then hints.
function assertSameAsCli(message, cli) {
  const [first, ...rest] = message.split('\n')
  assert.notStrictEqual(cli.status, 0)
  assert.strictEqual(cli.stdout, '')
  assert.strictEqual(cli.stderr, `✕ ${first}\n${rest.map((h) => `  hint ${h}\n`).join('')}`)
}

const trustBases = []

// Alice's repo, a signed vault holding DB_URL=prod-db, pinned on her machine.
function aliceRepo() {
  const base = mkdtempSync(join(tmpdir(), 'murk-node-trust-'))
  trustBases.push(base)
  const alice = person(base, 'alice')
  const repo = join(base, 'repo')
  mkdirSync(repo)
  execFileSync('git', ['init', '-q', '-b', 'main'], { cwd: repo })
  alice.murk(repo, ['init'], 'alice\n')
  alice.murk(repo, ['add', 'DB_URL'], 'prod-db\n')
  const alicePk = alice.signerEntry(repo).split(':')[0]
  return { base, alice, alicePk, repo }
}

// Mallory's own vault, listing Alice as a recipient, signed by Mallory.
function malloryVault(base, alicePk) {
  const mallory = person(base, 'mallory')
  const forge = join(base, 'forge')
  mkdirSync(forge)
  mallory.murk(forge, ['init'], 'mallory\n')
  mallory.murk(forge, ['circle', 'authorize', alicePk, '--name', 'alice'])
  mallory.murk(forge, ['add', 'DB_URL'], 'postgres://attacker\n')
  return join(forge, '.murk')
}

function plant(forged, repo, { stripSignature = false } = {}) {
  const vault = JSON.parse(readFileSync(forged, 'utf8'))
  if (stripSignature) delete vault.sig
  writeFileSync(join(repo, '.murk'), JSON.stringify(vault, null, 2))
}

test('a forged unsigned vault is refused like the CLI refuses it', () => {
  const { base, alice, alicePk, repo } = aliceRepo()
  plant(malloryVault(base, alicePk), repo, { stripSignature: true })
  const laptop = person(base, 'alice-laptop')
  const keyEnv = { MURK_KEY_FILE: alice.keyFile() }

  const message = as(laptop, repo, keyEnv, () => {
    refusal(() => get('DB_URL'))
    refusal(() => exportAll())
    return refusal()
  })

  assert.match(message, /is unsigned/)
  assertSameAsCli(message, laptop.attempt(repo, ['get', 'DB_URL'], keyEnv))
})

test('a self-enrolled signer is refused on a pinned machine, reads and writes', () => {
  const { base, alice, alicePk, repo } = aliceRepo()
  plant(malloryVault(base, alicePk), repo)
  const planted = readFileSync(join(repo, '.murk'))
  const pins = join(alice.home, '.config', 'murk', 'signer-pins')
  const pinState = () => readdirSync(pins).map((f) => [f, readFileSync(join(pins, f), 'utf8')])
  const before = pinState()
  const keyEnv = { MURK_KEY_FILE: alice.keyFile() }

  const message = as(alice, repo, keyEnv, () => {
    refusal(() => add('NEW_SECRET', 'for-alice-only'))
    return refusal()
  })

  assert.match(message, /not a trusted signer/)
  assert.deepStrictEqual(pinState(), before)
  assert.deepStrictEqual(readFileSync(join(repo, '.murk')), planted)
  assertSameAsCli(message, alice.attempt(repo, ['get', 'DB_URL'], keyEnv))
})

test('a vault is accepted after the trust step', () => {
  const { base, alice, repo } = aliceRepo()
  const laptop = person(base, 'alice-laptop')
  const keyEnv = { MURK_KEY_FILE: alice.keyFile() }

  const message = as(laptop, repo, keyEnv, () => refusal())
  assert.match(message, /not trusted on this machine yet/)

  laptop.murk(repo, ['trust', '--yes'], '', keyEnv)
  const vault = as(laptop, repo, keyEnv, () => load())
  assert.strictEqual(vault.get('DB_URL'), 'prod-db')
  assert.deepStrictEqual(vault.warnings, [])
})

function grantKey(alice, repo) {
  alice.murk(repo, ['agent', 'grant', '--name', 'ci', '--only', 'DB_URL', '--out', 'agent.key'])
  return readFileSync(join(repo, 'agent.key'), 'utf8')
}

test('a grant reads through its key-file anchor', () => {
  const { base, alice, repo } = aliceRepo()
  const key = grantKey(alice, repo)
  assert.match(key, /^# murk-trusted-signer: /)
  const runner = person(base, 'runner')

  assert.strictEqual(
    as(runner, repo, { MURK_KEY: key }, () => get('DB_URL')),
    'prod-db',
  )
  // A grant never touches the pin.
  assert.deepStrictEqual(readdirSync(runner.home), [])
})

test('a grant without its anchor is refused with the re-mint message', () => {
  const { base, alice, repo } = aliceRepo()
  const bare = grantKey(alice, repo)
    .split('\n')
    .filter((line) => !line.startsWith('#'))
    .join('\n')
  const runner = person(base, 'runner')

  const message = as(runner, repo, { MURK_KEY: bare }, () => refusal())

  assert.match(message, /re-mint the grant/)
  assertSameAsCli(message, runner.attempt(repo, ['get', 'DB_URL'], { MURK_KEY: bare }))
  // MURK_TRUSTED_SIGNERS is the other anchor a grant can use.
  const signers = { MURK_KEY: bare, MURK_TRUSTED_SIGNERS: alice.signerEntry(repo) }
  assert.strictEqual(
    as(runner, repo, signers, () => get('DB_URL')),
    'prod-db',
  )
})

const hasSshKeygen = spawnSync('ssh-keygen', ['-?']).error === undefined
test('an unsigned vault read by a key that cannot sign carries the CLI warning', () => {
  if (!hasSshKeygen) return
  const { base, alice, repo } = aliceRepo()
  const rsa = join(base, 'rsa')
  execFileSync('ssh-keygen', ['-q', '-t', 'rsa', '-b', '2048', '-N', '', '-f', rsa])
  const rsaPub = readFileSync(`${rsa}.pub`, 'utf8').split(' ').slice(0, 2).join(' ')
  alice.murk(repo, ['circle', 'authorize', rsaPub, '--name', 'rsa-dev', '--allow-ssh-rsa'])
  const dev = person(base, 'rsa-dev')
  const rsaEnv = { MURK_KEY_FILE: rsa }
  dev.murk(repo, ['trust', '--yes'], '', rsaEnv)
  dev.murk(repo, ['add', 'DB_URL'], 'from-rsa\n', rsaEnv)

  const vault = as(dev, repo, rsaEnv, () => load())

  assert.strictEqual(vault.get('DB_URL'), 'from-rsa')
  assert.strictEqual(vault.warnings.length, 1)
  assert.match(vault.warnings[0], /vault is unsigned and your key cannot sign/)
  const cli = dev.attempt(repo, ['get', 'DB_URL'], rsaEnv)
  assert.ok(cli.stderr.includes(vault.warnings[0]), cli.stderr)
  // On Alice's machine the same vault is a stripped signature: refused.
  const message = as(alice, repo, { MURK_KEY_FILE: alice.keyFile() }, () => refusal())
  assert.match(message, /is now unsigned/)
})

// Cleanup
rmSync(testDir, { recursive: true, force: true })
rmSync(agent.dir, { recursive: true, force: true })
for (const base of trustBases) rmSync(base, { recursive: true, force: true })
rmSync(testHome, { recursive: true, force: true })

console.log(`\n${passed} passed, ${failed} failed`)
if (failed > 0) process.exit(1)
