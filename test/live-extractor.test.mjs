// Containment flags for the live extractor, unit-tested without invoking a
// model. These assert the invocation we build, not the CLI's behavior — the
// redteam harness exercises the real thing.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { buildExtractorInvocation, scrubbedEnv } from '../src/live-extractor.mjs';

function flagValue(args, flag) {
  const i = args.indexOf(flag);
  return i === -1 ? undefined : args[i + 1];
}

test('x1. no built-in tools exist: --tools is present and empty', () => {
  const { args } = buildExtractorInvocation({});
  assert.equal(flagValue(args, '--tools'), '');
});

test('x2. MCP is strictly disabled regardless of host configuration', () => {
  const { args } = buildExtractorInvocation({});
  assert.ok(args.includes('--strict-mcp-config'));
  assert.deepEqual(JSON.parse(flagValue(args, '--mcp-config')), { mcpServers: {} });
});

test('x3. no settings sources load: host hooks/plugins/permissions never apply', () => {
  const { args } = buildExtractorInvocation({});
  assert.equal(flagValue(args, '--setting-sources'), '');
});

test('x4. one-shot: --print with no session resumption flags', () => {
  const { args } = buildExtractorInvocation({});
  assert.ok(args.includes('--print'));
  assert.ok(!args.includes('--resume'));
  assert.ok(!args.includes('--continue'));
});

test('x5. env scrub drops secrets and forwards only shell plumbing', () => {
  const env = scrubbedEnv({
    PATH: '/usr/bin',
    HOME: '/Users/x',
    ANTHROPIC_API_KEY: 'sk-secret',
    AWS_SECRET_ACCESS_KEY: 'aws-secret',
    GITHUB_TOKEN: 'gh-secret',
    DATABASE_URL: 'postgres://…',
  });
  assert.equal(env.PATH, '/usr/bin');
  assert.equal(env.HOME, '/Users/x');
  assert.equal(env.ANTHROPIC_API_KEY, undefined);
  assert.equal(env.AWS_SECRET_ACCESS_KEY, undefined);
  assert.equal(env.GITHUB_TOKEN, undefined);
  assert.equal(env.DATABASE_URL, undefined);
});
