import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  PathTraversalGuard,
  PathTraversalError,
  SafeFileName,
  RouteAccessPolicy,
  AccessGuard,
  AccessDeniedError,
  canonicalizePath,
  UrlGuard,
  SsrfError,
} from '../src/index.js';

test('path guard resolves inside base and rejects traversal', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secure-'));
  const guard = PathTraversalGuard.forBaseDirectory(tmp);
  const p = guard.resolve('reports/2026/q1.pdf');
  assert.ok(p.startsWith(fs.realpathSync.native(tmp)));
  for (const bad of [
    '../secret.txt', 'a/../../secret.txt', '..\\secret.txt', '/etc/passwd', '\\\\server\\share', 'C:\\Windows\\win.ini',
    'C:secret', 'file.txt::$DATA', '%2e%2e/secret', '%2e%2e%2fsecret', '..%c0%afsecret', 'report.pdf\0.png',
    '....//secret', '~/.ssh/id_rsa', '', ' ', '.. /x', '.',
  ]) {
    assert.throws(() => guard.resolve(bad), PathTraversalError, JSON.stringify(bad));
    assert.equal(guard.isSafe(bad), false);
  }
});

test('path guard rejects symlink escape', (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secure-'));
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'outside-'));
  const base = path.join(tmp, 'base');
  fs.mkdirSync(base);
  try {
    fs.symlinkSync(outside, path.join(base, 'link'), 'junction');
  } catch {
    t.skip('symlinks not permitted on this machine');
    return;
  }
  const guard = PathTraversalGuard.forBaseDirectory(base);
  assert.throws(() => guard.resolve('link/file.txt'), PathTraversalError);
});

test('safe file names', () => {
  assert.ok(SafeFileName.isSafe('invoice-2026.pdf'));
  for (const bad of ['../x.pdf', 'CON', 'nul.txt', '.htaccess', 'x.pdf.']) assert.equal(SafeFileName.isSafe(bad), false, bad);
  assert.equal(SafeFileName.sanitize('../../etc/passwd'), 'passwd');
  assert.equal(SafeFileName.sanitize('..\\..\\windows\\win.ini'), 'win.ini');
  assert.equal(SafeFileName.sanitize('CON'), '_CON');
  assert.equal(SafeFileName.sanitize('...'), 'file');
  assert.equal(SafeFileName.sanitize('a<b.png'), 'a_b.png');
});

const alice = { id: 'alice', roles: ['USER'], tenantId: 't1' };
const admin = { id: 'root', roles: new Set(['ADMIN']), tenantId: 't1' };
const policy = new RouteAccessPolicy()
  .permitAll('GET', '/public/**')
  .permitAll('POST', '/login')
  .hasAnyRole('*', '/admin/**', 'ADMIN')
  .authenticated('*', '/api/**');

test('route policy: deny by default and rules apply', () => {
  assert.equal(policy.evaluate('GET', '/internal/metrics', admin).allowed, false);
  assert.equal(policy.evaluate('GET', '/public/logo.png', null).allowed, true);
  assert.equal(policy.evaluate('DELETE', '/public/logo.png', null).allowed, false);
  assert.equal(policy.evaluate('GET', '/api/orders', alice).allowed, true);
  assert.equal(policy.evaluate('GET', '/api/orders', null).unauthenticated, true);
  assert.equal(policy.evaluate('GET', '/admin/users', alice).allowed, false);
  assert.equal(policy.evaluate('GET', '/admin/users', admin).allowed, true);
  assert.equal(policy.evaluate('GET', '/admin', admin).allowed, true);
});

test('route policy: bypass attempts never reach /admin', () => {
  for (const p of [
    '/public/../admin/users', '/public/%2e%2e/admin/users', '//admin/users', '/ADMIN/users', '/Admin/users/',
    '/admin;jsessionid=x/users', '/public/..;/admin/users', '/%61dmin/users', '/public%2f..%2fadmin/users',
    '/public\\..\\admin/users', '/admin/users%00.png', '/public/%252e%252e/admin',
  ]) {
    assert.equal(policy.evaluate('GET', p, alice).allowed, false, p);
  }
  assert.equal(canonicalizePath('//a///b/?x=1'), '/a/b');
  assert.equal(canonicalizePath('/a/../b'), null);
});

test('object-level access checks', () => {
  AccessGuard.requireOwner(alice, 'alice');
  assert.throws(() => AccessGuard.requireOwner(alice, 'bob'), AccessDeniedError);
  assert.throws(() => AccessGuard.requireOwner(alice, null), AccessDeniedError);
  AccessGuard.requireOwnerOrRole(admin, 'bob', 'ADMIN');
  assert.throws(() => AccessGuard.requireSameTenant(alice, 't2'), AccessDeniedError);
  assert.throws(() => AccessGuard.requireAnyRole(null, 'USER'), (e) => e.unauthenticated === true);
  assert.throws(() => AccessGuard.requireNoProtectedFields({ name: 'x', Role: 'ADMIN' }, 'role'), AccessDeniedError);
  assert.throws(() => AccessGuard.requireNoProtectedFields(JSON.parse('{"a":{"__proto__":{"isAdmin":true}}}')), AccessDeniedError);
  AccessGuard.requireNoProtectedFields({ name: 'x', profile: { bio: 'hi' } }, 'role');
});

const fakeDns = async (host) => {
  const table = {
    'public.example': ['93.184.215.14'],
    'rebind.example': ['93.184.215.14', '10.0.0.5'],
    'metadata.example': ['169.254.169.254'],
  };
  if (table[host]) return table[host];
  if (/^[0-9a-f:.]+$/.test(host)) return [host];
  throw new Error('ENOTFOUND');
};

test('SSRF guard allows public and blocks internal targets', async () => {
  const guard = new UrlGuard({ resolver: fakeDns });
  assert.equal((await guard.validate('https://public.example/hook')).port, 443);
  for (const url of [
    'http://127.0.0.1/', 'http://2130706433/', 'http://0x7f.1/', 'http://localhost.invalid/', 'http://10.1.2.3/',
    'http://172.16.0.1/', 'http://192.168.1.1/', 'http://169.254.169.254/latest/meta-data/', 'http://metadata.example/',
    'http://0.0.0.0/', 'http://100.64.0.1/', 'http://[::1]/', 'http://[::ffff:127.0.0.1]/', 'http://[fd00::1]/',
    'http://[fe80::1]/', 'http://[64:ff9b::a00:1]/', 'http://[2002:a00:1::]/', 'http://rebind.example/',
    'file:///etc/passwd', 'gopher://public.example/', 'ftp://public.example/', 'http://user:pass@public.example/',
    'http://public.example:8080/', 'http://public.example\\@evil/', 'http://public.example /', 'javascript:alert(1)',
    'http://224.0.0.1/',
  ]) {
    await assert.rejects(guard.validate(url), SsrfError, url);
  }
});

test('SSRF host allowlist', async () => {
  const guard = new UrlGuard({ resolver: fakeDns, allowHosts: ['*.example'] });
  assert.equal(await guard.isAllowed('https://public.example/'), true);
  assert.equal(await guard.isAllowed('https://93.184.215.14/'), false);
  assert.equal(await guard.isAllowed('https://example/'), false);
});
