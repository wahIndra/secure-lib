import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { ClaimMappings, principalFromVerifiedClaims, getClaim, AccessGuard, AccessDeniedError } from '../src/index.js';
import { idorProbe } from '../src/devtools.js';

// Claim shapes as issued by each provider (decoded, already-verified access tokens).
const KEYCLOAK = {
  sub: 'f1c2a8e0-alice',
  preferred_username: 'alice',
  realm_access: { roles: ['user', 'offline_access'] },
  resource_access: { 'orders-api': { roles: ['order-reader'] }, account: { roles: ['manage-account'] } },
  scope: 'openid profile email',
};

test('Keycloak realm and client roles', () => {
  const p = principalFromVerifiedClaims(KEYCLOAK, ClaimMappings.keycloak({ clientId: 'orders-api' }));
  assert.equal(p.id, 'f1c2a8e0-alice');
  assert.deepEqual([...p.roles], ['user', 'offline_access', 'order-reader']);
  assert.ok(p.permissions.has('email'));
  assert.equal(p.tenantId, null);
  assert.equal(p.roles.has('manage-account'), false, 'roles of other clients are not granted');
  assert.deepEqual([...principalFromVerifiedClaims(KEYCLOAK, ClaimMappings.keycloak()).roles], ['user', 'offline_access']);
  assert.equal(getClaim(p.claims, 'preferred_username'), 'alice');
});

test('Entra ID uses the object id and tenant', () => {
  const p = principalFromVerifiedClaims(
    { sub: 'pairwise-per-app', oid: '7f3c-object-id', tid: 'contoso-tenant', roles: ['Orders.Admin'], scp: 'Orders.Read User.Read' },
    ClaimMappings.entraId(),
  );
  assert.equal(p.id, '7f3c-object-id');
  assert.equal(p.tenantId, 'contoso-tenant');
  assert.ok(p.roles.has('Orders.Admin') && p.permissions.has('Orders.Read'));
});

test('Auth0 namespaced claim, Okta, Cognito, standard and custom', () => {
  const auth0 = principalFromVerifiedClaims(
    { sub: 'auth0|123', 'https://example.com/roles': ['admin'], permissions: ['read:orders'] },
    ClaimMappings.auth0({ rolesClaim: 'https://example.com/roles' }),
  );
  assert.ok(auth0.roles.has('admin') && auth0.permissions.has('read:orders'));
  assert.ok(principalFromVerifiedClaims({ sub: '00u1', groups: ['Admins'] }, ClaimMappings.okta()).roles.has('Admins'));
  assert.ok(principalFromVerifiedClaims({ sub: 'c0g', 'cognito:groups': ['admins'] }, ClaimMappings.cognito()).roles.has('admins'));
  const std = principalFromVerifiedClaims({ sub: 42, roles: 'a, b' });
  assert.equal(std.id, '42');
  assert.deepEqual([...std.roles], ['a', 'b']);
  const org = principalFromVerifiedClaims({ ...KEYCLOAK, org: { id: 'acme' } }, ClaimMappings.keycloak({ clientId: 'orders-api', tenantClaim: 'org.id' }));
  assert.equal(org.tenantId, 'acme');
  assert.equal(principalFromVerifiedClaims({ uid: 'u1' }, ClaimMappings.custom({ idClaim: 'uid' })).id, 'u1');
});

test('missing subject is unauthenticated; prototype keys are never read', () => {
  assert.throws(() => principalFromVerifiedClaims({ preferred_username: 'alice' }, ClaimMappings.keycloak()), (e) => e instanceof AccessDeniedError && e.unauthenticated);
  assert.throws(() => principalFromVerifiedClaims(null), AccessDeniedError);
  assert.equal(getClaim({}, '__proto__.polluted'), undefined);
  assert.equal(getClaim({ a: {} }, 'a.constructor'), undefined);
});

test('IDOR fix end to end: identity from the token, ownership on the object', () => {
  const alice = principalFromVerifiedClaims(KEYCLOAK, ClaimMappings.keycloak({ clientId: 'orders-api' }));
  AccessGuard.requireOwner(alice, 'f1c2a8e0-alice');
  assert.throws(() => AccessGuard.requireOwner(alice, 'b0b-other-user'), AccessDeniedError);
  assert.throws(() => AccessGuard.requireOwnerOrRole(alice, 'b0b-other-user', 'admin'), AccessDeniedError);
  const admin = principalFromVerifiedClaims({ sub: 'root', realm_access: { roles: ['admin'] } }, ClaimMappings.keycloak());
  AccessGuard.requireOwnerOrRole(admin, 'b0b-other-user', 'admin');
});

// ---------------------------------------------------------------- secure idor against a local server

const ALICE_ORDER = '{"id":1,"owner":"alice","email":"alice@shop.test"}';
let server;
let base;
before(async () => {
  server = http.createServer((req, res) => {
    const auth = req.headers.authorization ?? '';
    const user = auth.startsWith('Bearer token-') ? auth.slice('Bearer token-'.length) : null;
    const send = (status, body = '') => { res.writeHead(status); res.end(body); };
    if (req.url === '/vuln/orders/1') return user ? send(200, ALICE_ORDER) : send(401); // logged-in check only
    if (req.url === '/open/orders/1') return send(200, ALICE_ORDER); // no auth at all
    if (req.url === '/safe/orders/1') return !user ? send(401) : user === 'alice' ? send(200, ALICE_ORDER) : send(404);
    if (req.url === '/safe/my-orders') return user ? send(200, `[{"owner":"${user}","email":"${user}@shop.test"}]`) : send(401);
    return send(404);
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => server.close());

const target = (path, extra = {}) => ({
  url: `${base}${path}`,
  owner: { Authorization: 'Bearer token-alice' },
  other: { Authorization: 'Bearer token-bob' },
  ...extra,
});

test('idor: object readable by another user is HIGH', async () => {
  const r = await idorProbe(target('/vuln/orders/1'));
  assert.deepEqual(r.map((x) => [x.as, x.severity]), [['owner', null], ['other user', 'HIGH'], ['no credentials', null]]);
});

test('idor: object readable without login is HIGH twice', async () => {
  const r = await idorProbe(target('/open/orders/1'));
  assert.deepEqual(r.map((x) => x.severity), [null, 'HIGH', 'HIGH']);
});

test('idor: safe endpoint has no findings', async () => {
  assert.deepEqual((await idorProbe(target('/safe/orders/1'))).filter((x) => x.vulnerable), []);
});

test('idor: different body is MEDIUM without a marker and cleared with one', async () => {
  assert.equal((await idorProbe(target('/safe/my-orders')))[1].severity, 'MEDIUM');
  assert.deepEqual((await idorProbe(target('/safe/my-orders', { marker: 'alice@shop.test' }))).filter((x) => x.vulnerable), []);
  assert.equal((await idorProbe(target('/vuln/orders/1', { marker: 'alice@shop.test' })))[1].severity, 'HIGH');
});

test('idor: refuses a bad setup', async () => {
  await assert.rejects(idorProbe({ url: `${base}/safe/orders/1`, owner: { Authorization: 'Bearer token-bob' }, other: { Authorization: 'Bearer token-carol' } }), /owner's request did not succeed/);
  await assert.rejects(idorProbe({ url: `${base}/safe/orders/1`, owner: { Authorization: 'Bearer token-alice' } }), /--as-owner \/ --as-other/);
  await assert.rejects(idorProbe({ url: 'http://93.184.215.14/orders/1', owner: { a: 'b' }, other: { a: 'c' } }), /only targets local\/private/);
});
