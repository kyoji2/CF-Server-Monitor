import test from 'node:test';
import assert from 'node:assert/strict';
import {
  generateToken,
  checkAuth,
  buildAuthCookie,
  DEFAULT_AUTH_EXPIRY_SECONDS,
  getAuthExpirySeconds,
  AUTH_COOKIE_NAME
} from '../src/middleware/auth.js';

test('auth token expiry defaults to 365 days', () => {
  assert.equal(DEFAULT_AUTH_EXPIRY_SECONDS, 365 * 24 * 60 * 60);
  assert.equal(getAuthExpirySeconds({}, {}), 365 * 24 * 60 * 60);
});

test('auth token expiry respects env AUTH_TOKEN_DAYS override', () => {
  assert.equal(getAuthExpirySeconds({ AUTH_TOKEN_DAYS: '30' }, {}), 30 * 86400);
  assert.equal(getAuthExpirySeconds({ JWT_EXPIRY_DAYS: '180' }, {}), 180 * 86400);
  assert.equal(getAuthExpirySeconds({}, { jwt_expiry_days: '90' }), 90 * 86400);
});

test('generateToken signs token with long expiry and checkAuth verifies it', async () => {
  const env = { API_SECRET: 'test_secret_for_token_expiry_12345678' };
  const sys = { jwt_secret: 'x'.repeat(32) };

  const token = await generateToken(env, sys);
  assert.ok(token);

  // 解析 JWT payload 验证 exp 时间约为 365 天后
  const [, payloadBase64] = token.split('.');
  const payload = JSON.parse(Buffer.from(payloadBase64, 'base64').toString());
  const now = Math.floor(Date.now() / 1000);
  const diff = payload.exp - now;

  assert.ok(diff >= 365 * 86400 - 5 && diff <= 365 * 86400 + 5, `Expected ~365 days, got ${diff}s`);

  // 验证 checkAuth 成功通过
  const reqWithBearer = new Request('https://status.example.com/api/servers', {
    headers: { Authorization: `Bearer ${token}` }
  });
  const okBearer = await checkAuth(reqWithBearer, env, sys);
  assert.equal(okBearer, true);

  // 验证 cookie 也支持 365 天 Max-Age
  const cookieHeader = buildAuthCookie(reqWithBearer, token);
  assert.ok(cookieHeader.includes(`Max-Age=${365 * 86400}`));
  assert.ok(cookieHeader.includes(`${AUTH_COOKIE_NAME}=`));

  const reqWithCookie = new Request('https://status.example.com/api/servers', {
    headers: { Cookie: cookieHeader }
  });
  const okCookie = await checkAuth(reqWithCookie, env, sys);
  assert.equal(okCookie, true);
});
