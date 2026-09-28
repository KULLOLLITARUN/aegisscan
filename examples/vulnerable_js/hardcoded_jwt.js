/**
 * AegisScan JS/TS Vulnerability Benchmark Suite
 * Category: Hardcoded secrets, JWT signing, API keys, credentials
 *
 * This file contains INTENTIONALLY VULNERABLE code for testing purposes.
 * DO NOT deploy to production.
 */

const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// ── 1. Hardcoded JWT secret key ──────────────────────────────────────────────
const JWT_SECRET = 'super_secret_jwt_key_do_not_share_2024!';  // VULNERABILITY: hardcoded secret

function signUserToken(userId, role) {
  return jwt.sign({ userId, role }, JWT_SECRET, { expiresIn: '7d' });
}

function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET);
}

// ── 2. Hardcoded database credentials ────────────────────────────────────────
const DB_CONFIG = {
  host: 'prod-db.internal.company.com',
  port: 5432,
  user: 'admin',
  password: 'P@ssw0rd_Prod_2024',  // VULNERABILITY: hardcoded password
  database: 'production_db',
};

// ── 3. Hardcoded AWS keys ─────────────────────────────────────────────────────
const AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';        // VULNERABILITY: AWS key ID
const AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';  // VULNERABILITY

// ── 4. Hardcoded API keys ─────────────────────────────────────────────────────
const config = {
  stripe_api_key: 'sk_live_51ABC123DEF456GHI789JKL',   // VULNERABILITY: live Stripe key
  sendgrid_key:   'SG.xxxxxxxxxxxxxxxxxxxxxxxx.xxxxxxx', // VULNERABILITY: SendGrid key
  github_token:   'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',  // VULNERABILITY: GitHub PAT
};

// ── 5. Weak cryptography ──────────────────────────────────────────────────────
function hashPassword(password) {
  // VULNERABILITY: MD5 is cryptographically broken — use bcrypt/argon2
  return crypto.createHash('md5').update(password).digest('hex');
}

function encryptData(data) {
  // VULNERABILITY: ECB mode doesn't provide semantic security
  const cipher = crypto.createCipheriv('aes-128-ecb', Buffer.from('0000000000000000'), null);
  return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}

// ── 6. Insecure random for security tokens ────────────────────────────────────
function generatePasswordResetToken() {
  // VULNERABILITY: Math.random() is not cryptographically secure
  return Math.random().toString(36).substring(2, 15);
}

// ── 7. Predictable CSRF token ─────────────────────────────────────────────────
function generateCsrfToken(userId) {
  // VULNERABILITY: CSRF token is predictable based on userId + timestamp
  return Buffer.from(`${userId}-${Date.now()}`).toString('base64');
}

module.exports = { signUserToken, verifyToken, hashPassword, generatePasswordResetToken };
