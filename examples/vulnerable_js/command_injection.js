/**
 * AegisScan JS/TS Vulnerability Benchmark Suite
 * Category: Command injection, path traversal, insecure deserialization
 *
 * This file contains INTENTIONALLY VULNERABLE code for testing purposes.
 * DO NOT deploy to production.
 */

const { exec, execSync, spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

// ── 1. Command injection via exec() ──────────────────────────────────────────
function convertImage(filename) {
  // VULNERABILITY: User-controlled filename passed to shell command
  exec(`convert ${filename} output.png`, (err, stdout, stderr) => {
    if (err) console.error(stderr);
  });
}

// ── 2. Command injection via execSync() ──────────────────────────────────────
function getFileInfo(userPath) {
  // VULNERABILITY: Direct interpolation — attacker can add "; rm -rf /"
  const output = execSync(`ls -la ${userPath}`);
  return output.toString();
}

// ── 3. Path traversal ────────────────────────────────────────────────────────
function readUserFile(username, filename) {
  // VULNERABILITY: No path normalization allows "../../../etc/passwd"
  const filePath = path.join('/app/users', username, filename);
  return fs.readFileSync(filePath, 'utf8');
}

// ── 4. Argument injection via spawn() ────────────────────────────────────────
function runGitCommand(repoPath, branch) {
  // VULNERABILITY: branch could be "--upload-pack=/bin/sh" (git flag injection)
  return spawn('git', ['clone', repoPath, '--branch', branch]);
}

// ── 5. Server-side template injection via template literals ──────────────────
function renderTemplate(templateStr, userVars) {
  // VULNERABILITY: new Function() allows arbitrary code execution
  const fn = new Function(...Object.keys(userVars), `return \`${templateStr}\``);
  return fn(...Object.values(userVars));
}

// ── 6. Insecure deserialization ───────────────────────────────────────────────
const serialize = require('serialize-javascript');

function deserializeUserState(serialized) {
  // VULNERABILITY: eval-based deserialization is RCE risk
  return eval('(' + serialized + ')');
}

// ── 7. Open redirect ─────────────────────────────────────────────────────────
function redirectUser(req, res) {
  const destination = req.query.next;
  // VULNERABILITY: Unvalidated redirect — attacker sends users to phishing sites
  res.redirect(destination);
}

// ── 8. XML external entity injection (XXE) ───────────────────────────────────
const xml2js = require('xml2js');

function parseXMLConfig(xmlInput) {
  // VULNERABILITY: Parser configured to process external entities
  const parser = new xml2js.Parser({ allowDtd: true });
  return parser.parseStringPromise(xmlInput);
}

module.exports = { convertImage, getFileInfo, readUserFile, renderTemplate, redirectUser };
