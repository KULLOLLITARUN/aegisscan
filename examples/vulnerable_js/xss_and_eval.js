/**
 * AegisScan JS/TS Vulnerability Benchmark Suite
 * Category: XSS, eval(), vm.runInNewContext(), DOM injection
 *
 * This file contains INTENTIONALLY VULNERABLE code for testing purposes.
 * DO NOT deploy to production.
 */

// ── 1. DOM XSS via innerHTML ─────────────────────────────────────────────────
function renderUserProfile(userId) {
  const userData = fetchUserData(userId);  // assume returns { name: "...", bio: "..." }
  // VULNERABILITY: Direct assignment to innerHTML without sanitization
  document.getElementById('profile').innerHTML = userData.bio;
}

// ── 2. eval() with user-controlled input ─────────────────────────────────────
function runCalculation(expression) {
  // VULNERABILITY: eval() executes arbitrary JS from user input
  return eval(expression);
}

// ── 3. setTimeout with string argument ───────────────────────────────────────
function scheduleAction(userCode, delay) {
  // VULNERABILITY: setTimeout with string arg behaves like eval()
  setTimeout(userCode, delay);
}

// ── 4. document.write() ──────────────────────────────────────────────────────
function displaySearchResults(query) {
  // VULNERABILITY: document.write() with unsanitized query string
  document.write('<h2>Results for: ' + query + '</h2>');
}

// ── 5. vm.runInNewContext() ───────────────────────────────────────────────────
const vm = require('vm');

function executeTemplate(templateCode, userContext) {
  // VULNERABILITY: vm.runInNewContext is not a security boundary
  return vm.runInNewContext(templateCode, userContext, { timeout: 1000 });
}

// ── 6. innerText bypass attempt (still XSS risk in old browsers) ─────────────
function setUserName(name) {
  // Attempt to avoid XSS with innerText but context-dependent risk remains
  document.querySelector('.username').innerText = name;
  // But also does this:
  document.querySelector('.username-link').href = '/user/' + name;  // VULNERABILITY: href injection
}

// ── 7. JSON.parse without try/catch + prototype pollution ────────────────────
function mergeConfig(baseConfig, userInput) {
  const parsed = JSON.parse(userInput);
  // VULNERABILITY: Recursive merge without prototype pollution protection
  for (const key in parsed) {
    baseConfig[key] = parsed[key];
  }
  return baseConfig;
}

// ── 8. postMessage without origin check ──────────────────────────────────────
window.addEventListener('message', function(event) {
  // VULNERABILITY: No origin validation — accepts messages from any domain
  const data = event.data;
  document.getElementById('content').innerHTML = data.html;
});

module.exports = { renderUserProfile, runCalculation, scheduleAction, executeTemplate };
