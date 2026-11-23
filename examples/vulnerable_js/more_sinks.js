/**
 * AegisScan JS Vulnerability Benchmark Suite
 * Category: more DOM/XSS sinks, string-built SQL, path traversal in Express handlers
 *
 * This file contains INTENTIONALLY VULNERABLE code for testing purposes.
 * DO NOT deploy to production.
 */
const fs = require('fs');
const path = require('path');
const express = require('express');
const mysql = require('mysql');

const app = express();
const db = mysql.createConnection({ host: 'localhost' });
const UPLOAD_DIR = '/srv/uploads';

// ── 1. insertAdjacentHTML with untrusted markup ──────────────────────────────
function appendComment(list, comment) {
  // VULNERABILITY: comment.body is attacker-controlled HTML
  list.insertAdjacentHTML('beforeend', '<li>' + comment.body + '</li>');
}

// ── 2. jQuery .html() with untrusted data ────────────────────────────────────
function showBio(user) {
  // VULNERABILITY: user.bio is rendered as HTML
  $('#bio').html(user.bio);
}

// ── 3. React dangerouslySetInnerHTML ─────────────────────────────────────────
function Post({ post }) {
  // VULNERABILITY: post.content is untrusted markup
  return <div dangerouslySetInnerHTML={{ __html: post.content }} />;
}

// ── 4. setInterval with a code string ────────────────────────────────────────
function pollWidget(widgetId) {
  // VULNERABILITY: string argument is evaluated like eval()
  setInterval(`refresh('${widgetId}')`, 5000);
}

// ── 5. SQL built by concatenation ────────────────────────────────────────────
app.get('/orders', (req, res) => {
  // VULNERABILITY: req.query.id concatenated into SQL
  db.query('SELECT * FROM orders WHERE id = ' + req.query.id, (err, rows) => res.json(rows));
});

// ── 6. SQL built with a template literal ─────────────────────────────────────
app.delete('/orders/:id', (req, res) => {
  // VULNERABILITY: req.params.id interpolated into SQL
  db.query(`DELETE FROM orders WHERE id = ${req.params.id}`, () => res.sendStatus(204));
});

// ── 7. sendFile with a user-controlled path ──────────────────────────────────
app.get('/download/:file', (req, res) => {
  // VULNERABILITY: no root option, so ../ escapes the directory
  res.sendFile(req.params.file);
});

// ── 8. readFile with a user-controlled path ──────────────────────────────────
app.get('/report', (req, res) => {
  // VULNERABILITY: ../ in req.query.name escapes UPLOAD_DIR
  fs.readFile(path.join(UPLOAD_DIR, req.query.name), 'utf8', (err, data) => res.send(data));
});

// ── 9. createReadStream with a concatenated path ─────────────────────────────
app.get('/stream/:name', (req, res) => {
  // VULNERABILITY: concatenated user input in a file path
  fs.createReadStream('./uploads/' + req.params.name).pipe(res);
});

module.exports = { appendComment, showBio, Post, pollWidget };
