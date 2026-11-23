// Safe look-alikes for the DOM/SQL/path sinks in vulnerable_js/more_sinks.js. None of these
// may be flagged.
const fs = require('fs');
const path = require('path');
const express = require('express');
const DOMPurify = require('dompurify');

const app = express();
const PUBLIC_DIR = path.join(__dirname, 'public');

function appendComment(list, comment) {
  list.insertAdjacentHTML('beforeend', DOMPurify.sanitize('<li>' + comment.body + '</li>'));
  list.insertAdjacentText('beforeend', comment.body);
}

function showBio(el, user) {
  el.textContent = user.bio;
  el.innerHTML = DOMPurify.sanitize(user.bio);
  el.innerHTML = '';
  $('#bio').text(user.bio);
  $('#banner').html('<b>static</b>');
}

function Post({ post }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(post.content) }} />;
}

function timers(tick, cb) {
  setTimeout(() => tick(), 100);
  setTimeout(cb, 10);
  setInterval(tick, 1000);
}

app.get('/orders', (req, res) => {
  db.query('SELECT * FROM orders WHERE id = ?', [req.query.id], (err, rows) => res.json(rows));
  db.query('SELECT * FROM orders WHERE id = $1', [req.query.id]);
  db.query('SELECT 1');
  db.query(`SELECT count(*) FROM orders`);
});

app.get('/download/:file', (req, res) => {
  res.sendFile(req.params.file, { root: PUBLIC_DIR });
  res.sendFile(path.join(__dirname, 'index.html'));
});

function loadConfig(callback) {
  fs.readFile(path.join(__dirname, 'config.json'), 'utf8', callback);
  return fs.createReadStream(path.join(PUBLIC_DIR, 'logo.png'));
}
