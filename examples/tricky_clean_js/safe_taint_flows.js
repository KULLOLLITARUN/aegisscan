// The same flows with the standard fix applied to each.
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const escapeHtml = require('escape-html');
const app = require('express')();

app.get('/hello', (req, res) => {
  const name = escapeHtml(req.query.name);
  res.send('Hello ' + name);
});

app.get('/file', (req, res) => {
  const f = path.basename(req.query.file);
  fs.readFile('/srv/files/' + f, (err, data) => res.end(data));
});

app.post('/ping', (req, res) => {
  execFile('ping', ['-c', '1', req.body.host], () => res.end('ok'));
});
