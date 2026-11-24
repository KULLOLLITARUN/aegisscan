// A request value reaches a sink through a variable, not in one expression.
const fs = require('fs');
const { exec } = require('child_process');
const app = require('express')();

app.get('/hello', (req, res) => {
  const name = req.query.name;
  res.send('Hello ' + name);
});

app.get('/file', (req, res) => {
  const f = req.query.file;
  fs.readFile('/srv/files/' + f, (err, data) => res.end(data));
});

app.post('/ping', (req, res) => {
  const host = req.body.host;
  exec('ping -c 1 ' + host, () => res.end('ok'));
});
