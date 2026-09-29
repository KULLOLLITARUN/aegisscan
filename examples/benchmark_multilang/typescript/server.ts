import express from "express";
import { exec } from "child_process";
import jwt from "jsonwebtoken";
import { Pool } from "pg";

const app = express();
const pool = new Pool();
const JWT_SECRET = "s3cr3t-jwt-signing-key-do-not-share";

app.get("/user", async (req, res) => {
  const rows = await pool.query(`SELECT * FROM users WHERE name = '${req.query.name}'`);
  res.json(rows.rows);
});

app.get("/ping", (req, res) => {
  exec("ping -c 1 " + req.query.host, (err, stdout) => res.send(stdout));
});

app.get("/login", (req, res) => {
  res.cookie("token", jwt.sign({ user: req.query.user }, JWT_SECRET));
  res.redirect(String(req.query.next));
});

app.get("/greet", (req, res) => {
  res.send("<h1>Hello " + req.query.name + "</h1>");
});

app.listen(3000);
