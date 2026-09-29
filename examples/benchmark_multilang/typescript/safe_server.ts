import express from "express";
import { execFile } from "child_process";
import jwt from "jsonwebtoken";
import { Pool } from "pg";

const app = express();
const pool = new Pool();
const JWT_SECRET = process.env.JWT_SECRET ?? "";
const HOST = /^[A-Za-z0-9.-]{1,253}$/;
const ALLOWED_NEXT = new Set(["/", "/dashboard", "/profile"]);

const escapeHtml = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);

app.get("/user", async (req, res) => {
  const rows = await pool.query("SELECT * FROM users WHERE name = $1", [String(req.query.name)]);
  res.json(rows.rows);
});

app.get("/ping", (req, res) => {
  const host = String(req.query.host);
  if (!HOST.test(host)) {
    res.status(400).end();
    return;
  }
  execFile("ping", ["-c", "1", host], (err, stdout) => res.send(escapeHtml(stdout)));
});

app.get("/login", (req, res) => {
  res.cookie("token", jwt.sign({ user: String(req.query.user) }, JWT_SECRET, { expiresIn: "1h" }));
  const next = String(req.query.next);
  res.redirect(ALLOWED_NEXT.has(next) ? next : "/");
});

app.get("/greet", (req, res) => {
  res.send("<h1>Hello " + escapeHtml(String(req.query.name)) + "</h1>");
});

app.listen(3000);
