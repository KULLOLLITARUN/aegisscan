// Look-alikes that must NOT be flagged (precision fixture for the JS/TS optimizer).
const PATTERN = /\w+@\w+\.com/;
const HOISTED = new RegExp("a+b");

async function batch(db, ids) {
  return db.query("SELECT * FROM t WHERE id = ANY($1)", [ids]);
}

function joinParts(rows) {
  const parts = [];
  for (const r of rows) parts.push(String(r));
  return parts.join("\n");
}

function cross(xs, ys) {
  return xs.flatMap((x) => ys.map((y) => [x, y])); // two different collections
}

function total(values) {
  let t = 0;
  for (const v of values) t += v; // numeric +=, not a string
  return t;
}

async function concurrent(ids) {
  return Promise.all(ids.map((id) => fetch(`/api/${id}`))); // concurrent, not serial
}

function lookups(items, cache, session, parser) {
  for (const it of items) {
    cache.get(it);
    session.get("user");
    parser.query(it);
  }
}

function defineInLoop(items) {
  for (const it of items) {
    it.cb = async (c) => c.query("select 1"); // runs later, not per iteration
  }
}

function matches(lines) {
  return lines.filter((l) => PATTERN.test(l) || HOISTED.test(l));
}
