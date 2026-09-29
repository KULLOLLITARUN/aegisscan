// Intentional performance problems: benchmark fixture for the JS/TS optimizer.
async function loadOrders(db, userIds) {
  const orders = [];
  for (const uid of userIds) { // N+1: one query per user
    const rows = await db.query("SELECT * FROM orders WHERE user_id = $1", [uid]);
    orders.push(...rows);
  }
  return orders;
}

async function loadUsers(ids) {
  const users = [];
  for (const id of ids) { // N+1 via an ORM
    users.push(await User.findById(id));
  }
  return users;
}

async function fetchProfiles(ids) {
  const out = [];
  for (const id of ids) { // serial network round trips
    out.push(await fetch(`/api/users/${id}`));
  }
  return out;
}

function buildReport(rows) {
  let out = "";
  for (const row of rows) { // quadratic string building
    out += String(row) + "\n";
  }
  return out;
}

function findDuplicates(items) {
  const dupes = [];
  for (const a of items) {
    for (const b of items) { // O(n^2)
      if (a !== b && a === b) dupes.push(a);
    }
  }
  return dupes;
}

function countEmails(lines) {
  let n = 0;
  for (const line of lines) {
    if (new RegExp("\w+@\w+\.com").test(line)) n++; // recompiled every pass
  }
  return n;
}
