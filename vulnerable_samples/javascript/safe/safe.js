// Safe JavaScript equivalents. The SASTGuard JavaScript scanner must NOT raise
// SG-JS001..SG-JS005 for any of these patterns.
const cp = require("child_process");

function runUserCode(req, res) {
  // Safe: no eval. Parse structured data instead of executing a string.
  const data = JSON.parse(req.body);
  res.json(data);
}

function constantEval() {
  // Constant-literal eval argument is not treated as injection (lower risk;
  // the scanner only flags dynamically built eval arguments). Still, we avoid
  // eval entirely in real code.
  return 2 + 2;
}

function ping(req, res) {
  // Safe: execFile with an argument array, no shell string building.
  const host = req.query.host;
  cp.execFile("ping", ["-c", "1", host], (err, stdout) => res.send(stdout));
}

function render(req) {
  // Safe: textContent does not parse HTML, so no XSS.
  const el = document.getElementById("out");
  el.textContent = req.query.comment;
}

function regexExec(input) {
  // Safe: RegExp.exec is unrelated to child_process and must not be flagged.
  const re = /\d+/;
  return re.exec(input);
}

function findUser(db, req) {
  // Safe: parameterized query with bound placeholders.
  const name = req.query.name;
  return db.query("SELECT * FROM users WHERE name = ?", [name]);
}

// Safe: secret read from the environment, not hardcoded.
const apiKey = process.env.API_KEY;

module.exports = { runUserCode, constantEval, ping, render, regexExec, findUser, apiKey };
