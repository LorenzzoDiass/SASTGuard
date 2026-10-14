// Intentionally vulnerable JavaScript used to exercise the SASTGuard
// Tree-sitter JavaScript scanner. DO NOT use these patterns in real code.
const cp = require("child_process");

function runUserCode(req, res) {
  // SG-JS001: eval() of dynamically built input -> code injection.
  const expr = req.query.expr;
  const result = eval("return " + expr);
  res.send(String(result));
}

function ping(req, res) {
  // SG-JS002: child_process.exec with concatenated user input -> command injection.
  const host = req.query.host;
  cp.exec("ping -c 1 " + host, (err, stdout) => res.send(stdout));
}

function render(req) {
  // SG-JS003: innerHTML assigned dynamic (untrusted) data -> DOM XSS.
  const el = document.getElementById("out");
  el.innerHTML = req.query.comment;
}

function findUser(db, req) {
  // SG-JS004: SQL built by string concatenation -> SQL injection.
  const name = req.query.name;
  return db.query("SELECT * FROM users WHERE name = '" + name + "'");
}

// SG-JS005: hardcoded credential.
const apiKey = "sk_live_8f3kDJ29sldfkj2093sdkfj";

module.exports = { runUserCode, ping, render, findUser, apiKey };
