const express = require("express");
const app = express();

app.use(express.json());

// ❌ Hardcoded secret (already vulnerable)
const SECRET_TOKEN = "my-super-secret-token-1234567890";

// ----------------------------
// ❌ 1️⃣ SQL Injection Vulnerability
// ----------------------------
app.get("/user", (req, res) => {
  const username = req.query.username;

  // Simulated raw SQL query (DANGEROUS)
  const query = `SELECT * FROM users WHERE username = '${username}'`;

  console.log("Executing query:", query);

  // Simulated DB result
  res.json({
    message: "Query executed",
    query,
  });
});

// ----------------------------
// ❌ 2️⃣ Cross-Site Scripting (XSS)
// ----------------------------
app.get("/welcome", (req, res) => {
  const name = req.query.name;

  // Directly injecting user input into HTML
  res.send(`
    <h1>Welcome ${name}</h1>
    <p>Glad to see you!</p>
  `);
});

// ----------------------------
// ❌ 3️⃣ Command Injection
// ----------------------------
const { exec } = require("child_process");

app.get("/ping", (req, res) => {
  const host = req.query.host;

  // Dangerous OS command execution
  exec(`ping -c 1 ${host}`, (err, stdout, stderr) => {
    if (err) {
      return res.status(500).send(stderr);
    }
    res.send(stdout);
  });
});

// ----------------------------
// Existing Secure Endpoint (but still hardcoded secret)
// ----------------------------
app.get("/secure", (req, res) => {
  const token = req.headers["x-api-token"];

  if (!SECRET_TOKEN) {
    return res.status(500).json({ error: "Server configuration error" });
  }

  if (token !== SECRET_TOKEN) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  res.json({ message: "Secure data accessed" });
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});
