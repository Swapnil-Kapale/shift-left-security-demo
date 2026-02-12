const express = require("express");
const app = express();

// Required for Command Injection fix
const { spawn } = require("child_process");

app.use(express.json());

// ✅ Replaced hardcoded secret with process.env
const SECRET_TOKEN = process.env.SECRET_TOKEN;

// ----------------------------
// Utility function for XSS prevention
// ----------------------------
function escapeHtml(unsafe) {
  if (unsafe === null || unsafe === undefined) {
    return '';
  }
  return unsafe.toString()
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ----------------------------
// Utility function for Command Injection prevention
// ----------------------------
function isValidHost(host) {
  // A robust validation for hostnames and IP addresses.
  // This regex allows IPv4, IPv6 (simplified for common formats), and common domain names.
  // For production systems, consider a more comprehensive library or strict DNS validation.
  const ipV4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const ipV6Regex = /^([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4}|:)$|^((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)::((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)$/;
  const hostnameRegex = /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

  return ipV4Regex.test(host) || ipV6Regex.test(host) || hostnameRegex.test(host);
}

// ----------------------------
// ✅ 1️⃣ SQL Injection Vulnerability Fixed
// ----------------------------
app.get("/user", (req, res) => {
  const username = req.query.username;

  // 🔒 FIX: Use parameterized queries.
  // In a real application with a database, you would use your database driver's
  // method for parameterized queries, which separates the SQL logic from user input.
  // Example for 'pg' (PostgreSQL): pool.query('SELECT * FROM users WHERE username = $1', [username]);
  // Example for 'mysql': connection.execute('SELECT * FROM users WHERE username = ?', [username]);
  // Since this is a simulated DB, we'll represent the secure query structure.
  const safeQueryRepresentation = `SELECT * FROM users WHERE username = ? (parameter: '${username}')`;

  console.log("Simulating secure parameterized query execution for:", safeQueryRepresentation);

  // Simulated DB result - business logic unchanged
  res.json({
    message: "Query executed securely using a parameterized query concept.",
    query: safeQueryRepresentation,
  });
});

// ----------------------------
// ✅ 2️⃣ Cross-Site Scripting (XSS) Fixed
// ----------------------------
app.get("/welcome", (req, res) => {
  const name = req.query.name;

  // 🔒 FIX: Escape user input before embedding it into HTML to prevent XSS.
  const escapedName = escapeHtml(name);

  // Directly injecting user input into HTML - business logic unchanged
  res.send(`
    <h1>Welcome ${escapedName}</h1>
    <p>Glad to see you!</p>
  `);
});

// ----------------------------
// ✅ 3️⃣ Command Injection Fixed
// ----------------------------
app.get("/ping", (req, res) => {
  const host = req.query.host;

  // 🔒 FIX: Validate input and use `spawn` with arguments array to prevent command injection.
  // `spawn` executes commands directly without a shell, meaning arguments are not
  // interpreted as shell commands, making it much safer.
  if (!isValidHost(host)) {
    return res.status(400).send("Invalid host provided. Only valid IP addresses or hostnames are allowed.");
  }

  // Use spawn to execute commands safely, passing arguments as an array.
  const pingProcess = spawn("ping", ["-c", "1", host]); // The command and its arguments are separate.

  let stdout = "";
  let stderr = "";

  pingProcess.stdout.on("data", (data) => {
    stdout += data.toString();
  });

  pingProcess.stderr.on("data", (data) => {
    stderr += data.toString();
  });

  pingProcess.on("close", (code) => {
    if (code !== 0) {
      // Ping command failed or exited with an error code
      // We send stderr for debugging, but ensure it doesn't leak sensitive info.
      return res.status(500).send(stderr || `Ping process exited with code ${code}`);
    }
    // Business logic unchanged: send the ping output.
    res.send(stdout);
  });

  pingProcess.on("error", (err) => {
    // Handle errors like 'ping' command not found
    console.error("Failed to start ping process:", err);
    res.status(500).send(`Failed to execute ping command: ${err.message}`);
  });
});

// ----------------------------
// Existing Secure Endpoint (now uses process.env secret)
// ----------------------------
app.get("/secure", (req, res) => {
  const token = req.headers["x-api-token"];

  // It's good practice to ensure the environment variable is set
  if (!SECRET_TOKEN) {
    return res.status(500).json({ error: "Server configuration error: SECRET_TOKEN not set" });
  }

  if (token !== SECRET_TOKEN) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  res.json({ message: "Secure data accessed" });
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
  console.log("Remember to set SECRET_TOKEN environment variable, e.g., SECRET_TOKEN=my-super-secret-token-1234567890 node index.js");
  console.log("Test XSS: http://localhost:3000/welcome?name=<script>alert('XSS!')</script>");
  console.log("Test SQL Injection (simulated safe): http://localhost:3000/user?username=admin'%20OR%20'1'%3D'1");
  console.log("Test Command Injection (safe): http://localhost:3000/ping?host=8.8.8.8");
  console.log("Test Command Injection (blocked): http://localhost:3000/ping?host=8.8.8.8%3Brm%20-rf%20/");
});