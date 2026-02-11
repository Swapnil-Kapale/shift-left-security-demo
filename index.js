const express = require("express");
const app = express();
const { exec } = require("child_process"); // Keep exec for the ping endpoint

app.use(express.json());

// ✅ Replaced hardcoded secret with environment variable
const SECRET_TOKEN = process.env.SECRET_TOKEN;

// ----------------------------
// Helper function for XSS protection
// Escapes HTML entities in a string to prevent XSS attacks.
// It's recommended to use a battle-tested library like 'escape-html' or 'dompurify'
// in a production environment. This is a basic implementation for demonstration.
// ----------------------------
function escapeHtml(text) {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return text.replace(/[&<>"']/g, function(m) { return map[m]; });
}

// ----------------------------
// Helper for Command Injection protection
// Regex to validate a hostname or IPv4 address.
// This helps prevent malicious commands from being injected.
// ----------------------------
const isValidHost = (host) => {
  // Regex for a valid hostname (e.g., example.com, sub.domain.co.uk) or an IPv4 address.
  // This is a basic validation; more robust validation might be needed depending on requirements.
  const hostnameRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$/;
  const ipv4Regex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  return hostnameRegex.test(host) || ipv4Regex.test(host);
};


// ----------------------------
// ✅ 1️⃣ SQL Injection Vulnerability - FIXED
//    Uses a parameterized query approach (simulated here as there's no actual DB connection).
// ----------------------------
app.get("/user", (req, res) => {
  const username = req.query.username;

  // IMPORTANT: In a real application, you would use a database driver's
  // parameterized query features (e.g., 'pg' for PostgreSQL, 'mysql2' for MySQL).
  // This example *simulates* a parameterized query to demonstrate the concept
  // without needing an actual database connection.
  const query = `SELECT * FROM users WHERE username = ?`; // Use a placeholder
  const params = [username]; // Pass parameters separately

  console.log("Simulating parameterized query:", query, "with parameters:", params);

  // Simulated DB result
  res.json({
    message: "Query executed safely (simulated parameterized query)",
    query,
    params,
  });
});

// ----------------------------
// ✅ 2️⃣ Cross-Site Scripting (XSS) - FIXED
//    Escapes user input before injecting it into HTML.
// ----------------------------
app.get("/welcome", (req, res) => {
  const name = req.query.name;

  // Escape the user-provided 'name' to prevent XSS
  const escapedName = escapeHtml(name);

  // Injecting escaped user input into HTML
  res.send(`
    <h1>Welcome ${escapedName}</h1>
    <p>Glad to see you!</p>
  `);
});

// ----------------------------
// ✅ 3️⃣ Command Injection - FIXED
//    Validates user input ('host') before executing the command.
// ----------------------------
app.get("/ping", (req, res) => {
  const host = req.query.host;

  // Validate the host input to prevent command injection
  if (!isValidHost(host)) {
    return res.status(400).send("Invalid host provided. Please use a valid hostname or IP address.");
  }

  // Safe OS command execution:
  // The input 'host' is now validated, significantly reducing command injection risk.
  // For further security, consider using 'child_process.spawn' with an array of arguments
  // if you need to pass multiple, complex user-controlled inputs.
  exec(`ping -c 1 ${host}`, (err, stdout, stderr) => {
    if (err) {
      // Check if it's a specific error for ping (e.g., host not found) or a system error
      // and tailor the response accordingly. For simplicity, returning stderr.
      const status = stderr.includes("unknown host") || stderr.includes("Name or service not known") ? 404 : 500;
      return res.status(status).send(`Error: ${stderr}`);
    }
    res.send(stdout);
  });
});

// ----------------------------
// Existing Secure Endpoint (now properly using environment variable for secret)
// ----------------------------
app.get("/secure", (req, res) => {
  const token = req.headers["x-api-token"];

  // It's good practice to ensure the environment variable is actually set
  if (!SECRET_TOKEN) {
    return res.status(500).json({ error: "Server configuration error: SECRET_TOKEN is not set" });
  }

  if (token !== SECRET_TOKEN) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  res.json({ message: "Secure data accessed" });
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
  console.log("Remember to set SECRET_TOKEN environment variable, e.g., SECRET_TOKEN=my-super-secret-token-1234567890 node index.js");
});