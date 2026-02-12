const express = require("express");
const app = express();
const { execFile } = require("child_process"); // Use execFile for safer command execution

app.use(express.json());

// ✅ Replaced hardcoded secret with process.env.SECRET_TOKEN
const SECRET_TOKEN = process.env.SECRET_TOKEN;

// ----------------------------
// 1️⃣ SQL Injection Vulnerability - FIXED
//
// The original vulnerability would directly concatenate user input into the SQL query string.
// This fix uses a parameterized query pattern, where the query structure is defined separately
// from the user-provided data, preventing malicious SQL from being executed.
// ----------------------------
app.get("/user", (req, res) => {
  const username = req.query.username;

  // Use a parameterized query.
  // In a real application, you would pass these to your database driver
  // (e.g., `db.query('SELECT * FROM users WHERE username = $1', [username])` for PostgreSQL
  // or `db.execute('SELECT * FROM users WHERE username = ?', [username])` for MySQL with mysql2 driver)
  // to prevent SQL injection by separating the query logic from the data.
  const query = "SELECT * FROM users WHERE username = ?"; // Placeholder for username
  const params = [username]; // Parameters to be bound

  console.log("Simulating parameterized query:");
  console.log("SQL:", query);
  console.log("Parameters:", params);

  // Simulated DB result
  res.json({
    message: "Parameterized query simulated successfully",
    query: query,
    parameters: params,
  });
});

// ----------------------------
// 2️⃣ Cross-Site Scripting (XSS) - FIXED
//
// The original vulnerability would directly embed user input into the HTML response
// without proper encoding. This fix introduces an HTML escaping function to convert
// special HTML characters in user input into their entity equivalents, neutralizing
// malicious scripts.
// ----------------------------

// Utility function to escape HTML characters
function escapeHtml(str) {
  if (typeof str !== 'string') {
    return ''; // Handle non-string inputs gracefully
  }
  return str.replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
}

app.get("/welcome", (req, res) => {
  const name = req.query.name;

  // Escape user input before directly injecting into HTML to prevent XSS
  const escapedName = escapeHtml(name);

  res.send(`
    <h1>Welcome ${escapedName}</h1>
    <p>Glad to see you!</p>
  `);
});

// ----------------------------
// 3️⃣ Command Injection - FIXED
//
// The original vulnerability would allow user input to be concatenated into a shell command
// executed via `child_process.exec`, permitting attackers to run arbitrary commands.
// This fix uses `child_process.execFile` which treats arguments as distinct array elements
// and does not invoke a shell by default. Additionally, it includes robust input validation
// to restrict the `host` parameter to valid formats.
// ----------------------------
// child_process.execFile is safer than exec for executing commands
// with user-supplied arguments, as it treats arguments as distinct array elements
// and does not invoke a shell by default.

app.get("/ping", (req, res) => {
  const host = req.query.host;

  // Validate the host input to ensure it's a valid hostname or IP address.
  // This is an essential layer of defense against command injection.
  // For simplicity, a basic regex check is used. A more robust validation
  // might involve a dedicated library or stricter regex/DNS lookup.
  const ipAddressRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  const hostnameRegex = /^[a-zA-Z0-9.-]+$/; // Basic hostname regex

  if (!host || (!ipAddressRegex.test(host) && !hostnameRegex.test(host))) {
    return res.status(400).send("Invalid host specified. Please provide a valid IP address or hostname.");
  }

  // Use execFile, passing the command and arguments as separate elements.
  // This prevents shell metacharacter injection because the arguments are not
  // interpreted by a shell.
  execFile("ping", ["-c", "1", host], (err, stdout, stderr) => {
    if (err) {
      // Log the error for debugging purposes but avoid exposing internal system details to the user.
      console.error(`execFile error for host ${host}:`, err);
      // Return a generic error message, optionally including sanitized stderr if it provides useful info
      return res.status(500).send(`Failed to ping host: ${host}.`);
    }
    // Return the standard output of the ping command.
    res.send(stdout);
  });
});

// ----------------------------
// Existing Secure Endpoint (now uses environment variable for secret)
// ----------------------------
app.get("/secure", (req, res) => {
  const token = req.headers["x-api-token"];

  // Ensure the secret is loaded from the environment variable
  if (!SECRET_TOKEN) {
    console.error("SECRET_TOKEN environment variable not set.");
    return res.status(500).json({ error: "Server configuration error: SECRET_TOKEN missing." });
  }

  if (token !== SECRET_TOKEN) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  res.json({ message: "Secure data accessed" });
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
  console.log("NOTE: Ensure SECRET_TOKEN environment variable is set for the /secure endpoint.");
});