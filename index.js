const express = require("express");
const app = express();
const { exec } = require("child_process"); // Moved up for better scope

app.use(express.json());

// ✅ Replaced hardcoded secret with process.env.SECRET_NAME
const SECRET_TOKEN = process.env.API_SECRET_TOKEN;

// ----------------------------
// Utility functions for security fixes
// ----------------------------

/**
 * Escapes HTML entities in a string to prevent Cross-Site Scripting (XSS).
 * Replaces characters like <, >, &, ", ' with their corresponding HTML entities.
 * @param {string} str The string to escape.
 * @returns {string} The HTML-escaped string.
 */
function escapeHtml(str) {
  if (typeof str !== 'string') {
    return ''; // Handle non-string inputs gracefully to avoid errors
  }
  return str.replace(/[&<>"']/g, function(match) {
    switch (match) {
      case '&': return '&amp;';
      case '<': return '&lt;';
      case '>': return '&gt;';
      case '"': return '&quot;';
      case "'": return '&#x27;'; // or &#039; for apostrophe
      default: return match; // Should not happen with the regex
    }
  });
}

/**
 * Validates if a string is a safe hostname or IPv4 address, preventing command injection.
 * It restricts characters to common hostname/IP address components and disallows shell metacharacters.
 * @param {string} hostname The string to validate.
 * @returns {boolean} True if the hostname is valid and safe, false otherwise.
 */
function isValidHostname(hostname) {
  if (typeof hostname !== 'string' || hostname.length === 0) {
    return false;
  }

  // Regex for a standard hostname (alphanumeric, hyphens, dots)
  // This helps prevent common shell injection characters like `&`, `|`, `;`, `(`, `)`, etc.
  const hostnameRegex = /^[a-zA-Z0-9.-]+$/;

  // Regex for a valid IPv4 address
  const ipV4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

  // Check if it matches either a safe hostname pattern or a valid IPv4 pattern
  return hostnameRegex.test(hostname) || ipV4Regex.test(hostname);
}


// ----------------------------
// ❌ 1️⃣ SQL Injection Vulnerability (Business logic unchanged)
// ----------------------------
app.get("/user", (req, res) => {
  const username = req.query.username;

  // --- FIX: Use parameterized queries (simulated for demonstration) ---
  // In a real application, you would use a database driver's specific method
  // which safely separates the query structure from the user-provided data.
  // Example for a real DB client: `db.query('SELECT * FROM users WHERE username = ?', [username])`
  const queryTemplate = "SELECT * FROM users WHERE username = ?"; // The parameterized query string
  const queryParams = [username]; // The parameters passed separately

  console.log("Simulating parameterized query execution:");
  console.log("Query template:", queryTemplate);
  console.log("Parameters:", queryParams);

  // Simulated DB result - business logic unchanged: still returns a message and the query representation
  res.json({
    message: "Query executed (using parameterized query concept to prevent SQL injection)",
    query: queryTemplate, // Return the query template
    parameters: queryParams, // Show the parameters separately
  });
});

// ----------------------------
// ❌ 2️⃣ Cross-Site Scripting (XSS) (Business logic unchanged)
// ----------------------------
app.get("/welcome", (req, res) => {
  const name = req.query.name;

  // --- FIX: Escape user input before embedding it into HTML ---
  const escapedName = escapeHtml(name);

  // Directly injecting user input into HTML (now escaped)
  res.send(`
    <h1>Welcome ${escapedName}</h1>
    <p>Glad to see you!</p>
  `);
});

// ----------------------------
// ❌ 3️⃣ Command Injection (Business logic unchanged)
// ----------------------------
app.get("/ping", (req, res) => {
  const host = req.query.host;

  // --- FIX: Validate user input string to prevent command injection ---
  if (!isValidHostname(host)) {
    return res.status(400).send("Invalid host format. Only alphanumeric characters, hyphens, and dots are allowed for hostnames/IPs.");
  }

  // Safe OS command execution (after strict validation)
  // Even with validation, for critical operations, prefer `child_process.spawn`
  // with an array of arguments, or `child_process.execFile` if possible,
  // as they do not invoke a shell by default.
  // For `ping`, which is often shell-dependent for ` -c 1`, strong validation is key.
  exec(`ping -c 1 ${host}`, (err, stdout, stderr) => {
    if (err) {
      // Differentiate error types for better client feedback
      if (err.code === 127) {
        // Command not found (e.g., ping not installed)
        console.error(`Error: Ping command not found: ${err.message}`);
        return res.status(500).send("Server error: 'ping' command not found.");
      }
      // Other exec errors (e.g., host unreachable, permission denied)
      console.error(`Error executing ping for ${host}: ${stderr || err.message}`);
      return res.status(500).send(`Ping failed: ${stderr.trim() || err.message}`);
    }
    res.send(stdout);
  });
});

// ----------------------------
// Existing Secure Endpoint (now uses process.env secret)
// ----------------------------
app.get("/secure", (req, res) => {
  const token = req.headers["x-api-token"];

  // Ensure the environment variable is set
  if (!SECRET_TOKEN) {
    console.error("API_SECRET_TOKEN environment variable is not set.");
    return res.status(500).json({ error: "Server configuration error: API token missing." });
  }

  if (token !== SECRET_TOKEN) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  res.json({ message: "Secure data accessed" });
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
  console.log("To test the secure endpoint, set API_SECRET_TOKEN environment variable.");
  console.log("Example: API_SECRET_TOKEN=my-super-secret-token-1234567890wdascvd node index.js");
});