const express = require("express");
const app = express();
const { execFile } = require("child_process"); // Use execFile for safer command execution

app.use(express.json());

// ❌ Hardcoded secret (already vulnerable - Note: This is a known vulnerability
// but not one of the explicitly requested fixes for this exercise.
// In a real application, this should be an environment variable.)
const SECRET_TOKEN = "my-super-secret-token-1234567890wdascvd";

// ----------------------------
// 1️⃣ SQL Injection Vulnerability - FIXED
// ----------------------------
app.get("/user", (req, res) => {
  const username = req.query.username;

  // Use a parameterized query.
  // In a real application, you would pass these to your database driver
  // (e.g., `db.query('SELECT * FROM users WHERE username = $1', [username])` for PostgreSQL)
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
// ----------------------------
// child_process.execFile is safer than exec for executing commands
// with user-supplied arguments, as it treats arguments as distinct array elements
// and does not invoke a shell by default.

app.get("/ping", (req, res) => {
  const host = req.query.host;

  // Validate the host input to ensure it's a valid hostname or IP address.
  // This is an additional layer of defense.
  // For simplicity, a basic regex check is used. A more robust validation
  // might involve a dedicated library or stricter regex.
  const ipAddressRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  const hostnameRegex = /^[a-zA-Z0-9.-]+$/;

  if (!host || (!ipAddressRegex.test(host) && !hostnameRegex.test(host))) {
    return res.status(400).send("Invalid host specified.");
  }

  // Use execFile, passing the command and arguments as separate elements.
  // This prevents shell metacharacter injection.
  execFile("ping", ["-c", "1", host], (err, stdout, stderr) => {
    if (err) {
      // Log the error for debugging purposes but avoid exposing internal details to the user
      console.error(`execFile error for host ${host}:`, err);
      return res.status(500).send(`Failed to ping host: ${host}. ${stderr}`);
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