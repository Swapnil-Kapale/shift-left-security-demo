const express = require("express");
const app = express();
const { execFile } = require("child_process"); // Use execFile for safer command execution

app.use(express.json());

// ✅ Using environment variables for secrets
// Hardcoded secrets have been replaced with process.env.SECRET_NAME
const SECRET_TOKEN = process.env.SECRET_TOKEN;

// ----------------------------
// 1️⃣ SQL Injection Vulnerability - FIXED
//    Using parameterized queries (simulated)
// ----------------------------
app.get("/user", (req, res) => {
  const username = req.query.username;

  // Use a parameterized query.
  // In a real application, you would pass these to your database driver
  // (e.g., `db.query('SELECT * FROM users WHERE username = $1', [username])` for PostgreSQL
  // or `db.execute('SELECT * FROM users WHERE username = ?', [username])` for MySQL)
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
//    Escaping user input
// ----------------------------

// Utility function to escape HTML characters
function escapeHtml(str) {
  if (typeof str !== 'string') {
    return ''; // Handle non-string inputs gracefully by returning an empty string
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
//    Validating input and using execFile
// ----------------------------
// child_process.execFile is safer than exec for executing commands
// with user-supplied arguments, as it treats arguments as distinct array elements
// and does not invoke a shell by default.

app.get("/ping", (req, res) => {
  const host = req.query.host;

  // Validate the host input to ensure it's a valid hostname or IP address.
  // This is a critical layer of defense against command injection.
  // For simplicity, a basic regex check is used. A more robust validation
  // might involve a dedicated library or stricter, more comprehensive regex for hostnames.
  const ipAddressRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  const hostnameRegex = /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;


  if (!host || (!ipAddressRegex.test(host) && !hostnameRegex.test(host))) {
    return res.status(400).send("Invalid host specified. Please provide a valid IP address or hostname.");
  }

  // Use execFile, passing the command and arguments as separate elements.
  // This prevents shell metacharacter injection as arguments are not parsed by a shell.
  // The `-c 1` argument is also hardcoded to limit the number of pings.
  execFile("ping", ["-c", "1", host], { timeout: 5000 }, (err, stdout, stderr) => {
    if (err) {
      // Log the error for debugging purposes but avoid exposing internal system details to the user.
      console.error(`execFile error for host ${host}:`, err);
      // Return a generic error message to the client, possibly including sanitized stderr
      const errorMessage = stderr ? stderr.split('\n')[0] : 'Unknown error during ping.';
      return res.status(500).send(`Failed to ping host: ${host}. ${errorMessage}`);
    }
    // Only return stdout to the client
    res.send(stdout);
  });
});

// ----------------------------
// Existing Secure Endpoint (now using environment variable for secret)
// ----------------------------
app.get("/secure", (req, res) => {
  const token = req.headers["x-api-token"];

  // Ensure the environment variable is loaded
  if (!SECRET_TOKEN) {
    // This indicates a server configuration issue, not a client error.
    console.error("Server configuration error: SECRET_TOKEN environment variable not set.");
    return res.status(500).json({ error: "Server configuration error: Secret token is not set." });
  }

  if (token !== SECRET_TOKEN) {
    // Return a 401 Unauthorized status for incorrect tokens.
    return res.status(401).json({ error: "Unauthorized: Invalid API token." });
  }

  // If token is valid, respond with secure data.
  res.json({ message: "Secure data accessed successfully." });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});