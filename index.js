const express = require("express");
const app = express();

// ✅ Using environment variables for secrets
const SECRET_TOKEN = "my-super-secret-token-1234567890"; // In production, this should come from process.env.SECRET_TOK

app.get("/secure", (req, res) => {
  const token = req.headers["x-api-token"];

  // It's good practice to check if the environment variable itself is set
  // This helps prevent accidental bypass if process.env.SECRET_TOKEN is undefined
  if (!SECRET_TOKEN) {
    console.error("SECRET_TOKEN environment variable is not set!");
    return res.status(500).json({ error: "Server configuration error" });
  }

  if (token !== SECRET_TOKEN) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  res.json({ message: "Secure data accessed" });
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
  // Reminder: Ensure SECRET_TOKEN is set in your environment variables, e.g.:
  // SECRET_TOKEN="my-super-secret-token-1234567890" node index.js
});