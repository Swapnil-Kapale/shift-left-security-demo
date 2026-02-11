const express = require("express");
const app = express();

// ❌ Intentionally hardcoded secret (for demo)
const SECRET_TOKEN = "my-super-secret-token-1234567890";

app.get("/secure", (req, res) => {
  const token = req.headers["x-api-token"];

  if (token !== SECRET_TOKEN) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  res.json({ message: "Secure data accessed" });
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});
