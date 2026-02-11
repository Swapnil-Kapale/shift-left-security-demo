const fs = require("fs");
const path = require("path");

const SECRET_PATTERNS = [
  /SECRET/i,
  /TOKEN/i,
  /API_KEY/i,
  /PASSWORD/i,
];

let secretFound = false;

function scanFile(filePath) {
  const content = fs.readFileSync(filePath, "utf8");

  for (const pattern of SECRET_PATTERNS) {
    if (pattern.test(content)) {
      console.error(`❌ Hardcoded secret detected in: ${filePath}`);
      secretFound = true;
      return;
    }
  }
}

function scanDir(dir) {
  const files = fs.readdirSync(dir);

  for (const file of files) {
    const fullPath = path.join(dir, file);

    if (file === "node_modules" || file.startsWith(".")) continue;

    if (fs.statSync(fullPath).isDirectory()) {
      scanDir(fullPath);
    } else if (file.endsWith(".js")) {
      scanFile(fullPath);
    }
  }
}

scanDir(process.cwd());

if (secretFound) {
  console.error("❌ Layer 1 failed: Hardcoded secrets found.");
  process.exit(1);
}

console.log("✅ Layer 1 passed: No hardcoded secrets found.");
