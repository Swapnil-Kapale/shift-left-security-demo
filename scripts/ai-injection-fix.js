const fs = require("fs");
const path = require("path");
const https = require("https");
const { execSync } = require("child_process");

const AI_PROVIDER = process.env.AI_PROVIDER || "gemini";
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const GEMINI_MODEL = process.env.GEMINI_MODEL || "gemini-2.5-flash";

let refactorApplied = false;

/* ---------------------------- */
/* Changed Files Only           */
/* ---------------------------- */
function getChangedFiles() {
  try {
    const base = process.env.GITHUB_BASE_REF || "main";
    const output = execSync(
      `git diff --name-only origin/${base}...HEAD`,
      { encoding: "utf8" }
    );

    return output
      .split("\n")
      .filter(f => f.endsWith(".js") && !f.startsWith("scripts/"));
  } catch {
    return [];
  }
}

/* ---------------------------- */
/* Vulnerability Detection      */
/* ---------------------------- */
function containsInjection(content) {
  const patterns = [
    /\$\{.*\}/,                      // template injection
    /exec\s*\(/,                     // command injection
    /res\.send\s*\(\s*`/,            // raw HTML template
    /SELECT .*['"].*\+/,             // string concat SQL
  ];

  return patterns.some(p => p.test(content));
}

/* ---------------------------- */
/* Markdown Cleaner             */
/* ---------------------------- */
function stripMarkdown(text) {
  return text
    .replace(/```[a-z]*\n?/gi, "")
    .replace(/```/g, "")
    .trim();
}

/* ---------------------------- */
/* Gemini Call                  */
/* ---------------------------- */
async function callGemini(prompt) {
  const body = JSON.stringify({
    contents: [{ parts: [{ text: prompt }] }]
  });

  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: "generativelanguage.googleapis.com",
        path: `/v1beta/models/${GEMINI_MODEL}:generateContent?key=${GEMINI_API_KEY}`,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body),
        },
      },
      (res) => {
        let data = "";
        res.on("data", chunk => (data += chunk));
        res.on("end", () => {
          try {
            const parsed = JSON.parse(data);

            if (!parsed.candidates) return resolve(null);

            const text = parsed.candidates[0].content.parts
              .map(p => p.text || "")
              .join("");

            resolve(stripMarkdown(text));
          } catch (err) {
            reject(err);
          }
        });
      }
    );

    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

/* ---------------------------- */
/* AI Refactor Prompt           */
/* ---------------------------- */
async function generateRefactor(content, filePath) {
  const prompt = `
You are a senior security engineer.

Refactor this code to fix:

- SQL Injection → Use parameterized queries
- Cross-Site Scripting (XSS) → Escape user input
- Command Injection → Validate or sanitize input, avoid unsafe exec
- Do NOT change business logic
- Keep app runnable
- Return ONLY valid JavaScript code

File: ${filePath}

Code:
${content}
`;

  return await callGemini(prompt);
}

/* ---------------------------- */
/* Process File                 */
/* ---------------------------- */
async function processFile(filePath) {
  const content = fs.readFileSync(filePath, "utf8");

  if (!containsInjection(content)) return;

  console.log(`🚨 Vulnerability detected in ${filePath}`);

  const updated = await generateRefactor(content, filePath);

  if (!updated) {
    console.log("⚠ AI returned empty response");
    return;
  }

  if (updated !== content) {
    fs.writeFileSync(filePath, updated);
    console.log(`✅ Injection vulnerabilities fixed in ${filePath}`);
    refactorApplied = true;
  }
}

/* ---------------------------- */
/* Main                         */
/* ---------------------------- */
(async () => {
  const changedFiles = getChangedFiles();

  for (const file of changedFiles) {
    await processFile(file);
  }

  if (refactorApplied) {
    console.log("🔁 Injection fixes applied.");
    process.exit(2);
  } else {
    console.log("✅ No injection vulnerabilities detected.");
    process.exit(0);
  }
})();
