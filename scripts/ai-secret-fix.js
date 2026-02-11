const fs = require("fs");
const path = require("path");
const https = require("https");
const { execSync } = require("child_process");

const AI_PROVIDER = process.env.AI_PROVIDER || "gemini";
const OLLAMA_MODEL = process.env.OLLAMA_MODEL || "llama3";
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const GEMINI_MODEL = process.env.GEMINI_MODEL || "gemini-2.5-flash";

const SECRET_PATTERNS = [
  /SECRET/i,
  /TOKEN/i,
  /API_KEY/i,
  /PASSWORD/i,
];

let refactorApplied = false;

/* ------------------------ */
/* Get PR changed files     */
/* ------------------------ */
function getChangedFiles() {
  try {
    const output = execSync(
      "git diff --name-only origin/${GITHUB_BASE_REF}...HEAD",
      { encoding: "utf8" }
    );
    return output
      .split("\n")
      .filter(f => f.endsWith(".js") && !f.startsWith("scripts/"));
  } catch (err) {
    console.log("Fallback: scanning all JS files");
    return [];
  }
}

/* ------------------------ */
/* Markdown cleaner         */
/* ------------------------ */
function stripMarkdown(text) {
  return text
    .replace(/```[a-z]*\n?/gi, "")
    .replace(/```/g, "")
    .trim();
}

/* ------------------------ */
/* Secret detection         */
/* ------------------------ */
function containsSecret(content) {
  return SECRET_PATTERNS.some(pattern => pattern.test(content));
}

/* ------------------------ */
/* Gemini Call              */
/* ------------------------ */
async function callGemini(prompt) {
  if (!GEMINI_API_KEY) throw new Error("Missing GEMINI_API_KEY");

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

/* ------------------------ */
/* Ollama Call              */
/* ------------------------ */
async function callOllama(prompt) {
  const body = JSON.stringify({
    model: OLLAMA_MODEL,
    prompt,
    stream: false,
  });

  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: "host.docker.internal",
        port: 11434,
        path: "/api/generate",
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": body.length,
        },
      },
      (res) => {
        let data = "";
        res.on("data", chunk => (data += chunk));
        res.on("end", () => {
          try {
            const parsed = JSON.parse(data);
            resolve(stripMarkdown(parsed.response));
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

/* ------------------------ */
/* AI Refactor              */
/* ------------------------ */
async function generateRefactor(content, filePath) {
  const prompt = `
You are a security refactoring agent.

Refactor the following code:
- Replace hardcoded secrets with process.env.SECRET_NAME
- Do NOT change business logic
- Keep code runnable
- Return ONLY valid JavaScript code

File: ${filePath}

Code:
${content}
`;

  if (AI_PROVIDER === "ollama") return await callOllama(prompt);
  return await callGemini(prompt);
}

/* ------------------------ */
/* Process file             */
/* ------------------------ */
async function processFile(filePath) {
  const content = fs.readFileSync(filePath, "utf8");

  if (!containsSecret(content)) return;

  console.log(`🔐 Secret detected in ${filePath}`);

  const updated = await generateRefactor(content, filePath);

  if (!updated) {
    console.log("⚠ AI returned empty response");
    return;
  }

  if (updated !== content) {
    fs.writeFileSync(filePath, updated);
    console.log(`✅ Refactored ${filePath}`);
    refactorApplied = true;
  }
}

/* ------------------------ */
/* Main                     */
/* ------------------------ */
(async () => {
  const changedFiles = getChangedFiles();

  if (changedFiles.length === 0) {
    console.log("No specific changed files found, exiting.");
    process.exit(0);
  }

  for (const file of changedFiles) {
    await processFile(file);
  }

  if (refactorApplied) {
    console.log("🔁 Changes applied, committing...");
    process.exit(2); // special exit code
  } else {
    console.log("✅ No secrets detected.");
    process.exit(0);
  }
})();
