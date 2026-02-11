const fs = require("fs");
const path = require("path");
const https = require("https");

const AI_PROVIDER = process.env.AI_PROVIDER || "ollama";

const OLLAMA_MODEL = process.env.OLLAMA_MODEL || "llama3";
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const GEMINI_MODEL = process.env.GEMINI_MODEL || "gemini-1.5-flash";

const TARGET_EXTENSIONS = [".js"];

let secretFound = false;

function containsSecret(content) {
  const patterns = [/SECRET/i, /TOKEN/i, /API_KEY/i, /PASSWORD/i];
  return patterns.some((pattern) => pattern.test(content));
}

async function callOllama(prompt) {
  const payload = JSON.stringify({
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
          "Content-Length": payload.length,
        },
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          try {
            const parsed = JSON.parse(data);
            resolve(parsed.response);
          } catch (err) {
            reject(err);
          }
        });
      }
    );

    req.on("error", reject);
    req.write(payload);
    req.end();
  });
}

async function callGemini(prompt) {
  if (!GEMINI_API_KEY) {
    throw new Error("GEMINI_API_KEY not set");
  }

  const payload = JSON.stringify({
    contents: [{ parts: [{ text: prompt }] }],
  });

  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: "generativelanguage.googleapis.com",
        path: `/v1beta/models/${GEMINI_MODEL}:generateContent?key=${GEMINI_API_KEY}`,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": payload.length,
        },
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          try {
            console.log("Gemini raw response:", data);
            const parsed = JSON.parse(data);
            const text =
              parsed.candidates?.[0]?.content?.parts?.[0]?.text;
            resolve(text);
          } catch (err) {
            reject(err);
          }
        });
      }
    );

    req.on("error", reject);
    req.write(payload);
    req.end();
  });
}

async function generateRefactor(content, filePath) {
  const prompt = `
You are a security refactoring agent.

Refactor the following code:
- Replace hardcoded secrets with process.env.VARIABLE_NAME
- Do NOT change logic
- Keep the file compilable
- Return ONLY the updated code
- Do not add explanations

File: ${filePath}

Code:
${content}
`;

  if (AI_PROVIDER === "ollama") {
    return await callOllama(prompt);
  } else if (AI_PROVIDER === "gemini") {
    return await callGemini(prompt);
  } else {
    throw new Error("Unsupported AI_PROVIDER");
  }
}

async function processFile(filePath) {
  const content = fs.readFileSync(filePath, "utf8");

  if (!containsSecret(content)) return;

  console.log(`🔐 Secret detected in ${filePath}`);
  secretFound = true;

  const updatedCode = await generateRefactor(content, filePath);

  if (!updatedCode) {
    throw new Error("AI returned empty response");
  }

  fs.writeFileSync(filePath, updatedCode);
  console.log(`✅ Refactored ${filePath}`);
}

async function scanDir(dir) {
  const files = fs.readdirSync(dir);

  for (const file of files) {
    if (file === "node_modules" || file.startsWith(".")) continue;

    const fullPath = path.join(dir, file);

    if (fs.statSync(fullPath).isDirectory()) {
      await scanDir(fullPath);
    } else if (TARGET_EXTENSIONS.includes(path.extname(file))) {
      await processFile(fullPath);
    }
  }
}

(async () => {
  await scanDir(process.cwd());

  if (secretFound) {
    console.log("🔁 AI refactor applied. Re-run validation.");
    process.exit(1);
  } else {
    console.log("✅ No secrets detected.");
  }
})();
