const fs = require("fs");
const path = require("path");
const { GoogleGenerativeAI } = require("@google/generative-ai");
const { execSync } = require("child_process");

const AI_PROVIDER = process.env.AI_PROVIDER || "gemini";
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const GEMINI_MODEL = process.env.GEMINI_MODEL || "gemini-2.5-flash";

let genAI;

function initializeGenAI() {
  if (!GEMINI_API_KEY) {
    throw new Error("Missing GEMINI_API_KEY environment variable");
  }
  genAI = new GoogleGenerativeAI(GEMINI_API_KEY);
}

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

  const model = genAI.getGenerativeModel({ model: GEMINI_MODEL });
  const result = await model.generateContent(prompt);
  return result.response.text().replace(/```[a-z]*\n?/gi, "").replace(/```/g, "").trim();
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
  try {
    initializeGenAI();
    
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
  } catch (error) {
    console.error("❌ Error:", error.message);
    process.exit(1);
  }
})();
