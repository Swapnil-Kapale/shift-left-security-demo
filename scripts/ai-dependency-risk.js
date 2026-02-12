const { execSync } = require("child_process");
const https = require("https");

const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const GEMINI_MODEL = process.env.GEMINI_MODEL || "gemini-2.5-flash";

async function runAudit() {
  try {
    const output = execSync("npm audit --json", { encoding: "utf8" });
    return JSON.parse(output);
  } catch (err) {
    if (err.stdout) {
      return JSON.parse(err.stdout);
    }
    throw err;
  }
}

function extractVulnerabilities(auditJson) {
  if (!auditJson.vulnerabilities) return [];

  const results = [];

  for (const [pkg, details] of Object.entries(auditJson.vulnerabilities)) {
    results.push({
      package: pkg,
      severity: details.severity,
      via: details.via,
      fixAvailable: details.fixAvailable,
    });
  }

  return results;
}

function callGemini(prompt) {
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

            resolve(text.trim());
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

(async () => {
  const auditJson = await runAudit();
  const vulns = extractVulnerabilities(auditJson);

  if (vulns.length === 0) {
    console.log("✅ No dependency vulnerabilities detected.");
    process.exit(0);
  }

  console.log("🚨 Vulnerable packages detected:");
  console.log(JSON.stringify(vulns, null, 2));

  const prompt = `
You are a software supply-chain security expert.

Analyze the following npm dependency vulnerabilities.

For each package:
- Explain the risk briefly
- Suggest the safest upgrade version
- Suggest an alternative package if recommended
- Classify risk as Critical / High / Medium / Low
- Keep response structured and concise

Vulnerabilities:
${JSON.stringify(vulns, null, 2)}
`;

  const aiResponse = await callGemini(prompt);

  console.log("\n🧠 AI Dependency Risk Analysis:\n");
  console.log(aiResponse);

  // Fail pipeline if high severity present
  const hasHigh = vulns.some(v =>
    ["high", "critical"].includes(v.severity)
  );

  if (hasHigh) {
    console.log("\n❌ High/Critical dependency risk detected.");
    process.exit(1);
  } else {
    process.exit(0);
  }
})();
