const fs = require("fs");
const path = require("path");
const { GoogleGenerativeAI } = require("@google/generative-ai");

const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const GEMINI_MODEL = process.env.GEMINI_MODEL || "gemini-2.5-flash";

let genAI;

function initializeGenAI() {
  if (!GEMINI_API_KEY) {
    throw new Error("Missing GEMINI_API_KEY environment variable");
  }
  genAI = new GoogleGenerativeAI(GEMINI_API_KEY);
}

function scanRoutes() {
  const routes = [];
  const extensions = [".js", ".ts", ".jsx", ".tsx"];
  
  function walkDir(dir) {
    try {
      const files = fs.readdirSync(dir);
      
      for (const file of files) {
        if (file.startsWith(".") || file === "node_modules") continue;
        
        const fullPath = path.join(dir, file);
        const stat = fs.statSync(fullPath);
        
        if (stat.isDirectory()) {
          walkDir(fullPath);
        } else if (extensions.some(ext => file.endsWith(ext))) {
          const content = fs.readFileSync(fullPath, "utf8");
          const fileRoutes = extractRoutesFromFile(content, fullPath);
          routes.push(...fileRoutes);
        }
      }
    } catch (err) {
      // Skip inaccessible directories
    }
  }
  
  walkDir(process.cwd());
  return routes;
}

function extractRoutesFromFile(content, filePath) {
  const routes = [];
  
  // Regex patterns for common route definitions
  const patterns = [
    { regex: /app\.(get|post|put|delete|patch)\s*\(\s*["'`]([^"'`]+)["'`]\s*,\s*(\([^)]*\)|\w+)\s*=>/gm, type: "express" },
    { regex: /router\.(get|post|put|delete|patch)\s*\(\s*["'`]([^"'`]+)["'`]\s*,\s*(\([^)]*\)|\w+)\s*=>/gm, type: "express-router" },
    { regex: /@(Get|Post|Put|Delete|Patch)\s*\(\s*["'`]?([^"'`\)]*)/gm, type: "nestjs" },
    { regex: /\/\*\*[\s\S]*?(GET|POST|PUT|DELETE|PATCH)\s+([^\s]+)/gm, type: "comment" },
  ];
  
  for (const { regex, type } of patterns) {
    let match;
    while ((match = regex.exec(content)) !== null) {
      const method = match[1] || match[3];
      const path = match[2] || match[1];
      
      // Check for auth middleware presence
      const beforeRoute = content.substring(Math.max(0, match.index - 200), match.index);
      const afterRoute = content.substring(match.index, Math.min(content.length, match.index + 400));
      
      const hasAuthMiddleware = /auth|middleware|jwt|passport|guard|verify|protect/i.test(beforeRoute + afterRoute);
      const hasRBACCheck = /role|permission|admin|authorize/i.test(afterRoute);
      
      routes.push({
        method: method?.toUpperCase() || "UNKNOWN",
        path: path?.trim() || "unknown",
        filePath,
        hasAuthMiddleware,
        hasRBACCheck,
        context: afterRoute.substring(0, 150),
      });
    }
  }
  
  return routes;
}

function extractAuthFlaws(routes) {
  const flaws = [];

  for (const route of routes) {
    const issues = [];

    // Detect missing auth checks
    if (!route.hasAuthMiddleware) {
      issues.push("Missing authentication middleware");
    }

    // Detect potential IDOR (common patterns)
    if (/\/:[a-z_]+id|\/:\w+\/edit|\/:\w+\/delete/i.test(route.path)) {
      if (!route.hasRBACCheck) {
        issues.push("IDOR risk: ID-based route without RBAC check");
      }
    }

    // Detect admin routes without protection
    if (/admin|protected|private|internal/i.test(route.path) && !route.hasAuthMiddleware) {
      issues.push("Admin/protected route without authentication");
    }

    // Role bypass detection
    if (!route.hasRBACCheck && /admin|owner|moderator/i.test(route.path)) {
      issues.push("Role-based route missing RBAC logic");
    }

    if (issues.length > 0) {
      flaws.push({
        method: route.method,
        path: route.path,
        filePath: route.filePath,
        severity: calculateSeverity(issues, route),
        issues,
      });
    }
  }

  return flaws;
}

function calculateSeverity(issues, route) {
  if (issues.some(i => i.includes("admin") || i.includes("protected"))) {
    return "critical";
  }
  if (issues.some(i => i.includes("IDOR"))) {
    return "high";
  }
  if (issues.some(i => i.includes("Role"))) {
    return "high";
  }
  return "medium";
}


// ADK Tool 1: Analyze Auth Middleware
function analyzeAuthMiddleware({ flawType, routePath }) {
  console.info(`Analyzing auth middleware for ${flawType} on route: ${routePath}`);

  let middleware = "";
  let analysis = "";

  if (flawType === "missing_auth") {
    middleware = `
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  // Verify JWT token
  next();
};
app.get("${routePath}", authMiddleware, (req, res) => { /* handler */ });
    `;
    analysis = "Missing authentication: Added JWT verification middleware";
  } else if (flawType === "idor") {
    middleware = `
const idorProtection = (req, res, next) => {
  const userId = req.user.id;
  const resourceId = req.params.id;
  // Verify user owns the resource
  if (userId !== resourceId && !isAdmin(req.user)) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
};
app.get("${routePath}", authMiddleware, idorProtection, handler);
    `;
    analysis = "IDOR vulnerability: Added ownership verification check";
  } else if (flawType === "admin_unprotected") {
    middleware = `
const adminGuard = (req, res, next) => {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};
app.get("${routePath}", authMiddleware, adminGuard, handler);
    `;
    analysis = "Admin route unprotected: Added admin role verification";
  } else if (flawType === "role_bypass") {
    middleware = `
const roleGuard = (requiredRoles) => (req, res, next) => {
  if (!requiredRoles.includes(req.user?.role)) {
    return res.status(403).json({ error: 'Insufficient permissions' });
  }
  next();
};
app.get("${routePath}", authMiddleware, roleGuard(['admin', 'manager']), handler);
    `;
    analysis = "Role bypass risk: Added role-based access control";
  }

  return { analysis, middleware };
}

// ADK Tool 2: Recommend RBAC Pattern
function recommendRbacPattern({ routePath, requiredRoles }) {
  const pattern = requiredRoles.length > 1 ? "multi-role" : "single-role";

  const implementation = `
// RBAC Pattern for ${routePath}
const rbacConfig = {
  "${routePath}": {
    roles: ${JSON.stringify(requiredRoles)},
    permissions: ['read', 'write']
  }
};

const rbacMiddleware = (requiredRoles) => (req, res, next) => {
  const userRole = req.user?.role;
  if (!requiredRoles.includes(userRole)) {
    return res.status(403).json({ 
      error: 'Access denied',
      required_roles: requiredRoles,
      user_role: userRole 
    });
  }
  next();
};

// Usage: app.get("${routePath}", authMiddleware, rbacMiddleware(${JSON.stringify(requiredRoles)}), handler);
  `;

  return { pattern, implementation };
}

// Create Specialized Authorization Agents
async function createAuthSecurityAgents() {
  const model = genAI.getGenerativeModel({ model: GEMINI_MODEL });

  return {
    model,
    flawAnalyzerInstruction: `You are a code security analyzer specializing in authentication flaws.

Analyze the provided authorization flaws and classify each one:
- Categorize by type: missing_auth, idor, admin_unprotected, role_bypass
- Identify the route path and HTTP method
- Explain the specific vulnerability
- Estimate impact level

Be concise and technical in your analysis.`,
    middlewareInstruction: `You are an Express.js middleware expert.

Given authorization flaws, recommend specific middleware implementations:
- Suggest JWT authentication middleware
- Recommend IDOR protection patterns
- Propose admin guard middleware
- Suggest role-based access control implementations

Provide working code examples for each recommendation.`,
    rbacInstruction: `You are a security architect specializing in RBAC design.

Generate role-based access control patterns:
- Design role hierarchies
- Define permission matrices
- Create middleware for role enforcement
- Provide multi-level access examples

Focus on production-ready implementations.`,
    fixOrchestratorInstruction: `You are a security fix orchestrator that coordinates multiple agents.

Synthesize recommendations from other agents and provide:
- Complete security fixes
- Implementation priority order
- Testing strategies
- Deployment considerations

Consider all agent recommendations in your final output.`,
  };
}

// Run agents sequentially with response chaining
async function runAuthSecurityAgents(flaws, agents) {
  console.log("\n📋 Agent 1: Analyzing Authorization Flaws...\n");
  
  const flawAnalysisPrompt = `${agents.flawAnalyzerInstruction}

Analyze these authorization flaws:
${JSON.stringify(flaws, null, 2)}`;

  const flawAnalysis = await callWithRetry(async () => {
    const result = await agents.model.generateContent(flawAnalysisPrompt);
    return result.response.text();
  });
  console.log(flawAnalysis);
  await delay(1500); // Rate limiting delay

  console.log("\n🔧 Agent 2: Recommending Middleware Implementations...\n");
  
  const middlewarePrompt = `${agents.middlewareInstruction}

Based on these flaws:
${JSON.stringify(flaws, null, 2)}`;

  const middlewareRecommendations = await callWithRetry(async () => {
    const result = await agents.model.generateContent(middlewarePrompt);
    return result.response.text();
  });
  console.log(middlewareRecommendations);
  await delay(1500); // Rate limiting delay

  console.log("\n🛡️ Agent 3: Generating RBAC Patterns...\n");
  
  const rbacPrompt = `${agents.rbacInstruction}

For authorization flaws involving roles:
${JSON.stringify(flaws.filter(f => f.issues.some(i => i.includes("Role") || i.includes("RBAC"))), null, 2)}`;

  const rbacPatterns = await callWithRetry(async () => {
    const result = await agents.model.generateContent(rbacPrompt);
    return result.response.text();
  });
  console.log(rbacPatterns);
  await delay(1500); // Rate limiting delay

  console.log("\n✅ Agent 4: Orchestrating Complete Security Fixes...\n");
  
  const orchestratorPrompt = `${agents.fixOrchestratorInstruction}

AGENT 1 ANALYSIS (Authorization Flaw Classification):
${flawAnalysis}

AGENT 2 RECOMMENDATIONS (Middleware Implementations):
${middlewareRecommendations}

AGENT 3 OUTPUT (RBAC Patterns):
${rbacPatterns}

Now synthesize all the above recommendations and provide:
1. Priority-ordered fixes
2. Complete, production-ready code examples
3. Testing approach
4. Deployment checklist
5. Security validation steps`;

  const finalFixStrategy = await callWithRetry(async () => {
    const result = await agents.model.generateContent(orchestratorPrompt);
    return result.response.text();
  });
  console.log("\n" + finalFixStrategy);

  return {
    flawAnalysis,
    middlewareRecommendations,
    rbacPatterns,
    finalFixStrategy,
  };
}

(async () => {
  try {
    // Initialize Google Generative AI
    initializeGenAI();

    console.log("🔍 Scanning for authorization logic flaws...\n");

    const routes = scanRoutes();
    const flaws = extractAuthFlaws(routes);

    if (flaws.length === 0) {
      console.log("✅ No authorization flaws detected.");
      process.exit(0);
    }

    console.log(`🚨 Found ${flaws.length} potential authorization vulnerabilities:\n`);
    console.log(JSON.stringify(flaws, null, 2));

    console.log("\n🤖 Initializing Multi-Agent Security Analysis System...\n");

    // Create all specialized agents
    const agents = await createAuthSecurityAgents();

    // Run all agents sequentially
    const analysisResults = await runAuthSecurityAgents(flaws, agents);

    // Fail pipeline if critical/high severity present
    const hasHighRisk = flaws.some(f =>
      ["high", "critical"].includes(f.severity)
    );

    if (hasHighRisk) {
      console.log("\n❌ Critical/High authorization risk detected.");
      process.exit(1);
    } else {
      console.log("\n✅ Authorization analysis complete.");
      process.exit(0);
    }
  } catch (error) {
    console.error("❌ Agent analysis failed:", error.message);
    console.error("Stack:", error.stack);
    process.exit(1);
  }
})();
