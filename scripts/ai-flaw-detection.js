const fs = require("fs");
const path = require("path");
const { z } = require("zod");

let LlmAgent, InMemoryRunner, FunctionTool;

// Dynamic import for ESM modules
async function initializeADK() {
  const adkModule = await import("@google/adk");
  LlmAgent = adkModule.LlmAgent;
  InMemoryRunner = adkModule.InMemoryRunner;
  FunctionTool = adkModule.FunctionTool;
}

const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const GEMINI_MODEL = process.env.GEMINI_MODEL || "gemini-2.5-flash";

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

// ADK Tool 3: Generate Security Fix
function generateSecurityFix({ flaw, fixCode, severity }) {
  const report = `
=== Security Fix Report ===
Severity: ${severity.toUpperCase()}
Flaw: ${flaw}

Fixed Code:
${fixCode}

Verification Checklist:
- [ ] Authentication middleware properly validates tokens
- [ ] Role-based access control checks are in place
- [ ] IDOR protections verify resource ownership
- [ ] Admin routes are protected with admin guard
- [ ] Error messages don't leak sensitive info
- [ ] Middleware is applied to all sensitive routes
  `;

  return { fixed: true, report };
}

async function runAuthSecurityAgent(flaws) {
  // Wrap functions as ADK FunctionTools
  const analyzeAuthMiddlewareTool = new FunctionTool({
    name: "analyze_auth_middleware",
    description: "Analyzes authorization middleware patterns and suggests secure implementations",
    parameters: z.object({
      flawType: z.enum(["missing_auth", "idor", "admin_unprotected", "role_bypass"]),
      routePath: z.string(),
    }),
    execute: analyzeAuthMiddleware,
  });

  const recommendRbacPatternTool = new FunctionTool({
    name: "recommend_rbac_pattern",
    description: "Recommends RBAC (Role-Based Access Control) patterns for routes",
    parameters: z.object({
      routePath: z.string(),
      requiredRoles: z.array(z.string()),
    }),
    execute: recommendRbacPattern,
  });

  const generateSecurityFixTool = new FunctionTool({
    name: "generate_security_fix",
    description: "Generates complete security fix code for authorization vulnerabilities",
    parameters: z.object({
      flaw: z.string(),
      fixCode: z.string(),
      severity: z.enum(["critical", "high", "medium", "low"]),
    }),
    execute: generateSecurityFix,
  });

  // Create the ADK agent
  const agent = new LlmAgent({
    model: GEMINI_MODEL,
    name: "auth_security_agent",
    instruction: `You are an application security expert specializing in authorization vulnerabilities.

Analyze the provided authorization flaws and:
1. Use analyze_auth_middleware to identify required middleware
2. Use recommend_rbac_pattern to suggest role-based access control
3. Use generate_security_fix to create complete code fixes

For each vulnerability, provide:
- Detailed vulnerability explanation
- Middleware implementation suggestions
- RBAC pattern recommendations
- Complete working code examples
- Security best practices

Authorization Flaws to Analyze:
${JSON.stringify(flaws, null, 2)}

Analyze each flaw systematically and use all available tools to provide comprehensive security improvements.`,
    tools: [analyzeAuthMiddlewareTool, recommendRbacPatternTool, generateSecurityFixTool],
  });

  // Run the agent
  const runner = new InMemoryRunner();
  const results = await runner.runAgent(agent, "Analyze all the authorization flaws and provide security fixes");

  return results;
}

(async () => {
  try {
    // Initialize ADK modules first
    await initializeADK();

    console.log("🔍 Scanning for authorization logic flaws...\n");

    const routes = scanRoutes();
    const flaws = extractAuthFlaws(routes);

    if (flaws.length === 0) {
      console.log("✅ No authorization flaws detected.");
      process.exit(0);
    }

    console.log(`🚨 Found ${flaws.length} potential authorization vulnerabilities:\n`);
    console.log(JSON.stringify(flaws, null, 2));

    console.log("\n🤖 Initializing Google ADK Agent for security analysis...\n");

    const agentResults = await runAuthSecurityAgent(flaws);

    // Process agent results
    console.log("\n🧠 AI Authorization Flaw Analysis:\n");

    // Extract and display agent response
    if (agentResults && Array.isArray(agentResults)) {
      for (const result of agentResults) {
        if (result.content) {
          console.log(result.content);
        }
        // Log tool calls if present
        if (result.toolCalls && result.toolCalls.length > 0) {
          console.log("\n📌 Tool Calls Executed:");
          for (const toolCall of result.toolCalls) {
            console.log(`  - ${toolCall.name}: ${JSON.stringify(toolCall.input)}`);
          }
        }
      }
    }

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
