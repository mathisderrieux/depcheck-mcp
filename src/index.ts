#!/usr/bin/env node
/**
 * DepCheck MCP Server
 *
 * Expose à Claude Code (et tout client MCP) un outil `depcheck_check`
 * qui audite un package open-source via l'API DepCheck.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

// --- Configuration ---
// L'URL de l'API peut être overridée par variable d'env, sinon prod par défaut.
const API_BASE_URL =
  process.env.DEPCHECK_API_URL ?? "https://depcheck-production.up.railway.app";

const VERSION = "0.1.0";

// --- Création du serveur MCP ---
const server = new Server(
  {
    name: "depcheck-mcp",
    version: VERSION,
  },
  {
    capabilities: {
      tools: {}, // on déclare qu'on a des tools (la liste est servie par ListTools)
    },
  },
);

// --- Déclaration de l'outil exposé ---
// Claude Code appellera cette méthode pour découvrir ce que ce serveur sait faire.
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "depcheck_check",
        description:
          "Audit an open-source package for vulnerabilities, license issues, " +
          "maintenance status, and typosquatting risks BEFORE installing it. " +
          "Returns a verdict (GO / REVIEW / BLOCK) with reasoning. " +
          "Call this whenever the user asks to install, add, or evaluate a dependency.",
        inputSchema: {
          type: "object",
          properties: {
            ecosystem: {
              type: "string",
              enum: ["npm", "pypi", "cargo", "go"],
              description: "Package ecosystem: npm, pypi, cargo, or go",
            },
            package: {
              type: "string",
              description:
                "Package name. For npm scoped packages, include the scope (e.g. '@types/node').",
            },
            version: {
              type: "string",
              description:
                "Optional specific version to check (e.g. '18.2.0'). " +
                "If omitted, the latest stable version is checked.",
            },
          },
          required: ["ecosystem", "package"],
        },
      },
    ],
  };
});

// --- Exécution de l'outil quand Claude Code l'appelle ---
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  if (request.params.name !== "depcheck_check") {
    throw new Error(`Unknown tool: ${request.params.name}`);
  }

  const args = request.params.arguments as {
    ecosystem: string;
    package: string;
    version?: string;
  };

  // Validation côté serveur MCP avant d'appeler l'API
  if (!args.ecosystem || !args.package) {
    return {
      content: [
        { type: "text", text: "Error: 'ecosystem' and 'package' are required." },
      ],
      isError: true,
    };
  }

  // Construction de l'URL d'appel
  const url = new URL(`${API_BASE_URL}/v1/check`);
  url.searchParams.set("ecosystem", args.ecosystem);
  url.searchParams.set("package", args.package);
  if (args.version) {
    url.searchParams.set("version", args.version);
  }

  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers: {
        Accept: "application/json",
        "User-Agent": `depcheck-mcp/${VERSION}`,
      },
    });

    if (!response.ok) {
      return {
        content: [
          {
            type: "text",
            text: `DepCheck API returned ${response.status}: ${response.statusText}`,
          },
        ],
        isError: true,
      };
    }

    const data = await response.json();

    // On retourne le résultat sous forme texte structuré + JSON brut.
    // Claude lit les deux et peut citer/raisonner dessus.
    const summary = formatHumanSummary(data);

    return {
      content: [
        { type: "text", text: summary },
        { type: "text", text: "\nRaw JSON response:\n" + JSON.stringify(data, null, 2) },
      ],
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      content: [
        {
          type: "text",
          text: `DepCheck call failed: ${message}\nAPI URL: ${API_BASE_URL}`,
        },
      ],
      isError: true,
    };
  }
});

/**
 * Reformate la réponse JSON en résumé lisible.
 * Claude voit la version texte d'abord, ce qui l'aide à raisonner sans parser le JSON.
 */
function formatHumanSummary(data: any): string {
  const lines: string[] = [];
  lines.push(`Package: ${data.package} (${data.ecosystem})`);
  lines.push(`Verdict: ${data.verdict}  |  Score: ${data.score}/100`);
  lines.push(`Summary: ${data.summary}`);

  const v = data.checks?.vulnerabilities;
  if (v && v.count > 0) {
    lines.push(`Vulnerabilities: ${v.count} found, max severity ${v.severity_max}`);
    for (const vuln of v.found.slice(0, 5)) {
      lines.push(`  - ${vuln.id} [${vuln.severity}]: ${vuln.summary?.slice(0, 100) ?? ""}`);
    }
  }

  const lic = data.checks?.license;
  if (lic?.spdx) {
    lines.push(`License: ${lic.spdx}${lic.compatible ? "" : " (INCOMPATIBLE)"}`);
  }

  const maint = data.checks?.maintenance;
  if (maint?.last_release_days_ago !== null && maint?.last_release_days_ago !== undefined) {
    lines.push(`Last release: ${maint.last_release_days_ago} days ago`);
  }
  if (maint?.weekly_downloads) {
    lines.push(`Weekly downloads: ${maint.weekly_downloads.toLocaleString()}`);
  }

  const typo = data.checks?.typosquatting;
  if (typo?.suspicious) {
    lines.push(`⚠ TYPOSQUATTING SUSPECT — similar to: ${typo.similar_to.join(", ")}`);
  }

  if (data.alternatives?.length > 0) {
    lines.push(`Suggested alternatives:`);
    for (const alt of data.alternatives) {
      lines.push(`  - ${alt.name}: ${alt.reason}`);
    }
  }

  if (data.cache_hit) {
    lines.push(`(cached result)`);
  }

  return lines.join("\n");
}

// --- Connexion au transport stdio et démarrage ---
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // ⚠️ Pas de console.log : ça polluerait le stdout JSON-RPC.
  // Les logs de debug doivent aller vers stderr si besoin :
  console.error("DepCheck MCP server started, connected to:", API_BASE_URL);
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});