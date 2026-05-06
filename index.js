if (process.env.PRIVATE_KEY) {
  process.env.PRIVATE_KEY = 
    process.env.PRIVATE_KEY
      .replace(/\\n/g, '\n')
      .replace(/\\r/g, '')
      .trim()
}
const { GoogleGenerativeAI } = require("@google/generative-ai");

const SECURITY_REVIEW_PROMPT = `You are a security reviewer specializing in AI and cloud code. Review this diff for: hardcoded API keys, overpermissioned IAM policies, exposed secrets, insecure AI endpoints, missing rate limiting, prompt injection risks, unsafe S3 configs. Return ONLY a JSON array of findings with fields: severity (critical/high/medium), file, line, issue, fix. If no issues found return an empty array [].`;

const SEVERITY_CONFIG = {
  critical: { label: "Critical", emoji: "🔴" },
  high: { label: "High", emoji: "🟠" },
  medium: { label: "Medium", emoji: "🟡" }
};

const ORDERED_SEVERITIES = ["critical", "high", "medium"];
const DIFF_CHUNK_SIZE = 500;

const chunkDiffByLines = (diff, chunkSize = DIFF_CHUNK_SIZE) => {
  const lines = String(diff || "").split("\n");

  if (lines.length <= chunkSize) {
    return [diff];
  }

  const chunks = [];

  for (let i = 0; i < lines.length; i += chunkSize) {
    chunks.push(lines.slice(i, i + chunkSize).join("\n"));
  }

  return chunks;
};

const mergeAndDeduplicateFindings = (findingsByChunk) => {
  const mergedFindings = [];
  const seen = new Set();

  for (const chunkFindings of findingsByChunk) {
    if (!Array.isArray(chunkFindings)) {
      continue;
    }

    for (const finding of chunkFindings) {
      const file = String(finding?.file || "");
      const line = String(finding?.line || "");
      const dedupeKey = `${file}:${line}`;

      if (seen.has(dedupeKey)) {
        continue;
      }

      seen.add(dedupeKey);
      mergedFindings.push(finding);
    }
  }

  return mergedFindings;
};

const groupFindingsBySeverity = (findings) => findings.reduce((acc, finding) => {
  const severity = String(finding.severity || "").toLowerCase();

  if (!SEVERITY_CONFIG[severity]) {
    return acc;
  }

  acc[severity].push(finding);
  return acc;
}, { critical: [], high: [], medium: [] });

const formatFindingsMarkdown = (findings) => {
  if (!Array.isArray(findings) || findings.length === 0) {
    return null;
  }

  const groupedFindings = groupFindingsBySeverity(findings);
  const hasVisibleFindings = groupedFindings.critical.length > 0 || groupedFindings.high.length > 0;

  if (!hasVisibleFindings) {
    return null;
  }

  const sections = ORDERED_SEVERITIES
    .filter((severity) => severity !== "medium")
    .flatMap((severity) => {
    const items = groupedFindings[severity];

    if (items.length === 0) {
      return [];
    }

    const { label, emoji } = SEVERITY_CONFIG[severity];
    const formattedItems = items
      .map((finding) => {
        const file = finding.file || "Unknown";
        const line = finding.line || "Unknown";
        const issue = finding.issue || "Not provided";
        const fix = finding.fix || "Not provided";

        return [
          `${emoji} **${label}**`,
          `**File:** ${file}`,
          `**Line:** ${line}`,
          `**Issue:** ${issue}`,
          `**Fix:** ${fix}`
        ].join("\n");
      })
      .join("\n\n");

      return [`### ${label}`, formattedItems];
  });

  if (groupedFindings.medium.length > 0) {
    const { label, emoji } = SEVERITY_CONFIG.medium;
    const mediumItems = groupedFindings.medium
      .map((finding) => {
        const file = finding.file || "Unknown";
        const line = finding.line || "Unknown";
        const issue = finding.issue || "Not provided";
        const fix = finding.fix || "Not provided";

        return [
          `${emoji} **${label}**`,
          `**File:** ${file}`,
          `**Line:** ${line}`,
          `**Issue:** ${issue}`,
          `**Fix:** ${fix}`
        ].join("\n");
      })
      .join("\n\n");

    sections.push([
      "<details>",
      "<summary>🟡 Medium severity findings</summary>",
      "",
      mediumItems,
      "",
      "</details>"
    ].join("\n"));
  }

  return ["## 🔒 Cloud Security Review", ...sections].join("\n\n");
};

/**
 * @param {import('probot').Probot} app
 */
module.exports = (app, { getRouter } = {}) => {
  if (typeof getRouter === "function") {
    const router = getRouter();
    router.get("/health", (_req, res) => {
      res.status(200).type("text/plain").send("ok");
    });
  }

  app.on(["pull_request.opened", "pull_request.synchronize"], async (context) => {
    try {
      console.log("Step 1: Handler triggered");
      const { owner, repo } = context.repo();
      const pull_number = context.payload.pull_request.number;

      console.log("Step 2: Fetching diff");
      const diffResponse = await context.octokit.request(
        "GET /repos/{owner}/{repo}/pulls/{pull_number}",
        {
          owner,
          repo,
          pull_number,
          mediaType: {
            format: "diff"
          }
        }
      );

      const diff = diffResponse.data;
      console.log("Step 3: Diff fetched, length: " + diff.length);

      console.log(
        `
=== PR DIFF (${owner}/${repo}#${pull_number}) - ${new Date().toISOString()} ===
${diff}
=== END PR DIFF ===
`
      );

      const apiKey = process.env.GEMINI_API_KEY;

      if (!apiKey) {
        console.error("GEMINI_API_KEY is not set. Skipping Gemini security review.");
        return;
      }

      const genAI = new GoogleGenerativeAI(apiKey);
      const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

      const diffChunks = chunkDiffByLines(diff);
      const findingsByChunk = [];

      for (const [index, diffChunk] of diffChunks.entries()) {
        console.log("Step 4: Sending to Gemini");
        const result = await model.generateContent([
          { text: SECURITY_REVIEW_PROMPT },
          { text: `PR Diff (chunk ${index + 1}/${diffChunks.length}):

${diffChunk}` }
        ]);

        const rawText = result.response.text().trim();
        console.log("Step 5: Gemini response received");
        const cleanedText = rawText.replace(/^```json\s*|\s*```$/g, "").trim();
        const chunkFindings = JSON.parse(cleanedText);
        findingsByChunk.push(chunkFindings);
      }

      const findings = mergeAndDeduplicateFindings(findingsByChunk);
      const body = formatFindingsMarkdown(findings);

      console.log("Gemini security findings:", findings);

      if (!body) {
        console.log("No critical or high severity findings detected. Skipping PR comment.");
        return;
      }

      console.log("Step 6: Posting comment");
      await context.octokit.request(
        "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
        {
          owner,
          repo,
          issue_number: pull_number,
          body
        }
      );
    } catch (error) {
      console.error("Error in pull_request handler:", {
        message: error?.message,
        stack: error?.stack,
        error
      });
      throw error;
    }
  });
};
