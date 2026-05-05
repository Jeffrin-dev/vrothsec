const { GoogleGenerativeAI } = require("@google/generative-ai");

const SECURITY_REVIEW_PROMPT = `You are a security reviewer specializing in AI and cloud code. Review this diff for: hardcoded API keys, overpermissioned IAM policies, exposed secrets, insecure AI endpoints, missing rate limiting, prompt injection risks, unsafe S3 configs. Return ONLY a JSON array of findings with fields: severity (critical/high/medium), file, line, issue, fix. If no issues found return an empty array [].`;

const SEVERITY_CONFIG = {
  critical: { label: "Critical", emoji: "🔴" },
  high: { label: "High", emoji: "🟠" },
  medium: { label: "Medium", emoji: "🟡" }
};

const ORDERED_SEVERITIES = ["critical", "high", "medium"];

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
module.exports = (app) => {
  app.on(["pull_request.opened", "pull_request.synchronize"], async (context) => {
    const { owner, repo } = context.repo();
    const pull_number = context.payload.pull_request.number;

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

    console.log(
      `\n=== PR DIFF (${owner}/${repo}#${pull_number}) - ${new Date().toISOString()} ===\n${diff}\n=== END PR DIFF ===\n`
    );

    const apiKey = process.env.GEMINI_API_KEY;

    if (!apiKey) {
      console.error("GEMINI_API_KEY is not set. Skipping Gemini security review.");
      return;
    }

    try {
      const genAI = new GoogleGenerativeAI(apiKey);
      const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });

      const result = await model.generateContent([
        { text: SECURITY_REVIEW_PROMPT },
        { text: `PR Diff:\n\n${diff}` }
      ]);

      const rawText = result.response.text().trim();
      const cleanedText = rawText.replace(/^```json\s*|\s*```$/g, "").trim();
      const findings = JSON.parse(cleanedText);
      const body = formatFindingsMarkdown(findings);

      console.log("Gemini security findings:", findings);

      if (!body) {
        console.log("No critical or high severity findings detected. Skipping PR comment.");
        return;
      }

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
      console.error("Failed to generate or parse Gemini security findings:", error);
    }
  });
};
