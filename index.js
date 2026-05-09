if (process.env.PRIVATE_KEY) {
  process.env.PRIVATE_KEY = 
    process.env.PRIVATE_KEY
      .replace(/\\n/g, '\n')
      .replace(/\\r/g, '')
      .trim()
}
const crypto = require("node:crypto");
const express = require("express");
const { GoogleGenerativeAI } = require("@google/generative-ai");

const SECURITY_REVIEW_PROMPT = `You are a security reviewer specializing in AI and cloud code. Review this diff for: hardcoded API keys, overpermissioned IAM policies, exposed secrets, insecure AI endpoints, missing rate limiting, prompt injection risks, unsafe S3 configs. Return ONLY a JSON array of findings with fields: severity (critical/high/medium), file, line, issue, fix. If no issues found return an empty array [].`;

const SEVERITY_CONFIG = {
  critical: { label: "Critical", emoji: "🔴" },
  high: { label: "High", emoji: "🟠" },
  medium: { label: "Medium", emoji: "🟡" }
};

const ORDERED_SEVERITIES = ["critical", "high", "medium"];
const DIFF_CHUNK_SIZE = 500;


const readRequestBodyAsText = (req) => new Promise((resolve, reject) => {
  const chunks = [];

  req.setEncoding("utf8");
  req.on("data", (chunk) => chunks.push(chunk));
  req.on("end", () => resolve(chunks.join("")));
  req.on("error", reject);
});

const parsePaddleSignatureHeader = (signatureHeader) => {
  const parts = String(signatureHeader || "")
    .split(";")
    .map((part) => part.trim())
    .filter(Boolean);

  return parts.reduce((acc, part) => {
    const separatorIndex = part.indexOf("=");

    if (separatorIndex === -1) {
      return acc;
    }

    const key = part.slice(0, separatorIndex);
    const value = part.slice(separatorIndex + 1);

    acc[key] = value;
    return acc;
  }, {});
};

const verifyPaddleSignature = ({ secret, signatureHeader, rawBody }) => {
  if (!secret) {
    throw new Error("PADDLE_WEBHOOK_SECRET must be set");
  }

  const { ts, h1 } = parsePaddleSignatureHeader(signatureHeader);

  if (!ts || !h1) {
    return false;
  }

  const expectedSignature = crypto
    .createHmac("sha256", secret)
    .update(`${ts}:${rawBody}`)
    .digest("hex");
  const expectedBuffer = Buffer.from(expectedSignature, "hex");
  const actualBuffer = Buffer.from(h1, "hex");

  if (expectedBuffer.length !== actualBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(expectedBuffer, actualBuffer);
};

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

const getSubscribers = async () => {
  const repo = process.env.GITHUB_DATA_REPO;
  const token = process.env.GITHUB_DATA_TOKEN;

  if (!repo || !token) {
    throw new Error("GITHUB_DATA_REPO and GITHUB_DATA_TOKEN must be set");
  }

  const response = await fetch(`https://api.github.com/repos/${repo}/contents/subscribers.json`, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json"
    }
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Failed to fetch subscribers.json: ${response.status} ${errorText}`);
  }

  const data = await response.json();
  const decodedContent = Buffer.from(String(data.content || "").replace(/\n/g, ""), "base64").toString("utf8");

  return {
    subscribers: JSON.parse(decodedContent),
    sha: data.sha
  };
};

const addSubscriber = async (installationId) => {
  const repo = process.env.GITHUB_DATA_REPO;
  const token = process.env.GITHUB_DATA_TOKEN;

  if (!repo || !token) {
    throw new Error("GITHUB_DATA_REPO and GITHUB_DATA_TOKEN must be set");
  }

  const { subscribers, sha } = await getSubscribers();
  const idAsString = String(installationId);
  const installations = Array.isArray(subscribers.installations) ? subscribers.installations.map(String) : [];

  if (!installations.includes(idAsString)) {
    installations.push(idAsString);
  }

  const updatedSubscribers = {
    ...subscribers,
    installations
  };

  const content = Buffer.from(JSON.stringify(updatedSubscribers, null, 2), "utf8").toString("base64");

  const response = await fetch(`https://api.github.com/repos/${repo}/contents/subscribers.json`, {
    method: "PUT",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      message: `Add subscriber ${idAsString}`,
      content,
      sha
    })
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Failed to update subscribers.json: ${response.status} ${errorText}`);
  }

  return updatedSubscribers;
};

/**
 * @param {import('probot').Probot} app
 */
module.exports = (app, { getRouter }) => {
  if (typeof getRouter === "function") {
    const healthRouter = getRouter();
    healthRouter.get("/health", (_req, res) => {
      res.status(200).type("text/plain").send("ok");
    });
  }

  const router = getRouter("/paddle/webhook");
  router.post(
    "/",
    express.raw({ type: "*/*" }),
    async (req, res) => {
      try {
        const rawBody = Buffer.isBuffer(req.body)
          ? req.body.toString("utf8")
          : await readRequestBodyAsText(req);
        const signatureHeader = typeof req.get === "function"
          ? req.get("Paddle-Signature")
          : req.headers["paddle-signature"];
        const isValidSignature = verifyPaddleSignature({
          secret: process.env.PADDLE_WEBHOOK_SECRET,
          signatureHeader,
          rawBody
        });

        if (!isValidSignature) {
          res.status(401).send("Invalid signature");
          return;
        }

        const event = JSON.parse(rawBody);

        if (event?.event_type === "subscription.activated" || event?.event_type === "subscription.created") {
          const installationId = event.data?.custom_data?.installation_id;

          if (installationId) {
            await addSubscriber(installationId);
            console.log("Activated installation: " + installationId);
          }
        }

        res.status(200).send("OK");
      } catch (error) {
        console.error("Error in Paddle webhook handler:", {
          message: error?.message,
          stack: error?.stack,
          error
        });
        res.status(500).send("Internal Server Error");
      }
    }
  );

  app.on(["pull_request.opened", "pull_request.synchronize"], async (context) => {
    try {
      console.log("Step 1: Handler triggered");
      const isPrivate = Boolean(context.payload.repository?.private);
      const repoFullName = context.payload.repository?.full_name || "unknown/unknown";
      const installationId = String(context.payload.installation?.id || "");

      console.log(`Repository visibility check (${repoFullName}): ${isPrivate ? "private" : "public"}`);

      if (isPrivate) {
        const { subscribers } = await getSubscribers();
        const installations = Array.isArray(subscribers?.installations) ? subscribers.installations.map(String) : [];

        if (!installations.includes(installationId)) {
          const { owner, repo } = context.repo();
          const pull_number = context.payload.pull_request.number;

          await context.octokit.request(
            "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
            {
              owner,
              repo,
              issue_number: pull_number,
              body: `## 🔒 VrothSec — Subscription Required

VrothSec is **free for public repositories**.

Private repository scanning requires a subscription.

[**Get VrothSec Pro — $15/month →**](https://vrothsec.vercel.app/?installation_id=${context.payload.installation.id}#pricing)

Once subscribed your repo will be activated within 24 hours.`
            }
          );
          return;
        }
      }

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
      const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash-lite" });

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
