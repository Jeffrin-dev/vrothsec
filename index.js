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

    console.log(
      `\n=== PR DIFF (${owner}/${repo}#${pull_number}) - ${new Date().toISOString()} ===\n${diffResponse.data}\n=== END PR DIFF ===\n`
    );
  });
};
