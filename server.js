const express = require("express");
const { createNodeMiddleware } = require("probot");
const probotApp = require("./index.js");
const { addSubscriber, verifyPaddleSignature } = probotApp;

const app = express();
const port = process.env.PORT || 3000;

app.get("/health", (_req, res) => {
  res.status(200).type("text/plain").send("ok");
});

app.post(
  "/paddle/webhook",
  express.raw({ type: "*/*" }),
  async (req, res) => {
    console.log("Paddle webhook hit");
    console.log("All headers:", JSON.stringify(req.headers, null, 2));

    try {
      const signatureHeader = typeof req.get === "function"
        ? req.get("Paddle-Signature")
        : req.headers["paddle-signature"];

      if (!signatureHeader) {
        res.status(401).send("Missing signature");
        return;
      }

      const rawBody = req.body;

      const isValidSignature = verifyPaddleSignature({
        secret: process.env.PADDLE_WEBHOOK_SECRET,
        signatureHeader,
        rawBody
      });

      if (!isValidSignature) {
        res.status(401).send("Invalid signature");
        return;
      }

      const event = JSON.parse(rawBody.toString("utf8"));

      if (
        event?.event_type === "subscription.activated" ||
        event?.event_type === "subscription.created"
      ) {
        const installation_id = event?.data?.custom_data?.installation_id;
        if (installation_id) {
          await addSubscriber(installation_id);
        } else {
          console.warn(
            "Paddle webhook missing installation_id — skipping addSubscriber",
            event?.event_type
          );
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

const start = async () => {
  app.use(await createNodeMiddleware(probotApp));
  app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
  });
};

start().catch((error) => {
  console.error("Failed to start server:", error);
  process.exitCode = 1;
});
