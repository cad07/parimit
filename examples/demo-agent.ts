const baseUrl = process.env.PARIMIT_URL ?? "http://127.0.0.1:8787";

const proposal = {
  idempotency_key: `demo-agent-${new Date().toISOString().slice(0, 10)}`,
  requested_by: {
    type: "agent",
    id: "open-source-demo-agent",
  },
  on_behalf_of: "demo-user",
  amount: {
    currency: "INR",
    minor: "49900",
  },
  payee_reference: "demo-coffee-merchant",
  purpose: "Synthetic order DEMO-123",
};

const response = await fetch(`${baseUrl}/v1/intents`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify(proposal),
});

const result = await response.json();

if (!response.ok) {
  console.error("Parimit rejected the request:", result);
  process.exitCode = 1;
} else {
  console.log(JSON.stringify(result, null, 2));
  console.log("\nThe agent stopped after proposing. It cannot approve or execute the payment.");
}
