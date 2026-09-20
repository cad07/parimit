import { createServer } from "node:http";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { createIdentityProviderFromEnvironment } from "./auth.ts";
import { createHttpHandler } from "./http.ts";
import { createServiceFromEnvironment } from "./service.ts";

export function startServer(environment: Record<string, string | undefined> = process.env) {
  const effectiveEnvironment = {
    ...environment,
    PARIMIT_AUTH_MODE: environment.PARIMIT_AUTH_MODE ?? "demo_headers",
    PARIMIT_DEMO_MODE: environment.PARIMIT_DEMO_MODE ?? "true",
  };
  const identityProvider = createIdentityProviderFromEnvironment(effectiveEnvironment);
  const service = createServiceFromEnvironment(effectiveEnvironment);
  const host = effectiveEnvironment.PARIMIT_HOST ?? "127.0.0.1";
  const port = Number(effectiveEnvironment.PARIMIT_PORT ?? "8787");
  if (!Number.isInteger(port) || port < 0 || port > 65_535) {
    service.close();
    throw new Error("PARIMIT_PORT must be an integer from 0 to 65535");
  }
  const moduleDirectory = dirname(fileURLToPath(import.meta.url));
  const publicDirectory = resolve(moduleDirectory, "../public");
  const server = createServer(
    createHttpHandler(service, { publicDirectory, identityProvider }),
  );
  server.listen(port, host, () => {
    const address = server.address();
    const displayPort = typeof address === "object" && address ? address.port : port;
    console.warn("[Parimit] PROPOSAL-ONLY demo. It cannot move money or connect to UPI.");
    if (effectiveEnvironment.PARIMIT_AUTH_MODE === "demo_headers") {
      console.warn("[Parimit] Demo actor headers are spoofable and restricted to loopback.");
    } else {
      console.warn("[Parimit] OIDC identity verification is active.");
    }
    console.log(`Parimit listening on http://${host}:${displayPort}`);
  });
  const close = (): void => {
    server.close(() => service.close());
  };
  return { server, service, close };
}

const entrypoint = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : "";
if (import.meta.url === entrypoint) startServer();
