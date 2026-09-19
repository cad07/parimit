import { createServer } from "node:http";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { createHttpHandler } from "./http.ts";
import { createServiceFromEnvironment } from "./service.ts";

export function startServer(environment: Record<string, string | undefined> = process.env) {
  const service = createServiceFromEnvironment(environment);
  const host = environment.PARIMIT_HOST ?? "127.0.0.1";
  const port = Number(environment.PARIMIT_PORT ?? "8787");
  if (!Number.isInteger(port) || port < 0 || port > 65_535) {
    service.close();
    throw new Error("PARIMIT_PORT must be an integer from 0 to 65535");
  }
  const moduleDirectory = dirname(fileURLToPath(import.meta.url));
  const publicDirectory = resolve(moduleDirectory, "../public");
  const server = createServer(createHttpHandler(service, { publicDirectory }));
  server.listen(port, host, () => {
    const address = server.address();
    const displayPort = typeof address === "object" && address ? address.port : port;
    console.warn("[Parimit] PROPOSAL-ONLY demo. It cannot move money or connect to UPI.");
    console.warn("[Parimit] Demo actor headers are spoofable; do not use them in production.");
    console.log(`Parimit listening on http://${host}:${displayPort}`);
  });
  const close = (): void => {
    server.close(() => service.close());
  };
  return { server, service, close };
}

const entrypoint = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : "";
if (import.meta.url === entrypoint) startServer();
