// Shared scaffolding for the client and auth E2E suites: the raw-bytes request/response capture
// types, the guards that narrow a dynamically-imported generated module to callable exports, and
// a scripted local `node:http` server that replays a canned response per "METHOD url" route and
// records every request byte-for-byte. Both suites generate their own fixture tree and load their
// own operations, so that part stays in each test file; only the parts that were byte-identical
// between the two files live here.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

export type ExportedFunction = (...arguments_: unknown[]) => unknown;
export type HeaderEntry = readonly [string, string];
export type CapturedRequest = {
  readonly method: string;
  readonly url: string;
  readonly rawHeaderEntries: readonly HeaderEntry[];
  readonly body: Buffer;
};
export type ScriptedResponse = {
  readonly status: number;
  readonly headers?: readonly HeaderEntry[];
  readonly body?: Uint8Array;
  // Delays the body past the flushed headers, staggering response-start from response-complete
  // for tests that need a window in between (e.g. a mid-flight abort).
  readonly delayBodyMs?: number;
};

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function requiredRecord(value: unknown, label: string): Readonly<Record<string, unknown>> {
  if (!isRecord(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  return value;
}

function isExportedFunction(value: unknown): value is ExportedFunction {
  return typeof value === "function";
}

export function requiredFunction(module: unknown, name: string): ExportedFunction {
  const value = requiredRecord(module, "generated module")[name];
  if (!isExportedFunction(value)) {
    throw new TypeError(`generated export ${name} must be a function`);
  }
  return value;
}

function headerEntries(rawHeaders: readonly string[]): readonly HeaderEntry[] {
  const entries: HeaderEntry[] = [];
  for (let index = 0; index < rawHeaders.length; index += 2) {
    const name = rawHeaders[index];
    const value = rawHeaders[index + 1];
    if (name === undefined || value === undefined) {
      throw new TypeError("node:http produced an incomplete raw header entry");
    }
    entries.push([name, value]);
  }
  return entries;
}

function routeKey(method: string, url: string): string {
  return `${method} ${url}`;
}

export function requestHeader(request: CapturedRequest, name: string): string | undefined {
  const normalized = name.toLowerCase();
  return request.rawHeaderEntries.find(
    ([headerName]) => headerName.toLowerCase() === normalized,
  )?.[1];
}

async function captureRequest(request: IncomingMessage): Promise<CapturedRequest> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of request) {
    chunks.push(chunk);
  }
  return {
    method: request.method ?? "",
    url: request.url ?? "",
    rawHeaderEntries: headerEntries(request.rawHeaders),
    body: Buffer.concat(chunks),
  };
}

export type ScriptedServer = {
  readonly routes: Map<string, ScriptedResponse>;
  readonly requests: CapturedRequest[];
  readonly scriptRoute: (method: string, url: string, response: ScriptedResponse) => void;
  readonly requiredRequest: (index: number) => CapturedRequest;
  // Starts listening on an ephemeral loopback port and resolves the resulting base URL.
  readonly start: () => Promise<string>;
  readonly stop: () => Promise<void>;
};

// A single scripted route table and capture list, shared by the server handler below and by the
// `scriptRoute`/`requiredRequest` helpers a suite's tests call directly.
export function createScriptedServer(): ScriptedServer {
  const routes = new Map<string, ScriptedResponse>();
  const requests: CapturedRequest[] = [];
  let server: Server;

  function scriptRoute(method: string, url: string, response: ScriptedResponse): void {
    routes.set(routeKey(method, url), response);
  }

  function requiredRequest(index: number): CapturedRequest {
    const request = requests[index];
    if (request === undefined) {
      throw new TypeError(`captured request ${String(index)} is missing`);
    }
    return request;
  }

  async function start(): Promise<string> {
    server = createServer((request: IncomingMessage, response: ServerResponse) => {
      captureRequest(request)
        .then((captured) => {
          requests.push(captured);
          const scripted = routes.get(routeKey(captured.method, captured.url));
          if (scripted === undefined) {
            response.writeHead(500, { "Content-Type": "text/plain" });
            response.end(`No scripted response for ${captured.method} ${captured.url}`);
            return;
          }
          for (const [name, value] of scripted.headers ?? []) {
            response.setHeader(name, value);
          }
          response.writeHead(scripted.status);
          const end = (): void => {
            response.end(scripted.body);
          };
          if (scripted.delayBodyMs === undefined) {
            end();
          } else {
            response.flushHeaders();
            setTimeout(end, scripted.delayBodyMs);
          }
        })
        .catch((error: unknown) => {
          response.destroy(error instanceof Error ? error : new Error("request capture failed"));
        });
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (address === null || typeof address === "string") {
      throw new TypeError("node:http did not bind an IP socket");
    }
    return `http://127.0.0.1:${String(address.port)}`;
  }

  async function stop(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error === undefined ? resolve() : reject(error)));
    });
  }

  return { routes, requests, scriptRoute, requiredRequest, start, stop };
}
