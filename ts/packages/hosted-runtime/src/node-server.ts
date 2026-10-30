import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { AgentCoreHttpRuntime } from './runtime.js';
import type { RuntimeHttpRequest } from './contracts.js';

export interface AgentCoreNodeServerOptions {
  runtime: AgentCoreHttpRuntime;
  maxBodyBytes?: number;
  invocationHeartbeatMs?: number;
  contextFactory?: (request: IncomingMessage) => unknown | Promise<unknown>;
}

async function readBody(request: IncomingMessage, limit: number): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.byteLength;
    if (size > limit) {
      throw new Error('request body exceeds the configured limit');
    }
    chunks.push(buffer);
  }
  if (size === 0) {
    return {};
  }
  return Buffer.concat(chunks).toString('utf8');
}

function requestHeaders(request: IncomingMessage): RuntimeHttpRequest['headers'] {
  return Object.fromEntries(
    Object.entries(request.headers).map(([key, value]) => [key, value]),
  );
}

export function createAgentCoreNodeServer(options: AgentCoreNodeServerOptions): Server {
  const limit = options.maxBodyBytes ?? 2 * 1024 * 1024;
  const heartbeatMs = options.invocationHeartbeatMs ?? 15_000;
  if (!Number.isSafeInteger(heartbeatMs) || heartbeatMs < 1) {
    throw new Error('invocationHeartbeatMs must be a positive integer');
  }
  let activeInvocations = 0;
  return createServer(async (request, response) => {
    let heartbeat: NodeJS.Timeout | undefined;
    let invocationStarted = false;
    const stopHeartbeat = (): void => {
      if (heartbeat !== undefined) {
        clearInterval(heartbeat);
        heartbeat = undefined;
      }
    };
    response.once('close', stopHeartbeat);
    try {
      const path = new URL(request.url ?? '/', 'http://runtime.local').pathname;
      const method = request.method ?? 'GET';
      if (method.toUpperCase() === 'GET' && path === '/ping') {
        response.writeHead(200, {
          'content-type': 'application/json; charset=utf-8',
          'cache-control': 'no-store',
        });
        response.end(
          JSON.stringify({
            status: activeInvocations > 0 || options.runtime.busy ? 'HealthyBusy' : 'Healthy',
          }),
        );
        return;
      }
      const body = await readBody(request, limit);
      const context = await options.contextFactory?.(request);
      if (method.toUpperCase() === 'POST' && path === '/invocations') {
        activeInvocations += 1;
        invocationStarted = true;
        response.writeHead(200, {
          'content-type': 'application/json; charset=utf-8',
          'cache-control': 'no-store',
        });
        response.flushHeaders();
        response.write('\n');
        heartbeat = setInterval(() => {
          if (!response.destroyed && !response.writableEnded) {
            response.write('\n');
          }
        }, heartbeatMs);
        heartbeat.unref();
      }
      const runtimeResponse = await options.runtime.handle({
        method,
        path,
        headers: requestHeaders(request),
        body,
        context,
      });
      if (!response.headersSent && !response.destroyed) {
        response.writeHead(runtimeResponse.statusCode, runtimeResponse.headers);
      }
      if (!response.destroyed && !response.writableEnded) {
        response.end(runtimeResponse.body);
      }
    } catch (error) {
      if (!response.headersSent && !response.destroyed) {
        response.writeHead(400, {
          'content-type': 'application/json; charset=utf-8',
          'cache-control': 'no-store',
        });
      }
      if (!response.destroyed && !response.writableEnded) {
        response.end(
          JSON.stringify({
            error: 'BadRequest',
            message: error instanceof Error ? error.message : 'invalid request',
          }),
        );
      }
    } finally {
      stopHeartbeat();
      response.off('close', stopHeartbeat);
      if (invocationStarted) {
        activeInvocations -= 1;
      }
    }
  });
}

export async function listen(
  server: Server,
  port = 8080,
  host = '0.0.0.0',
): Promise<{ port: number; host: string }> {
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      server.off('error', reject);
      resolve();
    });
  });
  const address = server.address() as AddressInfo;
  return { port: address.port, host: address.address };
}
