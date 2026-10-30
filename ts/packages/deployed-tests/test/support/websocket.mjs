import { randomBytes } from 'node:crypto';
import { request } from 'node:https';

function encodeTextFrame(text) {
  const payload = Buffer.from(text);
  const mask = randomBytes(4);
  const extended =
    payload.length < 126
      ? Buffer.alloc(0)
      : payload.length <= 0xffff
        ? Buffer.alloc(2)
        : Buffer.alloc(8);
  let lengthMarker = payload.length;
  if (payload.length >= 126 && payload.length <= 0xffff) {
    lengthMarker = 126;
    extended.writeUInt16BE(payload.length);
  } else if (payload.length > 0xffff) {
    lengthMarker = 127;
    extended.writeBigUInt64BE(BigInt(payload.length));
  }
  const header = Buffer.from([0x81, 0x80 | lengthMarker]);
  const masked = Buffer.alloc(payload.length);
  for (let index = 0; index < payload.length; index += 1) {
    masked[index] = payload[index] ^ mask[index % 4];
  }
  return Buffer.concat([header, extended, mask, masked]);
}

function decodeFrame(buffer) {
  if (buffer.length < 2) return null;
  const opcode = buffer[0] & 0x0f;
  let length = buffer[1] & 0x7f;
  let offset = 2;
  if (length === 126) {
    if (buffer.length < 4) return null;
    length = buffer.readUInt16BE(2);
    offset = 4;
  } else if (length === 127) {
    if (buffer.length < 10) return null;
    const value = buffer.readBigUInt64BE(2);
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('WebSocket frame is too large.');
    length = Number(value);
    offset = 10;
  }
  const masked = (buffer[1] & 0x80) !== 0;
  const maskOffset = offset;
  if (masked) offset += 4;
  if (buffer.length < offset + length) return null;
  const payload = Buffer.from(buffer.subarray(offset, offset + length));
  if (masked) {
    const mask = buffer.subarray(maskOffset, maskOffset + 4);
    for (let index = 0; index < payload.length; index += 1) {
      payload[index] ^= mask[index % 4];
    }
  }
  return {
    opcode,
    payload,
    remaining: buffer.subarray(offset + length),
  };
}

export function openWebSocket(url, options = {}) {
  const parsed = new URL(url);
  if (parsed.protocol !== 'wss:') throw new Error('Only wss:// endpoints are supported.');

  return new Promise((resolve, reject) => {
    const key = randomBytes(16).toString('base64');
    const request_ = request({
      protocol: 'https:',
      hostname: parsed.hostname,
      port: parsed.port || 443,
      path: `${parsed.pathname}${parsed.search}`,
      method: 'GET',
      headers: {
        Connection: 'Upgrade',
        Upgrade: 'websocket',
        'Sec-WebSocket-Key': key,
        'Sec-WebSocket-Version': '13',
        Cookie: options.cookie || 'tf_session=1',
        Origin: options.origin || `https://${parsed.host}`,
        'User-Agent':
          options.userAgent ||
          'ThreatForest-deployed-WebSocket-test/1.0',
      },
      timeout: options.timeoutMs || 20_000,
    });
    request_.once('upgrade', (_response, socket, head) => {
      let buffered = head;
      const waiters = [];

      const flush = () => {
        while (waiters.length > 0) {
          const frame = decodeFrame(buffered);
          if (frame === null) return;
          buffered = frame.remaining;
          const waiter = waiters.shift();
          if (frame.opcode === 0x8) {
            waiter.reject(new Error('WebSocket closed before a message arrived.'));
          } else if (frame.opcode === 0x1) {
            waiter.resolve(frame.payload.toString('utf8'));
          }
        }
      };
      socket.on('data', (chunk) => {
        buffered = Buffer.concat([buffered, chunk]);
        flush();
      });
      socket.on('error', (error) => {
        while (waiters.length > 0) waiters.shift().reject(error);
      });

      resolve({
        sendJson(value) {
          socket.write(encodeTextFrame(JSON.stringify(value)));
        },
        nextMessage(timeoutMs = 20_000) {
          return new Promise((resolveMessage, rejectMessage) => {
            const waiter = { resolve: resolveMessage, reject: rejectMessage };
            waiters.push(waiter);
            flush();
            const timer = setTimeout(() => {
              const index = waiters.indexOf(waiter);
              if (index >= 0) waiters.splice(index, 1);
              rejectMessage(new Error('Timed out waiting for a WebSocket message.'));
            }, timeoutMs);
            timer.unref();
            const originalResolve = waiter.resolve;
            waiter.resolve = (value) => {
              clearTimeout(timer);
              originalResolve(value);
            };
          });
        },
        close() {
          socket.end(Buffer.from([0x88, 0x80, 0, 0, 0, 0]));
        },
      });
    });
    request_.once('response', (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
      response.once('end', () => {
        const detail = Buffer.concat(chunks)
          .toString('utf8')
          .replace(/\s+/g, ' ')
          .trim()
          .slice(0, 256);
        const errorType = response.headers['x-amzn-errortype'];
        const suffix = [
          typeof errorType === 'string' ? `type=${errorType}` : '',
          detail ? `body=${detail}` : '',
        ]
          .filter(Boolean)
          .join(', ');
        reject(
          new Error(
            `WebSocket upgrade failed with HTTP ${response.statusCode}` +
              `${suffix ? ` (${suffix})` : ''}.`,
          ),
        );
      });
    });
    request_.once('timeout', () => request_.destroy(new Error('WebSocket upgrade timed out.')));
    request_.once('error', reject);
    request_.end();
  });
}
