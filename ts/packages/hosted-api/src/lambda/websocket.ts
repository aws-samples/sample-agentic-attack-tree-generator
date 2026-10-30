import type {
  WebSocketGatewayEvent,
  WebSocketGatewayResponse,
} from '../websocket.js';
import { getHostedWebSocketComposition } from '../composition.js';

export async function handler(
  event: WebSocketGatewayEvent,
): Promise<WebSocketGatewayResponse> {
  return (await getHostedWebSocketComposition()).websocket(event);
}
