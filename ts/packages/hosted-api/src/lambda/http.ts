import type {
  ApiGatewayEvent,
  ApiGatewayResponse,
} from '../http.js';
import { getHostedComposition } from '../composition.js';

export async function handler(event: ApiGatewayEvent): Promise<ApiGatewayResponse> {
  return (await getHostedComposition()).http(event);
}
