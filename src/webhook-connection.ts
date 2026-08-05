import { DurableObject } from 'cloudflare:workers';
import type { Bindings } from './types';
import type { WebhookEvent } from './webhook-types';

interface WebhookEventMessage {
  type: 'event';
  event: WebhookEvent;
}

export class WebhookConnection extends DurableObject<Bindings> {
  async fetch(request: Request): Promise<Response> {
    if (request.method !== 'GET' || request.headers.get('upgrade')?.toLowerCase() !== 'websocket') {
      return new Response('WebSocket upgrade required', { status: 426 });
    }

    const pair = new WebSocketPair();
    this.ctx.acceptWebSocket(pair[1]);
    return new Response(null, { status: 101, webSocket: pair[0] });
  }

  async publish(event: WebhookEvent): Promise<void> {
    const message: WebhookEventMessage = { type: 'event', event };
    const encoded = JSON.stringify(message);

    for (const socket of this.ctx.getWebSockets()) {
      try {
        socket.send(encoded);
      } catch {
        socket.close(1011, 'Unable to deliver webhook event');
      }
    }
  }

  webSocketMessage(): void {
    // The browser only receives notifications; client messages are ignored.
  }

  webSocketClose(): void {
    // The runtime removes closed sockets from getWebSockets().
  }
}
