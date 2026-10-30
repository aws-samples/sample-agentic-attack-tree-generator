import {
  HostedProgressEventSchema,
  type HostedProgressEvent,
} from '@threatforest/types';
import type {
  ConnectionAdapter,
  EventAdapter,
  WebSocketConnection,
} from './contracts.js';
import { browserProgressEvent } from './websocket.js';

export interface WebSocketFanoutChange {
  eventName: 'INSERT' | 'MODIFY' | 'REMOVE';
  newItem?: Record<string, unknown>;
  oldItem?: Record<string, unknown>;
}

export interface WebSocketFanoutOptions {
  connections: ConnectionAdapter;
  events: EventAdapter;
  now?: () => Date;
  maximumReplayEvents?: number;
}

export class WebSocketFanout {
  readonly #connections: ConnectionAdapter;
  readonly #events: EventAdapter;
  readonly #now: () => Date;
  readonly #maximumReplayEvents: number;

  constructor(options: WebSocketFanoutOptions) {
    this.#connections = options.connections;
    this.#events = options.events;
    this.#now = options.now ?? (() => new Date());
    this.#maximumReplayEvents = options.maximumReplayEvents ?? 10_000;
  }

  async process(change: WebSocketFanoutChange): Promise<void> {
    const newItem = change.newItem;
    const entity = newItem?.entity;
    if (change.eventName === 'INSERT' && entity === 'event') {
      await this.#publish(HostedProgressEventSchema.parse(newItem));
      return;
    }
    if (
      change.eventName === 'MODIFY' &&
      entity === 'hosted-websocket-subscription'
    ) {
      const current = connectionFromItem(newItem!);
      const previousItem = change.oldItem;
      const previous =
        previousItem === undefined ? null : connectionFromItem(previousItem);
      if (
        previous?.phase === 'replay_pending' &&
        current.phase === 'live'
      ) {
        await this.#catchUp(current);
      }
    }
  }

  async #publish(event: HostedProgressEvent): Promise<void> {
    const scope = {
      owner_id: event.owner_id,
      application_id: event.application_id,
    };
    const connections = await this.#connections.listForRun(
      scope,
      event.run_id,
    );
    for (const connection of connections) {
      if (connection.phase !== 'live' || event.sequence <= connection.cursor) {
        continue;
      }
      await this.#catchUp(connection, event.sequence);
    }
  }

  async #catchUp(
    candidate: WebSocketConnection,
    throughSequence?: number,
  ): Promise<void> {
    let connection = await this.#connections.get(candidate.connectionId);
    if (connection === null || connection.phase !== 'live') {
      return;
    }
    if (Date.parse(connection.expiresAt) <= this.#now().getTime()) {
      await this.#connections.delete(connection.connectionId);
      return;
    }
    const events = await this.#events.list(
      {
        owner_id: connection.ownerId,
        application_id: connection.applicationId,
      },
      connection.runId,
      connection.cursor,
    );
    if (events.length > this.#maximumReplayEvents) {
      throw new Error(
        `WebSocket replay exceeds ${this.#maximumReplayEvents} events`,
      );
    }
    const ordered = [...events]
      .filter(
        (event) =>
          event.sequence > connection!.cursor &&
          (throughSequence === undefined ||
            event.sequence <= throughSequence),
      )
      .sort((left, right) => left.sequence - right.sequence);
    const seenSequences = new Set<number>();
    for (const event of ordered) {
      if (
        seenSequences.has(event.sequence) ||
        connection.seenEventIds.includes(event.event_id) ||
        event.sequence <= connection.cursor
      ) {
        continue;
      }
      if (event.sequence !== connection.cursor + 1) {
        throw new Error(
          `WebSocket event sequence gap after ${connection.cursor}`,
        );
      }
      try {
        await this.#connections.post(
          connection.connectionId,
          browserProgressEvent(event),
        );
      } catch (error) {
        if (!isGone(error)) throw error;
        await this.#connections.delete(connection.connectionId);
        return;
      }
      seenSequences.add(event.sequence);
      const advanced = await this.#connections.advance(connection, event);
      if (advanced === null) {
        return;
      }
      if (advanced.cursor < event.sequence) {
        throw new Error('WebSocket cursor update was not committed');
      }
      connection = advanced;
    }
  }
}

function connectionFromItem(
  item: Record<string, unknown>,
): WebSocketConnection {
  const value = item.connection;
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('WebSocket stream record has no connection');
  }
  const connection = value as Partial<WebSocketConnection>;
  if (
    typeof connection.connectionId !== 'string' ||
    typeof connection.ownerId !== 'string' ||
    typeof connection.applicationId !== 'string' ||
    typeof connection.runId !== 'string' ||
    (connection.phase !== 'replay_pending' && connection.phase !== 'live') ||
    !Number.isSafeInteger(connection.cursor) ||
    !Array.isArray(connection.seenEventIds) ||
    typeof connection.ticketId !== 'string' ||
    typeof connection.connectedAt !== 'string' ||
    typeof connection.expiresAt !== 'string'
  ) {
    throw new Error('WebSocket stream connection is malformed');
  }
  return connection as WebSocketConnection;
}

function isGone(error: unknown): boolean {
  if (typeof error !== 'object' || error === null) return false;
  const value = error as {
    name?: unknown;
    statusCode?: unknown;
    $metadata?: { httpStatusCode?: unknown };
  };
  return (
    value.name === 'GoneException' ||
    value.statusCode === 410 ||
    value.$metadata?.httpStatusCode === 410
  );
}
