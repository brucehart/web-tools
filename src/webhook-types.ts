export type StoredValue = string | string[];

export interface WebhookEvent {
  id: string;
  method: string;
  path: string;
  headers: Record<string, StoredValue>;
  query: Record<string, StoredValue>;
  body: string;
  ip: string | null;
  created_at: string;
}
