export type Bindings = Env & {
  DB: D1Database;
  ASSETS: Fetcher;
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
  OAUTH_REDIRECT_URL?: string;
  SESSION_COOKIE_NAME?: string;
};

export type HandlerResult = Response | null;

export type RouteHandler = (
  request: Request,
  env: Bindings,
  ctx: ExecutionContext,
  url: URL,
) => Promise<Response | null> | Response | null;

export type WorkerExport = ExportedHandler<Env>;
