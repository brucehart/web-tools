import { handleAuthRoutes } from './auth';
import { handleInternalTestRoutes } from './internal-test';
import { handlePagesApi } from './pages';
import { handlePastebinApi, handlePastebinPage } from './pastebin';
import { handleTodoApi } from './todo';
import { handleTranscriptApi } from './routes/transcript';
import { serveStatic } from './static';
import type { Bindings, WorkerExport } from './types';

export default {
  async fetch(request, env, _ctx): Promise<Response> {
    const bindings = env as unknown as Bindings;
    const url = new URL(request.url);

    const internalTestResponse = await handleInternalTestRoutes(request, bindings, url);
    if (internalTestResponse) return internalTestResponse;

    const authResponse = await handleAuthRoutes(request, bindings, url);
    if (authResponse) return authResponse;

    const pagesApiResponse = await handlePagesApi(request, bindings, url);
    if (pagesApiResponse) return pagesApiResponse;

    const pastebinApiResponse = await handlePastebinApi(request, bindings, url);
    if (pastebinApiResponse) return pastebinApiResponse;

    const todoApiResponse = await handleTodoApi(request, bindings, url);
    if (todoApiResponse) return todoApiResponse;

    const transcriptResponse = await handleTranscriptApi(request, bindings, url);
    if (transcriptResponse) return transcriptResponse;

    const pastebinPageResponse = await handlePastebinPage(request, bindings, url);
    if (pastebinPageResponse) return pastebinPageResponse;

    return serveStatic(request, bindings, url);
  },
} satisfies WorkerExport;
