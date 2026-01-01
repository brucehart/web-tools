import { handleAuthRoutes } from './auth';
import { handlePastebinApi, handlePastebinPage } from './pastebin';
import { handleGoalApi } from './goals';
import { handleTodoApi } from './todo';
import { handleTranscriptApi } from './routes/transcript';
import { serveStatic } from './static';
import type { Bindings, WorkerExport } from './types';

export default {
  async fetch(request, env, _ctx): Promise<Response> {
    const bindings = env as unknown as Bindings;
    const url = new URL(request.url);

    const authResponse = await handleAuthRoutes(request, bindings, url);
    if (authResponse) return authResponse;

    const pastebinApiResponse = await handlePastebinApi(request, bindings, url);
    if (pastebinApiResponse) return pastebinApiResponse;

    const goalApiResponse = await handleGoalApi(request, bindings, url);
    if (goalApiResponse) return goalApiResponse;

    const todoApiResponse = await handleTodoApi(request, bindings, url);
    if (todoApiResponse) return todoApiResponse;

    const transcriptResponse = await handleTranscriptApi(request, bindings, url);
    if (transcriptResponse) return transcriptResponse;

    const pastebinPageResponse = await handlePastebinPage(request, bindings, url);
    if (pastebinPageResponse) return pastebinPageResponse;

    return serveStatic(request, bindings, url);
  },
} satisfies WorkerExport;
