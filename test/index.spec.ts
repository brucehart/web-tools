import { env, createExecutionContext, waitOnExecutionContext, SELF } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import worker from '../src/index';

// For now, you'll need to do something like this to get a correctly-typed
// `Request` to pass to `worker.fetch()`.
const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;

describe('Tools index and Markdown viewer', () => {
  it('serves index page at / (unit)', async () => {
    const request = new IncomingRequest('http://example.com/');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>Web Tools</title>');
    expect(body).toContain('href="/markdown"');
    expect(body).toContain('href="/diff"');
    expect(body).toContain('href="/base64"');
    expect(body).toContain('href="/image-editor"');
    expect(body).toContain('href="/url-encode-decode"');
    expect(body).toContain('href="/area-code"');
    expect(body).toContain('href="/format-tools"');
    expect(body).toContain('href="/csv-editor"');
    expect(body).toContain('href="/boards"');
  });

  it('serves markdown viewer at /markdown (unit)', async () => {
    const request = new IncomingRequest('http://example.com/markdown');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>Markdown Viewer</title>');
    expect(body).toContain('textarea id="input"');
  });

  it('serves text diff at /diff (unit)', async () => {
    const request = new IncomingRequest('http://example.com/diff');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>Text Diff</title>');
    expect(body).toContain('id="originalInput"');
    expect(body).toContain('id="changedInput"');
  });

  it('serves format converter at /format-tools (unit)', async () => {
    const request = new IncomingRequest('http://example.com/format-tools');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>Data Format Converter</title>');
    expect(body).toContain('id="sourceFormat"');
    expect(body).toContain('id="targetFormat"');
  });

  it('serves base64 tool at /base64 (unit)', async () => {
    const request = new IncomingRequest('http://example.com/base64');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>Base64 Encoder/Decoder</title>');
    expect(body).toContain('id="dropZone"');
    expect(body).toContain('id="decodeInput"');
  });

  it('serves image editor at /image-editor (unit)', async () => {
    const request = new IncomingRequest('http://example.com/image-editor');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    expect(response.headers.get('cross-origin-opener-policy')).toBe('same-origin');
    expect(response.headers.get('cross-origin-embedder-policy')).toBe('require-corp');
    const body = await response.text();
    expect(body).toContain('<title>Image Editor</title>');
    expect(body).toContain('id="dropZone"');
    expect(body).toContain('id="scaleModePixels"');
    expect(body).toContain('id="scaleModePercent"');
    expect(body).toContain('id="aspectRatioSelect"');
    expect(body).toContain('id="resetScaleButton"');
    expect(body).toContain('id="scalePercentWidth"');
    expect(body).toContain('id="scalePercentHeight"');
    expect(body).toContain('id="scaleWidth"');
    expect(body).toContain('id="exportButton"');
    expect(body).toContain('id="copyImageButton"');
    expect(body).toContain('<option value="avif">AVIF</option>');
  });

  it('serves url encode/decode tool at /url-encode-decode (unit)', async () => {
    const request = new IncomingRequest('http://example.com/url-encode-decode');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>URL Encode/Decode</title>');
    expect(body).toContain('id="inputText"');
    expect(body).toContain('id="outputText"');
    expect(body).toContain('id="moveBtn"');
  });

  it('serves area code lookup at /area-code (unit)', async () => {
    const request = new IncomingRequest('http://example.com/area-code');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>Area Code Lookup</title>');
    expect(body).toContain('id="lookupInput"');
    expect(body).toContain('id="resultCard"');
    expect(body).toContain("window.addEventListener('DOMContentLoaded'");
  });

  it('serves area code lookup at /area-code/:code (unit)', async () => {
    const request = new IncomingRequest('http://example.com/area-code/937');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>Area Code Lookup</title>');
    expect(body).toContain('id="lookupInput"');
    expect(body).toContain('readPathLookup');
  });

  it('serves csv viewer and editor at /csv-editor (unit)', async () => {
    const request = new IncomingRequest('http://example.com/csv-editor');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>CSV Viewer &amp; Editor</title>');
    expect(body).toContain('id="csvInput"');
    expect(body).toContain('id="sheetHost"');
  });

  it('serves index page (integration)', async () => {
    const response = await SELF.fetch('https://example.com');
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>Web Tools</title>');
  });

  it('serves markdown viewer (integration)', async () => {
    const response = await SELF.fetch('https://example.com/markdown');
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>Markdown Viewer</title>');
  });

  it('serves text diff (integration)', async () => {
    const response = await SELF.fetch('https://example.com/diff');
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>Text Diff</title>');
  });

  it('serves format converter (integration)', async () => {
    const response = await SELF.fetch('https://example.com/format-tools');
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>Data Format Converter</title>');
  });

  it('serves base64 tool (integration)', async () => {
    const response = await SELF.fetch('https://example.com/base64');
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>Base64 Encoder/Decoder</title>');
  });

  it('serves image editor (integration)', async () => {
    const response = await SELF.fetch('https://example.com/image-editor');
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    expect(response.headers.get('cross-origin-opener-policy')).toBe('same-origin');
    expect(response.headers.get('cross-origin-embedder-policy')).toBe('require-corp');
    const body = await response.text();
    expect(body).toContain('<title>Image Editor</title>');
    expect(body).toContain('id="scaleModePixels"');
    expect(body).toContain('id="aspectRatioSelect"');
    expect(body).toContain('id="copyImageButton"');
    expect(body).toContain('<option value="avif">AVIF</option>');
  });

  it('serves image editor AVIF worker assets (integration)', async () => {
    const workerResponse = await SELF.fetch('https://example.com/workers/image-editor-avif-worker.mjs');
    expect(workerResponse.status).toBe(200);
    expect(workerResponse.headers.get('cross-origin-resource-policy')).toBe('same-origin');

    const wasmResponse = await SELF.fetch('https://example.com/vendor/jsquash-avif/codec/enc/avif_enc_mt.wasm');
    expect(wasmResponse.status).toBe(200);
    expect(wasmResponse.headers.get('cross-origin-resource-policy')).toBe('same-origin');
  });

  it('serves url encode/decode tool (integration)', async () => {
    const response = await SELF.fetch('https://example.com/url-encode-decode');
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>URL Encode/Decode</title>');
  });

  it('serves area code lookup (integration)', async () => {
    const response = await SELF.fetch('https://example.com/area-code');
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>Area Code Lookup</title>');
  });

  it('serves area code lookup at /area-code/:code (integration)', async () => {
    const response = await SELF.fetch('https://example.com/area-code/937');
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>Area Code Lookup</title>');
  });

  it('serves csv viewer and editor (integration)', async () => {
    const response = await SELF.fetch('https://example.com/csv-editor');
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>CSV Viewer &amp; Editor</title>');
  });

  it('serves actuary calculator at /actuary (unit)', async () => {
    const request = new IncomingRequest('http://example.com/actuary');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>Actuary Calculator</title>');
    expect(body).toContain('Actuary Calculator');
  });

  it('serves actuary calculator (integration)', async () => {
    const response = await SELF.fetch('https://example.com/actuary');
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>Actuary Calculator</title>');
  });

  it('rejects missing url for transcript API (unit)', async () => {
    const request = new IncomingRequest('http://example.com/api/yt-transcript', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ url: '' }),
    });
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(400);
    const json = await response.json();
    expect(json.error).toBe('url required');
  });

  it('uses the request host for Google OAuth callback when needed (unit)', async () => {
    const request = new IncomingRequest('https://tools.example.com/auth/google/login?returnTo=%2Fboards');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(302);
    const location = response.headers.get('location') || '';
    const oauthUrl = new URL(location);
    expect(oauthUrl.origin).toBe('https://accounts.google.com');
    expect(oauthUrl.searchParams.get('redirect_uri')).toBe('https://tools.example.com/auth/google/callback');
  });
});

describe('Pretty routes and Pages API', () => {
  it('serves todo list at /todo (unit)', async () => {
    const request = new IncomingRequest('http://example.com/todo');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>To-Do List</title>');
  });

  it('serves boards at /boards (unit)', async () => {
    const request = new IncomingRequest('http://example.com/boards');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>Boards</title>');
    expect(body).toContain('id="boardCanvas"');
  });

  it('rejects unauthenticated pages list', async () => {
    const request = new IncomingRequest('http://example.com/api/pages/list?tool=markdown');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(401);
  });

  it('rejects unauthenticated boards list', async () => {
    const request = new IncomingRequest('http://example.com/api/boards/list');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(401);
  });

  it('creates and fetches a markdown page (unit)', async () => {
    (env as any).INTERNAL_TEST_KEY = 'k';
    const seedReq = new IncomingRequest('http://example.com/api/_internal/seed', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-internal-key': 'k' },
      body: JSON.stringify({ email: 'user@example.com', name: 'User' }),
    });
    const seedCtx = createExecutionContext();
    const seedRes = await worker.fetch(seedReq, env, seedCtx);
    await waitOnExecutionContext(seedCtx);
    expect(seedRes.status).toBe(200);
    const seeded = await seedRes.json<any>();
    const token = String(seeded.token || '');
    expect(token).toContain('t_');

    const createReq = new IncomingRequest('http://example.com/api/pages/create', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: `wt_session=${token}` },
      body: JSON.stringify({ tool: 'markdown', title: 'Test', content: '# Hello' }),
    });
    const createCtx = createExecutionContext();
    const createRes = await worker.fetch(createReq, env, createCtx);
    await waitOnExecutionContext(createCtx);
    expect(createRes.status).toBe(200);
    const created = await createRes.json<any>();
    expect(typeof created.id).toBe('string');

    const listReq = new IncomingRequest('http://example.com/api/pages/list?tool=markdown', {
      headers: { cookie: `wt_session=${token}` },
    });
    const listCtx = createExecutionContext();
    const listRes = await worker.fetch(listReq, env, listCtx);
    await waitOnExecutionContext(listCtx);
    expect(listRes.status).toBe(200);
    const list = await listRes.json<any[]>();
    expect(list.some((r) => r.id === created.id)).toBe(true);

    const getReq = new IncomingRequest(`http://example.com/api/pages/get?id=${encodeURIComponent(created.id)}`, {
      headers: { cookie: `wt_session=${token}` },
    });
    const getCtx = createExecutionContext();
    const getRes = await worker.fetch(getReq, env, getCtx);
    await waitOnExecutionContext(getCtx);
    expect(getRes.status).toBe(200);
    const page = await getRes.json<any>();
    expect(page.id).toBe(created.id);
    expect(page.tool).toBe('markdown');
    expect(page.content).toBe('# Hello');
  });

  it('creates, reorders, and protects boards data (unit)', async () => {
    (env as any).INTERNAL_TEST_KEY = 'k';

    const seedOneReq = new IncomingRequest('http://example.com/api/_internal/seed', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-internal-key': 'k' },
      body: JSON.stringify({ email: 'boards-one@example.com', name: 'Boards One' }),
    });
    const seedOneCtx = createExecutionContext();
    const seedOneRes = await worker.fetch(seedOneReq, env, seedOneCtx);
    await waitOnExecutionContext(seedOneCtx);
    expect(seedOneRes.status).toBe(200);
    const userOne = await seedOneRes.json<any>();
    const tokenOne = String(userOne.token || '');

    const seedTwoReq = new IncomingRequest('http://example.com/api/_internal/seed', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-internal-key': 'k' },
      body: JSON.stringify({ email: 'boards-two@example.com', name: 'Boards Two' }),
    });
    const seedTwoCtx = createExecutionContext();
    const seedTwoRes = await worker.fetch(seedTwoReq, env, seedTwoCtx);
    await waitOnExecutionContext(seedTwoCtx);
    expect(seedTwoRes.status).toBe(200);
    const userTwo = await seedTwoRes.json<any>();
    const tokenTwo = String(userTwo.token || '');

    const createBoardReq = new IncomingRequest('http://example.com/api/boards/create', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: `wt_session=${tokenOne}` },
      body: JSON.stringify({ title: 'Project Alpha', description: 'Initial board' }),
    });
    const createBoardCtx = createExecutionContext();
    const createBoardRes = await worker.fetch(createBoardReq, env, createBoardCtx);
    await waitOnExecutionContext(createBoardCtx);
    expect(createBoardRes.status).toBe(200);
    const createdBoard = await createBoardRes.json<any>();
    expect(typeof createdBoard.id).toBe('string');

    const listBoardsReq = new IncomingRequest('http://example.com/api/boards/list', {
      headers: { cookie: `wt_session=${tokenOne}` },
    });
    const listBoardsCtx = createExecutionContext();
    const listBoardsRes = await worker.fetch(listBoardsReq, env, listBoardsCtx);
    await waitOnExecutionContext(listBoardsCtx);
    expect(listBoardsRes.status).toBe(200);
    const boards = await listBoardsRes.json<any[]>();
    expect(boards.some((board) => board.id === createdBoard.id)).toBe(true);

    const createTodoListReq = new IncomingRequest('http://example.com/api/boards/lists/create', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: `wt_session=${tokenOne}` },
      body: JSON.stringify({ board_id: createdBoard.id, title: 'To do' }),
    });
    const createTodoListCtx = createExecutionContext();
    const createTodoListRes = await worker.fetch(createTodoListReq, env, createTodoListCtx);
    await waitOnExecutionContext(createTodoListCtx);
    expect(createTodoListRes.status).toBe(200);
    const todoList = await createTodoListRes.json<any>();

    const createDoingListReq = new IncomingRequest('http://example.com/api/boards/lists/create', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: `wt_session=${tokenOne}` },
      body: JSON.stringify({ board_id: createdBoard.id, title: 'Doing' }),
    });
    const createDoingListCtx = createExecutionContext();
    const createDoingListRes = await worker.fetch(createDoingListReq, env, createDoingListCtx);
    await waitOnExecutionContext(createDoingListCtx);
    expect(createDoingListRes.status).toBe(200);
    const doingList = await createDoingListRes.json<any>();

    const createCardReq = new IncomingRequest('http://example.com/api/boards/cards/create', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: `wt_session=${tokenOne}` },
      body: JSON.stringify({ list_id: todoList.id, title: 'Write spec', markdown: '# Ready' }),
    });
    const createCardCtx = createExecutionContext();
    const createCardRes = await worker.fetch(createCardReq, env, createCardCtx);
    await waitOnExecutionContext(createCardCtx);
    expect(createCardRes.status).toBe(200);
    const cardOne = await createCardRes.json<any>();

    const createCardTwoReq = new IncomingRequest('http://example.com/api/boards/cards/create', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: `wt_session=${tokenOne}` },
      body: JSON.stringify({ list_id: todoList.id, title: 'Ship feature', markdown: 'Needs polish' }),
    });
    const createCardTwoCtx = createExecutionContext();
    const createCardTwoRes = await worker.fetch(createCardTwoReq, env, createCardTwoCtx);
    await waitOnExecutionContext(createCardTwoCtx);
    expect(createCardTwoRes.status).toBe(200);
    const cardTwo = await createCardTwoRes.json<any>();

    const moveCardReq = new IncomingRequest('http://example.com/api/boards/cards/move', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: `wt_session=${tokenOne}` },
      body: JSON.stringify({
        card_id: cardOne.id,
        to_list_id: doingList.id,
        source_card_ids: [cardTwo.id],
        destination_card_ids: [cardOne.id],
      }),
    });
    const moveCardCtx = createExecutionContext();
    const moveCardRes = await worker.fetch(moveCardReq, env, moveCardCtx);
    await waitOnExecutionContext(moveCardCtx);
    expect(moveCardRes.status).toBe(200);

    const addImageReq = new IncomingRequest('http://example.com/api/boards/cards/images/add', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: `wt_session=${tokenOne}` },
      body: JSON.stringify({
        card_id: cardOne.id,
        data_url: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9s2m30QAAAAASUVORK5CYII=',
        alt_text: 'pixel',
      }),
    });
    const addImageCtx = createExecutionContext();
    const addImageRes = await worker.fetch(addImageReq, env, addImageCtx);
    await waitOnExecutionContext(addImageCtx);
    expect(addImageRes.status).toBe(200);
    const addedImage = await addImageRes.json<any>();
    expect(typeof addedImage.id).toBe('string');

    const oversizedImageReq = new IncomingRequest('http://example.com/api/boards/cards/images/add', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: `wt_session=${tokenOne}` },
      body: JSON.stringify({
        card_id: cardOne.id,
        data_url: 'data:image/png;base64,' + 'A'.repeat(1_500_000),
      }),
    });
    const oversizedImageCtx = createExecutionContext();
    const oversizedImageRes = await worker.fetch(oversizedImageReq, env, oversizedImageCtx);
    await waitOnExecutionContext(oversizedImageCtx);
    expect(oversizedImageRes.status).toBe(400);

    const getBoardReq = new IncomingRequest(`http://example.com/api/boards/get?id=${encodeURIComponent(createdBoard.id)}`, {
      headers: { cookie: `wt_session=${tokenOne}` },
    });
    const getBoardCtx = createExecutionContext();
    const getBoardRes = await worker.fetch(getBoardReq, env, getBoardCtx);
    await waitOnExecutionContext(getBoardCtx);
    expect(getBoardRes.status).toBe(200);
    const hydratedBoard = await getBoardRes.json<any>();
    expect(hydratedBoard.board.id).toBe(createdBoard.id);
    expect(hydratedBoard.lists).toHaveLength(2);
    const hydratedDoing = hydratedBoard.lists.find((list) => list.id === doingList.id);
    const hydratedTodo = hydratedBoard.lists.find((list) => list.id === todoList.id);
    expect(hydratedDoing.cards).toHaveLength(1);
    expect(hydratedDoing.cards[0].id).toBe(cardOne.id);
    expect(hydratedDoing.cards[0].images).toHaveLength(1);
    expect(hydratedTodo.cards).toHaveLength(1);
    expect(hydratedTodo.cards[0].id).toBe(cardTwo.id);

    const forbiddenGetReq = new IncomingRequest(`http://example.com/api/boards/get?id=${encodeURIComponent(createdBoard.id)}`, {
      headers: { cookie: `wt_session=${tokenTwo}` },
    });
    const forbiddenGetCtx = createExecutionContext();
    const forbiddenGetRes = await worker.fetch(forbiddenGetReq, env, forbiddenGetCtx);
    await waitOnExecutionContext(forbiddenGetCtx);
    expect(forbiddenGetRes.status).toBe(404);
  });
});
