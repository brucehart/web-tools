import { requireUser } from './auth';
import { badRequest, json, readJson } from './utils/http';
import { urlSafeRandom } from './utils/random';
import type { Bindings, HandlerResult } from './types';

type BoardRow = {
	id: string;
	user_id: string;
	title: string;
	description: string | null;
	sort_order: number;
	created_at: string;
	updated_at: string;
};

type BoardListRow = {
	id: string;
	board_id: string;
	title: string;
	sort_order: number;
	created_at: string;
	updated_at: string;
};

type BoardCardRow = {
	id: string;
	board_id: string;
	list_id: string;
	title: string;
	markdown: string;
	sort_order: number;
	created_at: string;
	updated_at: string;
};

type CardImageRow = {
	id: string;
	card_id: string;
	mime_type: string;
	data_url: string;
	alt_text: string | null;
	sort_order: number;
	created_at: string;
};

const MAX_BOARD_TITLE_LENGTH = 120;
const MAX_BOARD_DESCRIPTION_LENGTH = 500;
const MAX_LIST_TITLE_LENGTH = 120;
const MAX_CARD_TITLE_LENGTH = 160;
const MAX_CARD_MARKDOWN_LENGTH = 30_000;
const MAX_IMAGE_BYTES = 1_024 * 1_024;
const MAX_IMAGES_PER_CARD = 3;
const NOW_SQL = "strftime('%Y-%m-%dT%H:%M:%SZ','now')";
const ALLOWED_IMAGE_MIME_TYPES = new Set(['image/png', 'image/jpeg', 'image/webp', 'image/gif', 'image/avif']);

function normalizeId(value: unknown): string {
	return String(value || '').trim();
}

function clampTitle(value: unknown, fallback: string, maxLength: number): string {
	const title = String(value || '').trim();
	return (title || fallback).slice(0, maxLength);
}

function clampOptionalText(value: unknown, maxLength: number): string | null {
	if (value === undefined || value === null) return null;
	const text = String(value).trim();
	return text ? text.slice(0, maxLength) : null;
}

function validateMarkdown(value: unknown): string | Response {
	const markdown = String(value || '');
	if (markdown.length > MAX_CARD_MARKDOWN_LENGTH) {
		return badRequest(`markdown exceeds ${MAX_CARD_MARKDOWN_LENGTH} characters`);
	}
	return markdown;
}

function parseIdArray(value: unknown): string[] {
	if (!Array.isArray(value)) return [];
	return value.map((entry) => normalizeId(entry)).filter(Boolean);
}

function hasExactIds(actualIds: string[], providedIds: string[]): boolean {
	if (actualIds.length !== providedIds.length) return false;
	const uniqueProvided = new Set(providedIds);
	if (uniqueProvided.size !== providedIds.length) return false;
	const actualSet = new Set(actualIds);
	return providedIds.every((id) => actualSet.has(id));
}

function parseImageDataUrl(dataUrl: string): { mimeType: string; byteLength: number } | null {
	const trimmed = dataUrl.trim();
	const match = trimmed.match(/^data:([^;,]+);base64,([A-Za-z0-9+/=]+)$/);
	if (!match) return null;
	const mimeType = match[1].toLowerCase();
	const base64 = match[2];
	const padding = base64.match(/=+$/)?.[0].length || 0;
	const byteLength = Math.floor((base64.length * 3) / 4) - padding;
	return { mimeType, byteLength };
}

async function allocateId(env: Bindings, existsSql: string): Promise<string | null> {
	for (let i = 0; i < 5; i += 1) {
		const id = urlSafeRandom(12);
		const exists = await env.DB.prepare(existsSql).bind(id).first();
		if (!exists) return id;
	}
	return null;
}

async function runStatements(env: Bindings, statements: D1PreparedStatement[]): Promise<void> {
	if (!statements.length) return;
	await env.DB.batch(statements);
}

function touchBoardStatement(env: Bindings, boardId: string): D1PreparedStatement {
	return env.DB.prepare(`UPDATE boards SET updated_at = ${NOW_SQL} WHERE id = ?`).bind(boardId);
}

function touchListStatement(env: Bindings, listId: string): D1PreparedStatement {
	return env.DB.prepare(`UPDATE board_lists SET updated_at = ${NOW_SQL} WHERE id = ?`).bind(listId);
}

function touchCardStatement(env: Bindings, cardId: string): D1PreparedStatement {
	return env.DB.prepare(`UPDATE board_cards SET updated_at = ${NOW_SQL} WHERE id = ?`).bind(cardId);
}

async function getOwnedBoard(env: Bindings, userId: string, boardId: string): Promise<BoardRow | null> {
	return (await env.DB.prepare(
		'SELECT id, user_id, title, description, sort_order, created_at, updated_at FROM boards WHERE id = ? AND user_id = ?',
	)
		.bind(boardId, userId)
		.first()) as BoardRow | null;
}

async function getOwnedList(env: Bindings, userId: string, listId: string): Promise<BoardListRow | null> {
	return (await env.DB.prepare(
		`SELECT l.id, l.board_id, l.title, l.sort_order, l.created_at, l.updated_at
     FROM board_lists l
     JOIN boards b ON b.id = l.board_id
     WHERE l.id = ? AND b.user_id = ?`,
	)
		.bind(listId, userId)
		.first()) as BoardListRow | null;
}

async function getOwnedCard(env: Bindings, userId: string, cardId: string): Promise<BoardCardRow | null> {
	return (await env.DB.prepare(
		`SELECT c.id, c.board_id, c.list_id, c.title, c.markdown, c.sort_order, c.created_at, c.updated_at
     FROM board_cards c
     JOIN boards b ON b.id = c.board_id
     WHERE c.id = ? AND b.user_id = ?`,
	)
		.bind(cardId, userId)
		.first()) as BoardCardRow | null;
}

async function getOwnedImage(
	env: Bindings,
	userId: string,
	imageId: string,
): Promise<(CardImageRow & { board_id: string; list_id: string }) | null> {
	return (await env.DB.prepare(
		`SELECT i.id, i.card_id, i.mime_type, i.data_url, i.alt_text, i.sort_order, i.created_at, c.board_id, c.list_id
     FROM card_images i
     JOIN board_cards c ON c.id = i.card_id
     JOIN boards b ON b.id = c.board_id
     WHERE i.id = ? AND b.user_id = ?`,
	)
		.bind(imageId, userId)
		.first()) as (CardImageRow & { board_id: string; list_id: string }) | null;
}

async function listIdsForBoard(env: Bindings, boardId: string): Promise<string[]> {
	const rows = await env.DB.prepare('SELECT id FROM board_lists WHERE board_id = ? ORDER BY sort_order ASC, created_at ASC')
		.bind(boardId)
		.all<{ id: string }>();
	return (rows.results || []).map((row) => row.id);
}

async function cardIdsForList(env: Bindings, listId: string, excludeCardId?: string): Promise<string[]> {
	let sql = 'SELECT id FROM board_cards WHERE list_id = ?';
	const values: unknown[] = [listId];
	if (excludeCardId) {
		sql += ' AND id != ?';
		values.push(excludeCardId);
	}
	sql += ' ORDER BY sort_order ASC, created_at ASC';
	const rows = await env.DB.prepare(sql)
		.bind(...values)
		.all<{ id: string }>();
	return (rows.results || []).map((row) => row.id);
}

function reorderListStatements(env: Bindings, boardId: string, listIds: string[]): D1PreparedStatement[] {
	return listIds.map((listId, index) =>
		env.DB.prepare(`UPDATE board_lists SET sort_order = ?, updated_at = ${NOW_SQL} WHERE id = ? AND board_id = ?`).bind(
			index,
			listId,
			boardId,
		),
	);
}

function reorderCardStatements(env: Bindings, listId: string, cardIds: string[]): D1PreparedStatement[] {
	return cardIds.map((cardId, index) =>
		env.DB.prepare(`UPDATE board_cards SET sort_order = ?, updated_at = ${NOW_SQL} WHERE id = ? AND list_id = ?`).bind(
			index,
			cardId,
			listId,
		),
	);
}

function reorderImageStatements(env: Bindings, cardId: string, imageIds: string[]): D1PreparedStatement[] {
	return imageIds.map((imageId, index) =>
		env.DB.prepare('UPDATE card_images SET sort_order = ? WHERE id = ? AND card_id = ?').bind(index, imageId, cardId),
	);
}

async function listBoards(env: Bindings, userId: string): Promise<Response> {
	const rows = await env.DB.prepare(
		`SELECT b.id, b.title, b.description, b.sort_order, b.created_at, b.updated_at,
      (SELECT COUNT(*) FROM board_lists l WHERE l.board_id = b.id) AS list_count,
      (SELECT COUNT(*) FROM board_cards c WHERE c.board_id = b.id) AS card_count
     FROM boards b
     WHERE b.user_id = ?
     ORDER BY b.sort_order ASC, b.updated_at DESC
     LIMIT 100`,
	)
		.bind(userId)
		.all();
	return json(rows.results || []);
}

async function createBoard(request: Request, env: Bindings, userId: string): Promise<Response> {
	const body = await readJson<{ title?: string; description?: string }>(request);
	const id = await allocateId(env, 'SELECT id FROM boards WHERE id = ?');
	if (!id) return badRequest('Failed to allocate board id', 500);
	const title = clampTitle(body.title, 'Untitled board', MAX_BOARD_TITLE_LENGTH);
	const description = clampOptionalText(body.description, MAX_BOARD_DESCRIPTION_LENGTH);
	await env.DB.prepare(
		`INSERT INTO boards (id, user_id, title, description, sort_order)
     VALUES (?, ?, ?, ?, COALESCE((SELECT MAX(sort_order) + 1 FROM boards WHERE user_id = ?), 0))`,
	)
		.bind(id, userId, title, description, userId)
		.run();
	return json({ id });
}

async function updateBoard(request: Request, env: Bindings, userId: string): Promise<Response> {
	const body = await readJson<{ id?: string; title?: string; description?: string | null }>(request);
	const id = normalizeId(body.id);
	if (!id) return badRequest('id required');
	const board = await getOwnedBoard(env, userId, id);
	if (!board) return new Response('Not found', { status: 404 });

	const updates: string[] = [];
	const values: unknown[] = [];

	if (body.title !== undefined) {
		updates.push('title = ?');
		values.push(clampTitle(body.title, 'Untitled board', MAX_BOARD_TITLE_LENGTH));
	}
	if (body.description !== undefined) {
		updates.push('description = ?');
		values.push(clampOptionalText(body.description, MAX_BOARD_DESCRIPTION_LENGTH));
	}
	if (updates.length === 0) return badRequest('No fields to update');

	updates.push(`updated_at = ${NOW_SQL}`);
	values.push(id, userId);
	await env.DB.prepare(`UPDATE boards SET ${updates.join(', ')} WHERE id = ? AND user_id = ?`)
		.bind(...values)
		.run();
	return json({ ok: true });
}

async function deleteBoard(request: Request, env: Bindings, userId: string): Promise<Response> {
	const body = await readJson<{ id?: string }>(request);
	const id = normalizeId(body.id);
	if (!id) return badRequest('id required');
	const board = await getOwnedBoard(env, userId, id);
	if (!board) return new Response('Not found', { status: 404 });

	await runStatements(env, [
		env.DB.prepare('DELETE FROM card_images WHERE card_id IN (SELECT id FROM board_cards WHERE board_id = ?)').bind(id),
		env.DB.prepare('DELETE FROM board_cards WHERE board_id = ?').bind(id),
		env.DB.prepare('DELETE FROM board_lists WHERE board_id = ?').bind(id),
		env.DB.prepare('DELETE FROM boards WHERE id = ? AND user_id = ?').bind(id, userId),
	]);
	return json({ ok: true });
}

async function getBoard(env: Bindings, userId: string, boardId: string): Promise<Response> {
	if (!boardId) return badRequest('id required');
	const board = await getOwnedBoard(env, userId, boardId);
	if (!board) return new Response('Not found', { status: 404 });

	const listsResult = await env.DB.prepare(
		'SELECT id, board_id, title, sort_order, created_at, updated_at FROM board_lists WHERE board_id = ? ORDER BY sort_order ASC, created_at ASC',
	)
		.bind(boardId)
		.all<BoardListRow>();
	const cardsResult = await env.DB.prepare(
		'SELECT id, board_id, list_id, title, markdown, sort_order, created_at, updated_at FROM board_cards WHERE board_id = ? ORDER BY sort_order ASC, created_at ASC',
	)
		.bind(boardId)
		.all<BoardCardRow>();
	const imagesResult = await env.DB.prepare(
		`SELECT i.id, i.card_id, i.mime_type, i.data_url, i.alt_text, i.sort_order, i.created_at
     FROM card_images i
     JOIN board_cards c ON c.id = i.card_id
     WHERE c.board_id = ?
     ORDER BY i.sort_order ASC, i.created_at ASC`,
	)
		.bind(boardId)
		.all<CardImageRow>();

	const imagesByCard = new Map<string, CardImageRow[]>();
	for (const image of imagesResult.results || []) {
		if (!imagesByCard.has(image.card_id)) imagesByCard.set(image.card_id, []);
		imagesByCard.get(image.card_id)?.push(image);
	}

	const cardsByList = new Map<string, Array<BoardCardRow & { images: CardImageRow[] }>>();
	for (const card of cardsResult.results || []) {
		if (!cardsByList.has(card.list_id)) cardsByList.set(card.list_id, []);
		cardsByList.get(card.list_id)?.push({
			...card,
			images: imagesByCard.get(card.id) || [],
		});
	}

	return json({
		board,
		lists: (listsResult.results || []).map((list) => ({
			...list,
			cards: cardsByList.get(list.id) || [],
		})),
	});
}

async function createList(request: Request, env: Bindings, userId: string): Promise<Response> {
	const body = await readJson<{ board_id?: string; title?: string }>(request);
	const boardId = normalizeId(body.board_id);
	if (!boardId) return badRequest('board_id required');
	const board = await getOwnedBoard(env, userId, boardId);
	if (!board) return new Response('Not found', { status: 404 });

	const id = await allocateId(env, 'SELECT id FROM board_lists WHERE id = ?');
	if (!id) return badRequest('Failed to allocate list id', 500);
	const title = clampTitle(body.title, 'Untitled list', MAX_LIST_TITLE_LENGTH);
	await runStatements(env, [
		env.DB.prepare(
			`INSERT INTO board_lists (id, board_id, title, sort_order)
       VALUES (?, ?, ?, COALESCE((SELECT MAX(sort_order) + 1 FROM board_lists WHERE board_id = ?), 0))`,
		).bind(id, boardId, title, boardId),
		touchBoardStatement(env, boardId),
	]);
	return json({ id });
}

async function updateList(request: Request, env: Bindings, userId: string): Promise<Response> {
	const body = await readJson<{ id?: string; title?: string }>(request);
	const id = normalizeId(body.id);
	if (!id) return badRequest('id required');
	const list = await getOwnedList(env, userId, id);
	if (!list) return new Response('Not found', { status: 404 });
	await runStatements(env, [
		env.DB.prepare(`UPDATE board_lists SET title = ?, updated_at = ${NOW_SQL} WHERE id = ?`).bind(
			clampTitle(body.title, 'Untitled list', MAX_LIST_TITLE_LENGTH),
			id,
		),
		touchBoardStatement(env, list.board_id),
	]);
	return json({ ok: true });
}

async function deleteList(request: Request, env: Bindings, userId: string): Promise<Response> {
	const body = await readJson<{ id?: string }>(request);
	const id = normalizeId(body.id);
	if (!id) return badRequest('id required');
	const list = await getOwnedList(env, userId, id);
	if (!list) return new Response('Not found', { status: 404 });
	const remainingIds = (await listIdsForBoard(env, list.board_id)).filter((listId) => listId !== id);

	await runStatements(env, [
		env.DB.prepare('DELETE FROM card_images WHERE card_id IN (SELECT id FROM board_cards WHERE list_id = ?)').bind(id),
		env.DB.prepare('DELETE FROM board_cards WHERE list_id = ?').bind(id),
		env.DB.prepare('DELETE FROM board_lists WHERE id = ?').bind(id),
		...reorderListStatements(env, list.board_id, remainingIds),
		touchBoardStatement(env, list.board_id),
	]);
	return json({ ok: true });
}

async function reorderBoardLists(request: Request, env: Bindings, userId: string): Promise<Response> {
	const body = await readJson<{ board_id?: string; list_ids?: string[] }>(request);
	const boardId = normalizeId(body.board_id);
	if (!boardId) return badRequest('board_id required');
	const board = await getOwnedBoard(env, userId, boardId);
	if (!board) return new Response('Not found', { status: 404 });
	const listIds = parseIdArray(body.list_ids);
	const actualIds = await listIdsForBoard(env, boardId);
	if (!hasExactIds(actualIds, listIds)) return badRequest('list_ids do not match the board lists');
	await runStatements(env, [...reorderListStatements(env, boardId, listIds), touchBoardStatement(env, boardId)]);
	return json({ ok: true });
}

async function createCard(request: Request, env: Bindings, userId: string): Promise<Response> {
	const body = await readJson<{ list_id?: string; title?: string; markdown?: string }>(request);
	const listId = normalizeId(body.list_id);
	if (!listId) return badRequest('list_id required');
	const list = await getOwnedList(env, userId, listId);
	if (!list) return new Response('Not found', { status: 404 });
	const markdown = validateMarkdown(body.markdown);
	if (markdown instanceof Response) return markdown;
	const id = await allocateId(env, 'SELECT id FROM board_cards WHERE id = ?');
	if (!id) return badRequest('Failed to allocate card id', 500);
	await runStatements(env, [
		env.DB.prepare(
			`INSERT INTO board_cards (id, board_id, list_id, title, markdown, sort_order)
       VALUES (?, ?, ?, ?, ?, COALESCE((SELECT MAX(sort_order) + 1 FROM board_cards WHERE list_id = ?), 0))`,
		).bind(id, list.board_id, listId, clampTitle(body.title, 'Untitled card', MAX_CARD_TITLE_LENGTH), markdown, listId),
		touchListStatement(env, listId),
		touchBoardStatement(env, list.board_id),
	]);
	return json({ id });
}

async function updateCard(request: Request, env: Bindings, userId: string): Promise<Response> {
	const body = await readJson<{ id?: string; title?: string; markdown?: string }>(request);
	const id = normalizeId(body.id);
	if (!id) return badRequest('id required');
	const card = await getOwnedCard(env, userId, id);
	if (!card) return new Response('Not found', { status: 404 });

	const updates: string[] = [];
	const values: unknown[] = [];

	if (body.title !== undefined) {
		updates.push('title = ?');
		values.push(clampTitle(body.title, 'Untitled card', MAX_CARD_TITLE_LENGTH));
	}
	if (body.markdown !== undefined) {
		const markdown = validateMarkdown(body.markdown);
		if (markdown instanceof Response) return markdown;
		updates.push('markdown = ?');
		values.push(markdown);
	}
	if (updates.length === 0) return badRequest('No fields to update');

	updates.push(`updated_at = ${NOW_SQL}`);
	values.push(id);
	await runStatements(env, [
		env.DB.prepare(`UPDATE board_cards SET ${updates.join(', ')} WHERE id = ?`).bind(...values),
		touchListStatement(env, card.list_id),
		touchBoardStatement(env, card.board_id),
	]);
	return json({ ok: true });
}

async function deleteCard(request: Request, env: Bindings, userId: string): Promise<Response> {
	const body = await readJson<{ id?: string }>(request);
	const id = normalizeId(body.id);
	if (!id) return badRequest('id required');
	const card = await getOwnedCard(env, userId, id);
	if (!card) return new Response('Not found', { status: 404 });
	const remainingIds = (await cardIdsForList(env, card.list_id)).filter((cardId) => cardId !== id);

	await runStatements(env, [
		env.DB.prepare('DELETE FROM card_images WHERE card_id = ?').bind(id),
		env.DB.prepare('DELETE FROM board_cards WHERE id = ?').bind(id),
		...reorderCardStatements(env, card.list_id, remainingIds),
		touchListStatement(env, card.list_id),
		touchBoardStatement(env, card.board_id),
	]);
	return json({ ok: true });
}

async function reorderCards(request: Request, env: Bindings, userId: string): Promise<Response> {
	const body = await readJson<{ list_id?: string; card_ids?: string[] }>(request);
	const listId = normalizeId(body.list_id);
	if (!listId) return badRequest('list_id required');
	const list = await getOwnedList(env, userId, listId);
	if (!list) return new Response('Not found', { status: 404 });
	const cardIds = parseIdArray(body.card_ids);
	const actualIds = await cardIdsForList(env, listId);
	if (!hasExactIds(actualIds, cardIds)) return badRequest('card_ids do not match the list cards');
	await runStatements(env, [
		...reorderCardStatements(env, listId, cardIds),
		touchListStatement(env, listId),
		touchBoardStatement(env, list.board_id),
	]);
	return json({ ok: true });
}

async function moveCard(request: Request, env: Bindings, userId: string): Promise<Response> {
	const body = await readJson<{
		card_id?: string;
		to_list_id?: string;
		source_card_ids?: string[];
		destination_card_ids?: string[];
	}>(request);
	const cardId = normalizeId(body.card_id);
	const toListId = normalizeId(body.to_list_id);
	if (!cardId) return badRequest('card_id required');
	if (!toListId) return badRequest('to_list_id required');

	const card = await getOwnedCard(env, userId, cardId);
	if (!card) return new Response('Not found', { status: 404 });
	const destinationList = await getOwnedList(env, userId, toListId);
	if (!destinationList) return new Response('Not found', { status: 404 });
	if (destinationList.board_id !== card.board_id) {
		return badRequest('cannot move cards across boards');
	}

	const destinationCardIds = parseIdArray(body.destination_card_ids);
	if (destinationList.id === card.list_id) {
		const actualIds = await cardIdsForList(env, card.list_id);
		if (!hasExactIds(actualIds, destinationCardIds) || !destinationCardIds.includes(card.id)) {
			return badRequest('destination_card_ids do not match the list cards');
		}
		await runStatements(env, [
			...reorderCardStatements(env, card.list_id, destinationCardIds),
			touchListStatement(env, card.list_id),
			touchBoardStatement(env, card.board_id),
		]);
		return json({ ok: true });
	}

	const sourceCardIds = parseIdArray(body.source_card_ids);
	const actualSourceIds = await cardIdsForList(env, card.list_id, card.id);
	const actualDestinationIds = await cardIdsForList(env, destinationList.id);
	if (!hasExactIds(actualSourceIds, sourceCardIds)) {
		return badRequest('source_card_ids do not match the source list cards');
	}
	if (!destinationCardIds.includes(card.id)) {
		return badRequest('destination_card_ids must include the moved card');
	}
	if (!hasExactIds([...actualDestinationIds, card.id], destinationCardIds)) {
		return badRequest('destination_card_ids do not match the destination list cards');
	}

	await runStatements(env, [
		env.DB.prepare(`UPDATE board_cards SET list_id = ?, sort_order = -1, updated_at = ${NOW_SQL} WHERE id = ?`).bind(
			destinationList.id,
			card.id,
		),
		...reorderCardStatements(env, card.list_id, sourceCardIds),
		...reorderCardStatements(env, destinationList.id, destinationCardIds),
		touchListStatement(env, card.list_id),
		touchListStatement(env, destinationList.id),
		touchBoardStatement(env, card.board_id),
	]);
	return json({ ok: true });
}

async function addCardImage(request: Request, env: Bindings, userId: string): Promise<Response> {
	const body = await readJson<{ card_id?: string; data_url?: string; alt_text?: string }>(request);
	const cardId = normalizeId(body.card_id);
	if (!cardId) return badRequest('card_id required');
	const card = await getOwnedCard(env, userId, cardId);
	if (!card) return new Response('Not found', { status: 404 });
	const dataUrl = String(body.data_url || '').trim();
	if (!dataUrl) return badRequest('data_url required');
	const parsed = parseImageDataUrl(dataUrl);
	if (!parsed) return badRequest('data_url must be a base64 image data URL');
	if (!ALLOWED_IMAGE_MIME_TYPES.has(parsed.mimeType)) {
		return badRequest('unsupported image type');
	}
	if (parsed.byteLength > MAX_IMAGE_BYTES) {
		return badRequest(`image exceeds ${MAX_IMAGE_BYTES} bytes`);
	}
	const countRow = await env.DB.prepare('SELECT COUNT(*) AS count FROM card_images WHERE card_id = ?')
		.bind(cardId)
		.first<{ count: number | string }>();
	const count = Number(countRow?.count || 0);
	if (count >= MAX_IMAGES_PER_CARD) {
		return badRequest(`cards can have at most ${MAX_IMAGES_PER_CARD} images`);
	}
	const id = await allocateId(env, 'SELECT id FROM card_images WHERE id = ?');
	if (!id) return badRequest('Failed to allocate image id', 500);
	await runStatements(env, [
		env.DB.prepare(
			`INSERT INTO card_images (id, card_id, mime_type, data_url, alt_text, sort_order)
       VALUES (?, ?, ?, ?, ?, COALESCE((SELECT MAX(sort_order) + 1 FROM card_images WHERE card_id = ?), 0))`,
		).bind(id, cardId, parsed.mimeType, dataUrl, clampOptionalText(body.alt_text, 200), cardId),
		touchCardStatement(env, cardId),
		touchListStatement(env, card.list_id),
		touchBoardStatement(env, card.board_id),
	]);
	return json({ id });
}

async function deleteCardImage(request: Request, env: Bindings, userId: string): Promise<Response> {
	const body = await readJson<{ id?: string }>(request);
	const id = normalizeId(body.id);
	if (!id) return badRequest('id required');
	const image = await getOwnedImage(env, userId, id);
	if (!image) return new Response('Not found', { status: 404 });
	const remainingRows = await env.DB.prepare('SELECT id FROM card_images WHERE card_id = ? ORDER BY sort_order ASC, created_at ASC')
		.bind(image.card_id)
		.all<{ id: string }>();
	const remainingIds = (remainingRows.results || []).map((row) => row.id).filter((imageId) => imageId !== id);

	await runStatements(env, [
		env.DB.prepare('DELETE FROM card_images WHERE id = ?').bind(id),
		...reorderImageStatements(env, image.card_id, remainingIds),
		touchCardStatement(env, image.card_id),
		touchListStatement(env, image.list_id),
		touchBoardStatement(env, image.board_id),
	]);
	return json({ ok: true });
}

export async function handleBoardsApi(request: Request, env: Bindings, url: URL): Promise<HandlerResult> {
	const path = url.pathname;

	if (path === '/api/boards/list' && request.method === 'GET') {
		const user = await requireUser(request, env);
		if (user instanceof Response) return user;
		return listBoards(env, user.id);
	}

	if (path === '/api/boards/create' && request.method === 'POST') {
		const user = await requireUser(request, env);
		if (user instanceof Response) return user;
		return createBoard(request, env, user.id);
	}

	if (path === '/api/boards/update' && request.method === 'POST') {
		const user = await requireUser(request, env);
		if (user instanceof Response) return user;
		return updateBoard(request, env, user.id);
	}

	if (path === '/api/boards/delete' && request.method === 'POST') {
		const user = await requireUser(request, env);
		if (user instanceof Response) return user;
		return deleteBoard(request, env, user.id);
	}

	if (path === '/api/boards/get' && request.method === 'GET') {
		const user = await requireUser(request, env);
		if (user instanceof Response) return user;
		return getBoard(env, user.id, normalizeId(url.searchParams.get('id')));
	}

	if (path === '/api/boards/lists/create' && request.method === 'POST') {
		const user = await requireUser(request, env);
		if (user instanceof Response) return user;
		return createList(request, env, user.id);
	}

	if (path === '/api/boards/lists/update' && request.method === 'POST') {
		const user = await requireUser(request, env);
		if (user instanceof Response) return user;
		return updateList(request, env, user.id);
	}

	if (path === '/api/boards/lists/delete' && request.method === 'POST') {
		const user = await requireUser(request, env);
		if (user instanceof Response) return user;
		return deleteList(request, env, user.id);
	}

	if (path === '/api/boards/lists/reorder' && request.method === 'POST') {
		const user = await requireUser(request, env);
		if (user instanceof Response) return user;
		return reorderBoardLists(request, env, user.id);
	}

	if (path === '/api/boards/cards/create' && request.method === 'POST') {
		const user = await requireUser(request, env);
		if (user instanceof Response) return user;
		return createCard(request, env, user.id);
	}

	if (path === '/api/boards/cards/update' && request.method === 'POST') {
		const user = await requireUser(request, env);
		if (user instanceof Response) return user;
		return updateCard(request, env, user.id);
	}

	if (path === '/api/boards/cards/delete' && request.method === 'POST') {
		const user = await requireUser(request, env);
		if (user instanceof Response) return user;
		return deleteCard(request, env, user.id);
	}

	if (path === '/api/boards/cards/reorder' && request.method === 'POST') {
		const user = await requireUser(request, env);
		if (user instanceof Response) return user;
		return reorderCards(request, env, user.id);
	}

	if (path === '/api/boards/cards/move' && request.method === 'POST') {
		const user = await requireUser(request, env);
		if (user instanceof Response) return user;
		return moveCard(request, env, user.id);
	}

	if (path === '/api/boards/cards/images/add' && request.method === 'POST') {
		const user = await requireUser(request, env);
		if (user instanceof Response) return user;
		return addCardImage(request, env, user.id);
	}

	if (path === '/api/boards/cards/images/delete' && request.method === 'POST') {
		const user = await requireUser(request, env);
		if (user instanceof Response) return user;
		return deleteCardImage(request, env, user.id);
	}

	return null;
}
