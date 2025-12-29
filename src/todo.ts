import { requireUser } from './auth';
import { badRequest, json, readJson } from './utils/http';
import { urlSafeRandom } from './utils/random';
import type { Bindings, HandlerResult } from './types';

type Priority = 'low' | 'medium' | 'high';
type Category = 'personal' | 'work' | 'projects' | 'shopping' | 'health' | 'finance' | 'other';

const VALID_CATEGORIES: Category[] = ['personal', 'work', 'projects', 'shopping', 'health', 'finance', 'other'];

interface Todo {
    id: string;
    user_id: string;
    title: string;
    description: string | null;
    completed: number;
    priority: Priority;
    category: Category;
    due_date: string | null;
    created_at: string;
    updated_at: string;
}

async function createTodo(
    env: Bindings,
    userId: string,
    title: string,
    description: string | null,
    priority: Priority,
    category: Category,
    dueDate: string | null,
): Promise<Response> {
    if (!title) return badRequest('title required');
    for (let i = 0; i < 5; i++) {
        const id = urlSafeRandom(12);
        const exists = await env.DB.prepare('SELECT id FROM todos WHERE id = ?').bind(id).first();
        if (exists) continue;
        await env.DB.prepare(
            'INSERT INTO todos (id, user_id, title, description, priority, category, due_date) VALUES (?, ?, ?, ?, ?, ?, ?)',
        )
            .bind(id, userId, title, description, priority, category, dueDate)
            .run();
        return json({ id });
    }
    return badRequest('Failed to allocate id', 500);
}

async function listTodos(env: Bindings, userId: string): Promise<Response> {
    // Order by: incomplete first, then priority (high->medium->low), then due_date (earliest first, nulls last)
    const rows = await env.DB.prepare(
        `SELECT id, title, description, completed, priority, category, due_date, created_at, updated_at 
     FROM todos WHERE user_id = ? 
     ORDER BY completed ASC, 
              CASE priority WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 END, 
              CASE WHEN due_date IS NULL THEN 1 ELSE 0 END, 
              due_date ASC,
              created_at DESC 
     LIMIT 500`,
    )
        .bind(userId)
        .all();
    return json(rows.results || []);
}

async function getTodo(env: Bindings, userId: string, id: string): Promise<Response> {
    if (!id) return badRequest('id required');
    const row = (await env.DB.prepare(
        'SELECT id, title, description, completed, priority, category, due_date, created_at, updated_at FROM todos WHERE id = ? AND user_id = ?',
    )
        .bind(id, userId)
        .first()) as Todo | null;
    if (!row) return new Response('Not found', { status: 404 });
    return json(row);
}

async function updateTodo(
    request: Request,
    env: Bindings,
    userId: string,
): Promise<Response> {
    const body = await readJson<{
        id?: string;
        title?: string;
        description?: string;
        completed?: boolean;
        priority?: Priority;
        category?: Category;
        due_date?: string | null;
    }>(request);
    const id = (body.id || '').toString();
    if (!id) return badRequest('id required');

    const row = (await env.DB.prepare('SELECT user_id FROM todos WHERE id = ?').bind(id).first()) as any;
    if (!row) return new Response('Not found', { status: 404 });
    if (row.user_id !== userId) return new Response('Forbidden', { status: 403 });

    const updates: string[] = [];
    const values: any[] = [];

    if (body.title !== undefined) {
        if (!body.title) return badRequest('title cannot be empty');
        updates.push('title = ?');
        values.push(body.title);
    }
    if (body.description !== undefined) {
        updates.push('description = ?');
        values.push(body.description || null);
    }
    if (body.completed !== undefined) {
        updates.push('completed = ?');
        values.push(body.completed ? 1 : 0);
    }
    if (body.priority !== undefined) {
        if (!['low', 'medium', 'high'].includes(body.priority)) {
            return badRequest('priority must be low, medium, or high');
        }
        updates.push('priority = ?');
        values.push(body.priority);
    }
    if (body.due_date !== undefined) {
        updates.push('due_date = ?');
        values.push(body.due_date || null);
    }
    if (body.category !== undefined) {
        if (!VALID_CATEGORIES.includes(body.category)) {
            return badRequest('category must be personal, work, shopping, health, finance, or other');
        }
        updates.push('category = ?');
        values.push(body.category);
    }

    if (updates.length === 0) {
        return badRequest('No fields to update');
    }

    updates.push("updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')");
    values.push(id);

    await env.DB.prepare(`UPDATE todos SET ${updates.join(', ')} WHERE id = ?`)
        .bind(...values)
        .run();

    return json({ ok: true });
}

async function deleteTodo(request: Request, env: Bindings, userId: string): Promise<Response> {
    const body = await readJson<{ id?: string }>(request);
    const id = (body.id || '').toString();
    if (!id) return badRequest('id required');
    const row = (await env.DB.prepare('SELECT user_id FROM todos WHERE id = ?').bind(id).first()) as any;
    if (!row) return new Response('Not found', { status: 404 });
    if (row.user_id !== userId) return new Response('Forbidden', { status: 403 });
    await env.DB.prepare('DELETE FROM todos WHERE id = ?').bind(id).run();
    return json({ ok: true });
}

async function toggleTodo(request: Request, env: Bindings, userId: string): Promise<Response> {
    const body = await readJson<{ id?: string }>(request);
    const id = (body.id || '').toString();
    if (!id) return badRequest('id required');
    const row = (await env.DB.prepare('SELECT user_id, completed FROM todos WHERE id = ?').bind(id).first()) as any;
    if (!row) return new Response('Not found', { status: 404 });
    if (row.user_id !== userId) return new Response('Forbidden', { status: 403 });
    const newCompleted = row.completed ? 0 : 1;
    await env.DB.prepare("UPDATE todos SET completed = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id = ?")
        .bind(newCompleted, id)
        .run();
    return json({ ok: true, completed: !!newCompleted });
}

export async function handleTodoApi(
    request: Request,
    env: Bindings,
    url: URL,
): Promise<HandlerResult> {
    const path = url.pathname;

    if (path === '/api/todo/create' && request.method === 'POST') {
        const user = await requireUser(request, env);
        if (user instanceof Response) return user;
        const body = await readJson<{
            title?: string;
            description?: string;
            priority?: Priority;
            category?: Category;
            due_date?: string;
        }>(request);
        const title = (body.title || '').toString().trim();
        const description = body.description ? body.description.toString() : null;
        const priority: Priority =
            body.priority === 'low' ? 'low' : body.priority === 'high' ? 'high' : 'medium';
        const category: Category = VALID_CATEGORIES.includes(body.category as Category)
            ? (body.category as Category)
            : 'personal';
        const dueDate = body.due_date ? body.due_date.toString() : null;
        return createTodo(env, (user as any).id, title, description, priority, category, dueDate);
    }

    if (path === '/api/todo/list' && request.method === 'GET') {
        const user = await requireUser(request, env);
        if (user instanceof Response) return user;
        return listTodos(env, (user as any).id);
    }

    if (path === '/api/todo/get' && request.method === 'GET') {
        const user = await requireUser(request, env);
        if (user instanceof Response) return user;
        const id = url.searchParams.get('id') || '';
        return getTodo(env, (user as any).id, id);
    }

    if (path === '/api/todo/update' && request.method === 'POST') {
        const user = await requireUser(request, env);
        if (user instanceof Response) return user;
        return updateTodo(request, env, (user as any).id);
    }

    if (path === '/api/todo/delete' && request.method === 'POST') {
        const user = await requireUser(request, env);
        if (user instanceof Response) return user;
        return deleteTodo(request, env, (user as any).id);
    }

    if (path === '/api/todo/toggle' && request.method === 'POST') {
        const user = await requireUser(request, env);
        if (user instanceof Response) return user;
        return toggleTodo(request, env, (user as any).id);
    }

    return null;
}
