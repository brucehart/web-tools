import { requireUser } from './auth';
import { badRequest, json, readJson } from './utils/http';
import { urlSafeRandom } from './utils/random';
import type { Bindings, HandlerResult } from './types';

type GoalStatus = 'complete' | 'partial' | 'missed';

interface GoalRow {
  id: string;
  name: string;
  created_at: string;
}

interface EntryRow {
  goal_id: string;
  day: string;
  status: GoalStatus;
}

async function createGoal(env: Bindings, userId: string, name: string): Promise<Response> {
  if (!name) return badRequest('name required');

  for (let i = 0; i < 5; i += 1) {
    const id = urlSafeRandom(12);
    const exists = await env.DB.prepare('SELECT id FROM goals WHERE id = ?').bind(id).first();
    if (exists) continue;

    await env.DB.prepare('INSERT INTO goals (id, user_id, name) VALUES (?, ?, ?)')
      .bind(id, userId, name)
      .run();

    return json({ id });
  }

  return badRequest('Failed to allocate id', 500);
}

async function listGoals(env: Bindings, userId: string): Promise<Response> {
  const goalsRes = await env.DB.prepare('SELECT id, name, created_at FROM goals WHERE user_id = ? ORDER BY created_at')
    .bind(userId)
    .all();
  const goals = (goalsRes.results || []) as GoalRow[];

  const entriesRes = await env.DB.prepare('SELECT goal_id, day, status FROM goal_entries WHERE user_id = ?')
    .bind(userId)
    .all();
  const entries = (entriesRes.results || []) as EntryRow[];

  const entryMap: Record<string, Record<string, GoalStatus>> = {};
  for (const entry of entries) {
    if (!entryMap[entry.goal_id]) entryMap[entry.goal_id] = {};
    entryMap[entry.goal_id][entry.day] = entry.status;
  }

  return json({
    goals: goals.map((goal) => ({
      id: goal.id,
      name: goal.name,
      created_at: goal.created_at,
      entries: entryMap[goal.id] || {},
    })),
  });
}

async function deleteGoal(env: Bindings, userId: string, id: string): Promise<Response> {
  if (!id) return badRequest('id required');
  const goal = await env.DB.prepare('SELECT user_id FROM goals WHERE id = ?').bind(id).first();
  if (!goal) return new Response('Not found', { status: 404 });
  if ((goal as any).user_id !== userId) return new Response('Forbidden', { status: 403 });

  await env.DB.prepare('DELETE FROM goal_entries WHERE goal_id = ?').bind(id).run();
  await env.DB.prepare('DELETE FROM goals WHERE id = ?').bind(id).run();

  return json({ ok: true });
}

async function setEntry(env: Bindings, userId: string, goalId: string, day: string, status: string): Promise<Response> {
  if (!goalId) return badRequest('goal_id required');
  if (!day || !/^\d{4}-\d{2}-\d{2}$/.test(day)) return badRequest('day must be YYYY-MM-DD');

  const goal = await env.DB.prepare('SELECT user_id FROM goals WHERE id = ?').bind(goalId).first();
  if (!goal) return new Response('Not found', { status: 404 });
  if ((goal as any).user_id !== userId) return new Response('Forbidden', { status: 403 });

  if (!['complete', 'partial', 'missed', 'none'].includes(status)) {
    return badRequest('invalid status');
  }

  if (status === 'none') {
    await env.DB.prepare('DELETE FROM goal_entries WHERE goal_id = ? AND day = ?')
      .bind(goalId, day)
      .run();
    return json({ ok: true, status: 'none' });
  }

  await env.DB.prepare(
    "INSERT INTO goal_entries (goal_id, user_id, day, status) VALUES (?, ?, ?, ?) ON CONFLICT(goal_id, day) DO UPDATE SET status = excluded.status, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')",
  )
    .bind(goalId, userId, day, status)
    .run();

  return json({ ok: true, status });
}

export async function handleGoalApi(request: Request, env: Bindings, url: URL): Promise<HandlerResult> {
  const path = url.pathname;

  if (path === '/api/goals/create' && request.method === 'POST') {
    const user = await requireUser(request, env);
    if (user instanceof Response) return user;
    const body = await readJson<{ name?: string }>(request);
    const name = (body.name || '').toString().trim();
    return createGoal(env, (user as any).id, name);
  }

  if (path === '/api/goals/list' && request.method === 'GET') {
    const user = await requireUser(request, env);
    if (user instanceof Response) return user;
    return listGoals(env, (user as any).id);
  }

  if (path === '/api/goals/delete' && request.method === 'POST') {
    const user = await requireUser(request, env);
    if (user instanceof Response) return user;
    const body = await readJson<{ id?: string }>(request);
    const id = (body.id || '').toString();
    return deleteGoal(env, (user as any).id, id);
  }

  if (path === '/api/goals/entry' && request.method === 'POST') {
    const user = await requireUser(request, env);
    if (user instanceof Response) return user;
    const body = await readJson<{ goal_id?: string; day?: string; status?: string }>(request);
    const goalId = (body.goal_id || '').toString();
    const day = (body.day || '').toString();
    const status = (body.status || '').toString();
    return setEntry(env, (user as any).id, goalId, day, status);
  }

  return null;
}
