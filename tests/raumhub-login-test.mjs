import { test } from 'node:test'; import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite'; import { readFileSync, writeFileSync } from 'node:fs'; import { createHash } from 'node:crypto';
const SRC = process.env.WSRC;
writeFileSync(new URL('./w-under-test.mjs', import.meta.url), readFileSync(SRC, 'utf8') + '\nexport { d1SchemaSql_, W_INIT_SQL_ };\n');
const mod = await import('./w-under-test.mjs?' + Date.now());
const sha = s => createHash('sha256').update(s).digest('hex');
function makeEnv() {
  const db = new DatabaseSync(':memory:');
  for (const q of mod.d1SchemaSql_()) db.exec(q); for (const q of mod.W_INIT_SQL_) db.exec(q);
  const stmt = (sql, args = []) => ({ sql, args, bind: (...a) => stmt(sql, a) });
  const DB = { raw: db, prepare: sql => stmt(sql), async batch(list) { return list.map(s => /^\s*SELECT/i.test(s.sql) ? { results: db.prepare(s.sql).all(...s.args).map(r => ({ ...r })) } : { meta: { changes: Number(db.prepare(s.sql).run(...s.args).changes) } }); } };
  const add = (id, name, role, code, exp) => db.prepare('INSERT INTO members (id,name,role,groups,active,invite_hash,invite_expires,token_hashes) VALUES (?,?,?,?,?,?,?,?)').run(id, name, role, '[]', 1, code ? sha(id + ':' + code) : '', exp || new Date(Date.now() + 864e5).toISOString(), '[]');
  add('m1', 'Lea', 'leader', '123456'); add('m2', 'Tom', 'member', '654321');
  return { DB, ALLOWED_ORIGINS: 'https://otierdei.github.io', add };
}
const call = async (env, body, ip = '9.9.9.9') => (await (await mod.default.fetch(new Request('https://w.test/', { method: 'POST', headers: { 'CF-Connecting-IP': ip, Origin: 'https://otierdei.github.io' }, body: JSON.stringify(body) }), env)).json());

test('names: keine Liste ohne id, nur der eigene Name mit id', async () => {
  const env = makeEnv();
  assert.deepEqual((await call(env, { action: 'names' })).data, []);
  assert.deepEqual((await call(env, { action: 'names', member: 'm2' })).data, [{ id: 'm2', name: 'Tom' }]);
  assert.deepEqual((await call(env, { action: 'names', member: 'gibtsnicht' })).data, []);
});
test('alter 6 stelliger Code geht noch, Token mit Ablauf, Code danach höchstens 1 Stunde gültig', async () => {
  const env = makeEnv();
  const r = await call(env, { action: 'login', member: 'm1', code: '123456' });
  assert.equal(r.ok, true); assert.ok(r.data.token);
  const row = env.DB.raw.prepare("SELECT token_hashes, invite_expires FROM members WHERE id='m1'").get();
  const th = JSON.parse(row.token_hashes); assert.equal(th.length, 1); assert.match(th[0], /^[0-9a-f]{64}~\d{13}$/);
  assert.ok(Date.parse(row.invite_expires) - Date.now() <= 3600e3 + 1000);
  assert.equal((await call(env, { action: 'bootstrap', token: r.data.token })).ok, true);
  assert.equal((await call(env, { action: 'bootstrap', token: 'falsch' })).error, 'auth');
});
test('abgelaufenes Token wird abgelehnt, altes Token ohne Ablauf gilt bis zum Stichtag, Abmelden entfernt nur das eigene', async () => {
  const env = makeEnv();
  const set = v => env.DB.raw.prepare("UPDATE members SET token_hashes=? WHERE id='m2'").run(JSON.stringify(v));
  set([sha('alt')]); assert.equal((await call(env, { action: 'bootstrap', token: 'alt' })).ok, true);
  set([sha('alt') + '~' + (Date.now() - 1000)]); assert.equal((await call(env, { action: 'bootstrap', token: 'alt' })).error, 'auth');
  set([sha('a') + '~' + (Date.now() + 1e6), sha('b') + '~' + (Date.now() + 1e6)]);
  assert.equal((await call(env, { action: 'logout', token: 'a' })).ok, true);
  assert.equal((await call(env, { action: 'bootstrap', token: 'a' })).error, 'auth');
  assert.equal((await call(env, { action: 'bootstrap', token: 'b' })).ok, true);
});
test('Sperre pro Mitglied nach 5 und pro IP nach 20 Fehlversuchen, mitgeschickte IP zählt nicht', async () => {
  const env = makeEnv();
  for (let i = 0; i < 5; i++) assert.equal((await call(env, { action: 'login', member: 'm2', code: '000000' }, '1.1.1.' + i)).error, 'bad_code');
  assert.equal((await call(env, { action: 'login', member: 'm2', code: '654321' }, '1.1.1.99')).error, 'locked');
  const e2 = makeEnv(); for (let i = 0; i < 25; i++) e2.add('x' + i, 'X', 'member', '111111');
  for (let i = 0; i < 20; i++) assert.equal((await call(e2, { action: 'login', member: 'x' + i, code: '000000', __ip: 'gefälscht' + i }, '5.5.5.5')).error, 'bad_code');
  assert.equal((await call(e2, { action: 'login', member: 'x22', code: '111111', __ip: 'anders' }, '5.5.5.5')).error, 'locked');
  assert.equal((await call(e2, { action: 'login', member: 'x23', code: '111111' }, '6.6.6.6')).ok, true);
});
test('neue Einladung: 8 Ziffern, Login damit geht', async () => {
  const env = makeEnv();
  const t = (await call(env, { action: 'login', member: 'm1', code: '123456' })).data.token;
  const codes = new Set();
  for (let i = 0; i < 30; i++) { const inv = await call(env, { action: 'invite', token: t, id: 'm2' }); assert.equal(inv.ok, true, JSON.stringify(inv)); assert.match(inv.data.code, /^\d{8}$/); codes.add(inv.data.code); var last = inv.data.code; }
  assert.equal(codes.size, 30);
  assert.equal((await call(env, { action: 'login', member: 'm2', code: last })).ok, true);
});
test('ohne id: Anmeldung nur mit 8 stelligem Code, 6 stellig geht nicht, eigene Sperre', async () => {
  const env = makeEnv(); env.add('m3', 'Ida', 'member', '12345678');
  assert.equal((await call(env, { action: 'login', code: '123456' }, '7.7.7.1')).error, 'bad_code');
  const r = await call(env, { action: 'login', code: '12345678' }, '7.7.7.2');
  assert.equal(r.ok, true); assert.equal(r.data.data.me.id, 'm3');
  const e2 = makeEnv(); e2.add('m3', 'Ida', 'member', '12345678');
  for (let i = 0; i < 60; i++) assert.equal((await call(e2, { action: 'login', code: '00000000' }, '8.8.' + (i % 200) + '.' + i)).error, 'bad_code');
  assert.equal((await call(e2, { action: 'login', code: '12345678' }, '8.9.9.9')).error, 'locked');
  assert.equal((await call(e2, { action: 'login', member: 'm3', code: '12345678' }, '8.9.9.8')).ok, true);
});
test('fertige Projekte ablegen und wieder öffnen (18.11.2026), nur Leitung und Mitte', async () => {
  const env = makeEnv();
  const lt = (await call(env, { action: 'login', member: 'm1', code: '123456' })).data.token;
  const mt = (await call(env, { action: 'login', member: 'm2', code: '654321' })).data.token;
  assert.equal((await call(env, { action: 'saveProject', token: lt, project: { id: 'p1', title: 'Social Media', when: 'laufend', note: '' } })).ok, true);
  assert.deepEqual((await call(env, { action: 'bootstrap', token: lt })).data.projectsDone, []);
  assert.equal((await call(env, { action: 'setProjectDone', token: mt, id: 'p1', done: true })).ok, false, 'Mitglied darf nicht');
  assert.deepEqual((await call(env, { action: 'setProjectDone', token: lt, id: 'p1', done: true })).data.done, ['p1']);
  assert.deepEqual((await call(env, { action: 'bootstrap', token: mt })).data.projectsDone, ['p1']);
  assert.ok((await call(env, { action: 'bootstrap', token: lt })).data.projects.some((p) => p.id === 'p1'), 'Projekt bleibt erhalten');
  assert.equal((await call(env, { action: 'setProjectDone', token: lt, id: 'gibtsnicht', done: true })).ok, false);
  assert.deepEqual((await call(env, { action: 'setProjectDone', token: lt, id: 'p1', done: false })).data.done, []);
});
test('Gebet: ausdrückliche Einwilligung nötig, Widerruf löscht eigene Beiträge, Kommentare und Zusagen (18.11.2026)', async () => {
  const env = makeEnv();
  const lt = (await call(env, { action: 'login', member: 'm1', code: '123456' })).data.token;
  const mt = (await call(env, { action: 'login', member: 'm2', code: '654321' })).data.token;
  assert.equal((await call(env, { action: 'bootstrap', token: lt })).data.prayerConsent, null);
  assert.equal((await call(env, { action: 'addPrayer', token: lt, kind: 'anliegen', text: 'Bitte betet' })).ok, false, 'ohne Einwilligung nicht');
  assert.equal((await call(env, { action: 'prayerConsent', token: lt, on: true, text_version: 'alt' })).ok, false, 'alte Textfassung nicht');
  assert.equal((await call(env, { action: 'prayerConsent', token: lt, on: true, text_version: '2026-11-18' })).ok, true);
  assert.equal((await call(env, { action: 'bootstrap', token: lt })).data.prayerConsent.v, '2026-11-18');
  const p1 = (await call(env, { action: 'addPrayer', token: lt, kind: 'anliegen', text: 'Lea Anliegen' })).data.id;
  await call(env, { action: 'prayerConsent', token: mt, on: true, text_version: '2026-11-18' });
  const p2 = (await call(env, { action: 'addPrayer', token: mt, kind: 'dank', text: 'Tom Dank' })).data.id;
  await call(env, { action: 'commentPrayer', token: lt, id: p2, text: 'Amen' });
  await call(env, { action: 'reactPrayer', token: lt, id: p2, pray: true });
  const w = (await call(env, { action: 'prayerConsent', token: lt, on: false })).data;
  assert.equal(w.deleted, 1); assert.equal(w.changed, 1);
  const d = (await call(env, { action: 'bootstrap', token: mt })).data;
  assert.ok(!d.prayer.some((p) => p.id === p1), 'eigener Beitrag gelöscht');
  const t = d.prayer.find((p) => p.id === p2); assert.equal(t.comments.length, 0); assert.deepEqual(t.pray, []);
  assert.equal((await call(env, { action: 'commentPrayer', token: lt, id: p2, text: 'nochmal' })).ok, false, 'nach Widerruf wieder gesperrt');
});
test('Protokoll: Einträge älter als 24 Monate werden gelöscht', async () => {
  const env = makeEnv();
  await call(env, { action: 'login', member: 'm1', code: '123456' });
  env.DB.raw.prepare('INSERT INTO log (at, by, action, entity, id, summary) VALUES (?,?,?,?,?,?)').run('2020-01-01T00:00:00.000Z', 'm1', 'x', 'songs', 's', 'alt');
  const tasks = []; const ctx = { waitUntil: (p) => tasks.push(p) };
  const real = Math.random; Math.random = () => 0;
  try { await mod.default.fetch(new Request('https://w.test/', { method: 'POST', headers: { Origin: 'https://otierdei.github.io' }, body: JSON.stringify({ action: 'names' }) }), env, ctx); } finally { Math.random = real; }
  await Promise.all(tasks);
  assert.equal(env.DB.raw.prepare("SELECT count(*) AS n FROM log WHERE summary = 'alt'").get().n, 0);
  assert.ok(env.DB.raw.prepare('SELECT count(*) AS n FROM log').get().n >= 1, 'neue Einträge bleiben');
});
