// Real loopback API + Chromium. Only independent synthetic data; no raw output.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdtemp, rm} from 'node:fs/promises';
import {createServer} from 'node:net';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {chromium} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

const root = resolve(import.meta.dirname, '..');
const temporary = await mkdtemp(join(tmpdir(), 'asla-mapping-browser-'));
const socket = createServer();
await new Promise((done) => socket.listen(0, '127.0.0.1', done));
const port = socket.address().port;
await new Promise((done) => socket.close(done));
const origin = `http://127.0.0.1:${port}`;
const endpoint = '/api/v1/investigations/json-mapping';
const child = spawn(join(root, '.venv/bin/python'), ['-m', 'uvicorn', 'app.api:app',
  '--host', '127.0.0.1', '--port', String(port), '--no-proxy-headers', '--no-access-log', '--log-level', 'critical'],
{cwd: root, stdio: 'ignore'});
let browser;
let page;
const canary = 'UNSELECTED_MAPPING_VALUE_CANARY';
const rows = ['/normal?q=green+tea', '/download?file=..%2Fprivate',
  '/catalog?id=8%27%20OR%202%3D2', '/preview?x=%3Cscript%3Echeck()%3C/script%3E']
  .map((target, i) => ({when: '2026-04-09T10:00:00+09:00', peer: `192.0.2.${171 + i}`,
    verb: 'GET', target, code: 200, unselected: canary}));
const mapping = [['timestamp', 'when'], ['source-ip', 'peer'], ['method', 'verb'], ['request-uri', 'target'], ['status', 'code']];
const posts = [];
const consoleMessages = [];
const pageErrors = [];
let external = 0;
let scans = 0;
async function chooseFields() {
  await page.locator('#json-mapping-discover').click();
  for (const [meaning, key] of mapping) {
    const select = page.locator(`#json-map-${meaning}`);
    await select.focus();
    // Native select type-ahead, including each required meaning.
    await page.keyboard.press(key[0]);
    await page.keyboard.press('Tab');
    assert.equal(await select.inputValue(), key);
  }
}
async function enterMapping() {
  await page.locator('#nav-local').click();
  const details = page.locator('#local-choice-details');
  if (!(await details.evaluate((node) => node.open))) await details.locator('summary').click();
  await page.locator('#input-mode-mapping').check();
}
async function scanAndReflow(label) {
  for (const width of [1440, 768, 320]) {
    await page.setViewportSize({width, height: 900});
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, `${label}: document overflow ${width}`);
    assert.equal(await page.locator('#json-mapping-panel').evaluate((node) => node.scrollWidth > node.clientWidth + 1), false, `${label}: panel overflow ${width}`);
    const result = await new AxeBuilder({page}).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
    assert.deepEqual(result.violations.map((v) => v.id), [], `${label}: axe ${width}`);
    scans++;
  }
  await page.setViewportSize({width: 1440, height: 900});
}
try {
  for (let i = 0; i < 120; i++) {
    if (child.exitCode !== null) throw new Error('server exited');
    try { if ((await fetch(`${origin}/api/health`)).ok) break; } catch { /* startup */ }
    await new Promise((done) => setTimeout(done, 50));
  }
  browser = await chromium.launch({headless: true});
  const context = await browser.newContext({acceptDownloads: true});
  await context.route('**/*', async (route) => {
    if (new URL(route.request().url()).origin !== origin) { external++; return route.abort(); }
    await route.continue();
  });
  page = await context.newPage();
  page.on('dialog', (dialog) => dialog.accept());
  page.on('console', (message) => consoleMessages.push(message.text()));
  page.on('pageerror', (error) => pageErrors.push(error.name));
  page.on('request', (request) => { if (request.method() === 'POST') posts.push(new URL(request.url()).pathname); });
  await page.goto(origin, {waitUntil: 'networkidle'});
  await enterMapping();
  await page.locator('#json-mapping-discover').click();
  assert.match(await page.locator('#json-mapping-error').textContent(), /비었|공백/);
  assert.equal(await page.locator('#json-mapping-error').evaluate((node) => node === document.activeElement), true);
  await page.locator('#json-mapping-text').fill('not JSON');
  await page.locator('#json-mapping-discover').click();
  assert.match(await page.locator('#json-mapping-error').textContent(), /각 줄/);
  await page.locator('#json-mapping-text').fill(rows.map((r) => JSON.stringify(r)).join('\n'));
  await page.locator('#json-mapping-discover').click();
  assert.equal(posts.length, 0);
  for (const [meaning] of mapping) assert.equal(await page.locator(`#json-map-${meaning}`).inputValue(), '');
  assert.equal(await page.locator('#json-mapping-confirm').isChecked(), false);
  assert.equal(await page.locator('#json-mapping-confirm').isDisabled(), true);
  await chooseFields();
  assert.equal(await page.locator('#json-mapping-confirm').isChecked(), false);
  assert.equal((await page.locator('#json-mapping-preview').textContent()).includes(canary), false);
  assert.equal(await page.locator('#json-mapping-panel').evaluate((node, value) => node.textContent.includes(value), canary), false);
  await page.locator('#local-button').click();
  assert.equal(posts.length, 0);
  assert.match(await page.locator('#json-mapping-error').textContent(), /체크/);
  await page.locator('#json-map-status').selectOption('verb');
  assert.equal(await page.locator('#json-mapping-confirm').isDisabled(), true);
  await page.locator('#json-map-status').selectOption('code');
  await scanAndReflow('approved-fields-unconfirmed');
  await page.locator('#json-mapping-confirm').focus();
  await page.keyboard.press('Space');
  const success = page.waitForResponse((r) => r.url().endsWith(endpoint));
  await page.locator('#local-button').click();
  const response = await success;
  assert.equal(response.status(), 200);
  const body = await response.json();
  assert.equal(body.result.analysis_summary.supported_detection_count, 3);
  assert.equal(body.result.input_quality.aggregate.recognized_lines, 4);
  assert.equal(JSON.stringify(body).includes(canary), false);
  assert.equal(JSON.stringify(body).includes('192.0.2.171'), false);
  await page.locator('#results').waitFor({state: 'visible'});
  assert.equal(await page.locator('#json-mapping-result-notice').isVisible(), true);
  assert.equal(await page.locator('#json-mapping-text').inputValue(), '');
  assert.equal(await page.locator('#json-map-timestamp option').count(), 1);
  const download = page.waitForEvent('download');
  await page.locator('#report-button').click();
  const report = await download;
  assert.equal(report.failure && await report.failure(), null);
  await enterMapping();
  // Invalid type passes key discovery but server must reject the entire sample.
  await page.locator('#json-mapping-text').fill(JSON.stringify(rows[0]) + '\n' + JSON.stringify({...rows[1], code: '200'}));
  await chooseFields();
  await page.locator('#json-mapping-confirm').check();
  const rejected = page.waitForResponse((r) => r.url().endsWith(endpoint));
  await page.locator('#local-button').click();
  assert.equal((await rejected).status(), 400);
  await page.locator('#error-summary').waitFor({state: 'visible'});
  assert.equal(await page.locator('#results').isHidden(), true);
  assert.equal(await page.locator('#json-mapping-text').inputValue(), '');
  assert.equal(await page.locator('#json-mapping-confirm').isChecked(), false);
  await enterMapping();
  await page.locator('#json-mapping-text').fill(JSON.stringify(rows[0]));
  await chooseFields();
  // Editing requires fresh discovery and fresh approval.
  await page.locator('#json-mapping-confirm').check();
  await page.locator('#json-mapping-text').fill(JSON.stringify(rows[1]));
  assert.equal(await page.locator('#json-mapping-confirm').isDisabled(), true);
  await page.locator('#input-mode-text').check();
  assert.equal(await page.locator('#json-mapping-text').inputValue(), '');
  await page.locator('#text-source input[value="access"]').check();
  await page.locator('#log-text').fill('192.0.2.179 - - [09/Apr/2026:01:00:00 +0000] "GET /health HTTP/1.1" 200 20');
  const textSuccess = page.waitForResponse((r) => r.url().endsWith('/investigations/text'));
  await page.locator('#local-button').click();
  assert.equal((await textSuccess).status(), 200);
  await page.locator('#results').waitFor({state: 'visible'});
  assert.equal(await page.locator('#json-mapping-result-notice').isHidden(), true);
  await page.locator('#nav-local').click();
  await page.locator('#input-mode-file').check();
  for (const [id, name] of [['application-file', 'brute_force.log'], ['ssh-file', 'ssh_auth.log'], ['access-file', 'web_shell.log']])
    await page.locator(`#${id}`).setInputFiles(join(root, 'sample_logs', name));
  const fileSuccess = page.waitForResponse((r) => new URL(r.url()).pathname === '/api/v1/investigations');
  await page.locator('#local-button').click();
  assert.equal((await fileSuccess).status(), 200);
  await page.locator('#results').waitFor({state: 'visible'});
  await enterMapping();
  await page.locator('#json-mapping-text').fill(JSON.stringify(rows[0]));
  await page.locator('#nav-start').click();
  assert.equal(await page.locator('#json-mapping-text').inputValue(), '');
  await enterMapping();
  await page.locator('#json-mapping-text').fill(JSON.stringify({...rows[0], '<img src=x onerror=alert(1)>': canary}));
  await page.locator('#json-mapping-discover').click();
  assert.equal(await page.locator('#json-mapping-preview img').count(), 0);
  assert.equal(await page.locator('#json-map-status option').last().textContent(), '<img src=x onerror=alert(1)>');
  await scanAndReflow('hostile-key-safe-text');
  await page.setViewportSize({width: 320, height: 900});
  await page.screenshot({path: join(temporary, 'mapping-320.png'), fullPage: true});
  await page.evaluate(() => window.dispatchEvent(new Event('pagehide')));
  assert.equal(await page.locator('#json-mapping-text').inputValue(), '');
  assert.equal(await page.locator('#json-map-status option').count(), 1);
  const storage = await page.evaluate(async () => [localStorage.length, sessionStorage.length,
    typeof indexedDB.databases === 'function' ? (await indexedDB.databases()).length : 0]);
  assert.deepEqual(storage, [0, 0, 0]);
  assert.deepEqual(pageErrors, []);
  assert.equal(consoleMessages.some((message) => message.includes(canary)), false);
  assert.equal(external, 0);
  assert.deepEqual(posts, [endpoint, endpoint, '/api/v1/investigations/text', '/api/v1/investigations']);
  console.log(JSON.stringify({status: 'passed', actual_api_posts: posts.length, mapping_success: 200,
    mapping_rejection: 400, axe_scans: scans, axe_violations: 0, widths: [1440, 768, 320],
    keyboard_fields: 5, storage_entries: 0, external_requests: external, screenshot: join(temporary, 'mapping-320.png')}));
} finally {
  if (browser) await browser.close();
  if (child.exitCode === null) await new Promise((done) => { child.once('exit', done); child.kill('SIGINT'); });
  // Keep screenshots only when explicitly requested for visual review.
  if (!process.env.MAPPING_KEEP_SCREENSHOT) await rm(temporary, {recursive: true, force: true});
}
