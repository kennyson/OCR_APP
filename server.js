require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFile } = require('child_process');
const { promisify } = require('util');

const multer = require('multer');
const upload = multer();

const execFileAsync = promisify(execFile);
const app = express();
const PORT = process.env.PORT || 3000;
const BASE_URL = (process.env.BASE_URL || '').replace(/\/$/, '');
const CLIENT_ID = process.env.BOX_CLIENT_ID;
const CLIENT_SECRET = process.env.BOX_CLIENT_SECRET;

if (!CLIENT_ID || !CLIENT_SECRET || !BASE_URL) {
  console.error('Missing required env vars: BOX_CLIENT_ID, BOX_CLIENT_SECRET, BASE_URL');
  process.exit(1);
}

// ── Token encryption (for storing refresh token in cookie) ───────────────────
const ENC_KEY = crypto.scryptSync(CLIENT_SECRET, 'box-ocr-salt', 32);

function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv);
  const enc = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return iv.toString('hex') + ':' + enc.toString('hex') + ':' + tag.toString('hex');
}

function decrypt(data) {
  const [ivH, encH, tagH] = data.split(':');
  const decipher = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, Buffer.from(ivH, 'hex'));
  decipher.setAuthTag(Buffer.from(tagH, 'hex'));
  return decipher.update(Buffer.from(encH, 'hex'), null, 'utf8') + decipher.final('utf8');
}

// ── In-flight OCR processes (for cancel support) ─────────────────────────────
const activeProcesses = new Map(); // requestId → ChildProcess

// ── Service token storage (for automated webhook OCR) ────────────────────────
const SERVICE_TOKEN_FILE = path.join(os.tmpdir(), 'box-ocr-service-token.json');
const WATCHED_FOLDERS_FILE = path.join(os.tmpdir(), 'box-ocr-watched-folders.json');

function saveServiceToken(refreshToken) {
  try {
    fs.writeFileSync(SERVICE_TOKEN_FILE, JSON.stringify({ refreshToken }));
  } catch (e) {
    console.error('Failed to save service token:', e.message);
  }
}

async function getServiceAccessToken() {
  let stored;
  try {
    stored = JSON.parse(fs.readFileSync(SERVICE_TOKEN_FILE, 'utf8'));
  } catch {
    throw new Error('No service token. Open the OCR app in Box once to re-authenticate.');
  }
  const tokens = await refreshAccessToken(stored.refreshToken);
  saveServiceToken(tokens.refresh_token);
  return tokens.access_token;
}

function loadWatchedFolders() {
  try { return JSON.parse(fs.readFileSync(WATCHED_FOLDERS_FILE, 'utf8')); }
  catch { return {}; }
}

function saveWatchedFolders(data) {
  fs.writeFileSync(WATCHED_FOLDERS_FILE, JSON.stringify(data));
}

// ── Webhook signature validation ──────────────────────────────────────────────
function validateWebhookSignature(rawBody, timestamp, sigPrimary, sigSecondary) {
  const primaryKey = process.env.BOX_WEBHOOK_PRIMARY_KEY;
  const secondaryKey = process.env.BOX_WEBHOOK_SECONDARY_KEY;
  if (!primaryKey && !secondaryKey) return true; // no keys configured, skip

  function computeSig(key) {
    return crypto.createHmac('sha256', key).update(timestamp + rawBody).digest('base64');
  }

  const validPrimary = primaryKey && sigPrimary === computeSig(primaryKey);
  const validSecondary = secondaryKey && sigSecondary === computeSig(secondaryKey);
  return validPrimary || validSecondary;
}

// ── Box webhook receiver (raw body needed for signature — defined FIRST) ──────
app.post('/webhook', express.raw({ type: '*/*' }), async (req, res) => {
  const timestamp  = req.headers['box-delivery-timestamp'] || '';
  const sigPrimary = req.headers['box-signature-primary']  || '';
  const sigSecondary = req.headers['box-signature-secondary'] || '';
  const rawBody = req.body.toString('utf8');

  if (!validateWebhookSignature(rawBody, timestamp, sigPrimary, sigSecondary)) {
    console.log('Webhook: invalid signature — rejecting');
    return res.status(401).send('Invalid signature');
  }

  let event;
  try { event = JSON.parse(rawBody); }
  catch { return res.status(400).send('Invalid JSON'); }

  if (event.trigger !== 'FILE.UPLOADED') return res.json({ ok: true, skipped: 'not FILE.UPLOADED' });

  const file = event.source;
  if (!file || file.type !== 'file' || !file.name?.toLowerCase().endsWith('.pdf')) {
    return res.json({ ok: true, skipped: 'not a PDF' });
  }

  console.log(`Webhook: auto-OCR queued for "${file.name}" (${file.id})`);
  res.json({ ok: true }); // respond immediately; Box expects fast ack

  setImmediate(async () => {
    const inputPath  = path.join(os.tmpdir(), `box-auto-in-${file.id}.pdf`);
    const outputPath = path.join(os.tmpdir(), `box-auto-out-${file.id}.pdf`);
    try {
      const accessToken = await getServiceAccessToken();
      const { data } = await axios.get(
        `https://api.box.com/2.0/files/${file.id}/content`,
        { headers: { Authorization: `Bearer ${accessToken}` }, responseType: 'arraybuffer' }
      );
      fs.writeFileSync(inputPath, data);
      await ocrByPage(inputPath, outputPath, null);

      const form = new FormData();
      form.append('attributes', JSON.stringify({ name: file.name }));
      form.append('file', fs.createReadStream(outputPath), {
        filename: file.name, contentType: 'application/pdf'
      });
      const uploadToken = await getServiceAccessToken();
      await axios.post(
        `https://upload.box.com/api/2.0/files/${file.id}/content`,
        form,
        { headers: { Authorization: `Bearer ${uploadToken}`, ...form.getHeaders() } }
      );
      console.log(`Auto-OCR complete: "${file.name}"`);
    } catch (err) {
      console.error(`Auto-OCR failed for "${file.name}":`, err.message);
    } finally {
      try { fs.unlinkSync(inputPath); } catch {}
      try { fs.unlinkSync(outputPath); } catch {}
    }
  });
});

// ── Global middleware ─────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ── Refresh token helper ─────────────────────────────────────────────────────
async function refreshAccessToken(refreshToken) {
  const { data } = await axios.post(
    'https://api.box.com/oauth2/token',
    new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET
    }),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
  );
  return data; // { access_token, refresh_token }
}

function setRefreshCookie(res, refreshToken) {
  res.cookie('box_rt', encrypt(refreshToken), {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    maxAge: 60 * 24 * 60 * 60 * 1000 // 60 days
  });
}

async function getFileName(fileId, token) {
  try {
    const { data } = await axios.get(
      `https://api.box.com/2.0/files/${fileId}?fields=name`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    return data.name;
  } catch { return 'document.pdf'; }
}

// ── Box Integration entry point ──────────────────────────────────────────────
app.post('/ocr-ui', upload.none(), async (req, res) => {
  const file_id = req.body.file_id || req.query.file_id;
  const file_name = req.body.file_name || req.query.file_name;
  console.log('POST /ocr-ui file_id:', file_id, 'file_name:', file_name);

  if (!file_id) {
    return res.status(400).send(renderError('Missing file_id', 'No file ID was provided by Box.'));
  }

  // Try stored refresh token first (skip OAuth)
  const encCookie = req.cookies?.box_rt;
  if (encCookie) {
    try {
      const oldRefresh = decrypt(encCookie);
      const tokens = await refreshAccessToken(oldRefresh);
      setRefreshCookie(res, tokens.refresh_token);
      saveServiceToken(tokens.refresh_token); // keep service token fresh

      const fileName = file_name || await getFileName(file_id, tokens.access_token);
      return res.send(renderApp(file_id, fileName, tokens.access_token));
    } catch (err) {
      console.log('Refresh token expired, starting OAuth:', err.message);
      res.clearCookie('box_rt');
    }
  }

  // Fall through to OAuth
  const state = Buffer.from(JSON.stringify({
    file_id,
    file_name: file_name || 'document.pdf'
  })).toString('base64url');

  const authUrl = 'https://account.box.com/api/oauth2/authorize?' +
    `client_id=${CLIENT_ID}` +
    `&response_type=code` +
    `&redirect_uri=${encodeURIComponent(BASE_URL + '/callback')}` +
    `&state=${state}`;

  res.redirect(authUrl);
});

// ── OAuth callback ────────────────────────────────────────────────────────────
app.get('/callback', async (req, res) => {
  const { code, state } = req.query;
  if (!code || !state) return res.status(400).send(renderError('OAuth Error', 'Missing code or state.'));

  let stateData;
  try {
    stateData = JSON.parse(Buffer.from(state, 'base64url').toString());
  } catch {
    return res.status(400).send(renderError('OAuth Error', 'Invalid state parameter.'));
  }

  try {
    const { data } = await axios.post(
      'https://api.box.com/oauth2/token',
      new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uri: BASE_URL + '/callback'
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    setRefreshCookie(res, data.refresh_token);
    saveServiceToken(data.refresh_token); // save for automated webhook processing

    const accessToken = data.access_token;
    let fileName = stateData.file_name;
    if (!fileName || fileName.includes('{') || fileName.includes('#')) {
      fileName = await getFileName(stateData.file_id, accessToken);
    }

    res.send(renderApp(stateData.file_id, fileName, accessToken));
  } catch (err) {
    const msg = err.response?.data?.error_description || err.message;
    res.status(500).send(renderError('OAuth Failed', msg));
  }
});

// ── API: list PDFs in parent folder ──────────────────────────────────────────
app.get('/api/folder-pdfs', async (req, res) => {
  const { file_id, access_token } = req.query;
  if (!access_token) return res.status(401).json({ error: 'Not authenticated' });

  try {
    const { data: fileInfo } = await axios.get(
      `https://api.box.com/2.0/files/${file_id}?fields=parent`,
      { headers: { Authorization: `Bearer ${access_token}` } }
    );

    const folderId = fileInfo.parent.id;
    const pdfs = [];
    let marker = null;
    do {
      const params = { fields: 'id,name', limit: 1000 };
      if (marker) params.marker = marker;
      const { data } = await axios.get(
        `https://api.box.com/2.0/folders/${folderId}/items`,
        { headers: { Authorization: `Bearer ${access_token}` }, params }
      );
      for (const item of data.entries) {
        if (item.type === 'file' && item.name.toLowerCase().endsWith('.pdf')) {
          pdfs.push({ id: item.id, name: item.name });
        }
      }
      marker = data.next_marker || null;
    } while (marker);

    res.json({ folder_id: folderId, folder_name: fileInfo.parent.name, pdfs });
  } catch (err) {
    res.status(500).json({ error: err.response?.data?.message || err.message });
  }
});

// ── API: watched folders ──────────────────────────────────────────────────────
app.get('/api/watched-folders', (req, res) => {
  res.json(loadWatchedFolders());
});

app.post('/api/watch-folder', async (req, res) => {
  const { folder_id, folder_name, access_token } = req.body;
  if (!access_token) return res.status(401).json({ error: 'Not authenticated' });

  try {
    const watched = loadWatchedFolders();
    if (watched[folder_id]) return res.json({ ok: true, alreadyWatching: true });

    const { data } = await axios.post(
      'https://api.box.com/2.0/webhooks',
      {
        target: { id: folder_id, type: 'folder' },
        address: BASE_URL + '/webhook',
        triggers: ['FILE.UPLOADED']
      },
      { headers: { Authorization: `Bearer ${access_token}`, 'Content-Type': 'application/json' } }
    );

    watched[folder_id] = { webhookId: data.id, folderName: folder_name };
    saveWatchedFolders(watched);
    res.json({ ok: true, webhookId: data.id });
  } catch (err) {
    res.status(500).json({ error: err.response?.data?.message || err.message });
  }
});

app.post('/api/unwatch-folder', async (req, res) => {
  const { folder_id, access_token } = req.body;
  if (!access_token) return res.status(401).json({ error: 'Not authenticated' });

  try {
    const watched = loadWatchedFolders();
    const entry = watched[folder_id];
    if (!entry) return res.json({ ok: true, notWatching: true });

    try {
      await axios.delete(
        `https://api.box.com/2.0/webhooks/${entry.webhookId}`,
        { headers: { Authorization: `Bearer ${access_token}` } }
      );
    } catch (e) {
      // Webhook may have already been removed; continue
      console.log('Webhook delete warning:', e.response?.data?.message || e.message);
    }

    delete watched[folder_id];
    saveWatchedFolders(watched);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.response?.data?.message || err.message });
  }
});

// ── Page-by-page OCR ─────────────────────────────────────────────────────────
async function ocrByPage(inputPath, outputPath, requestId) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'box-ocr-pages-'));
  try {
    const { stdout } = await execFileAsync('qpdf', ['--show-npages', inputPath]);
    const pageCount = parseInt(stdout.trim(), 10);
    console.log(`OCR: splitting ${pageCount} pages`);

    const ocrPagePaths = [];

    for (let i = 1; i <= pageCount; i++) {
      const pageIn  = path.join(tmpDir, `page-${i}-in.pdf`);
      const pageOut = path.join(tmpDir, `page-${i}-out.pdf`);

      await execFileAsync('qpdf', ['--empty', '--pages', inputPath, String(i), '--', pageIn]);

      const proc = execFile('ocrmypdf', [
        '--skip-text', '--jobs', '1', '--output-type', 'pdf', '--fast-web-view', '0',
        pageIn, pageOut
      ]);
      if (requestId) activeProcesses.set(requestId, proc);

      await new Promise((resolve, reject) => {
        proc.on('close', code => {
          if (requestId) activeProcesses.delete(requestId);
          if (code === 0 || code === 6) resolve();
          else if (code === null) reject(Object.assign(new Error('Cancelled'), { killed: true }));
          else reject(new Error(`Page ${i}: ocrmypdf exited with code ${code}`));
        });
        proc.on('error', err => {
          if (requestId) activeProcesses.delete(requestId);
          reject(err);
        });
      });

      ocrPagePaths.push(pageOut);
    }

    await execFileAsync('qpdf', ['--empty', '--pages', ...ocrPagePaths, '--', outputPath]);
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  }
}

// ── API: OCR a single file ───────────────────────────────────────────────────
app.post('/api/ocr', async (req, res) => {
  const { file_id, file_name, access_token, request_id } = req.body;
  if (!access_token) return res.status(401).json({ error: 'Not authenticated' });

  const inputPath  = path.join(os.tmpdir(), `box-ocr-in-${file_id}.pdf`);
  const outputPath = path.join(os.tmpdir(), `box-ocr-out-${file_id}.pdf`);

  try {
    const { data } = await axios.get(
      `https://api.box.com/2.0/files/${file_id}/content`,
      { headers: { Authorization: `Bearer ${access_token}` }, responseType: 'arraybuffer' }
    );
    fs.writeFileSync(inputPath, data);

    await ocrByPage(inputPath, outputPath, request_id);

    const form = new FormData();
    form.append('attributes', JSON.stringify({ name: file_name }));
    form.append('file', fs.createReadStream(outputPath), {
      filename: file_name, contentType: 'application/pdf'
    });
    await axios.post(
      `https://upload.box.com/api/2.0/files/${file_id}/content`,
      form,
      { headers: { Authorization: `Bearer ${access_token}`, ...form.getHeaders() } }
    );

    res.json({ success: true });
  } catch (err) {
    if (err.killed) return res.json({ cancelled: true });
    res.status(500).json({ error: err.response?.data?.message || err.message });
  } finally {
    try { fs.unlinkSync(inputPath); } catch {}
    try { fs.unlinkSync(outputPath); } catch {}
  }
});

// ── API: cancel OCR ──────────────────────────────────────────────────────────
app.post('/api/cancel', (req, res) => {
  const { request_id } = req.body;
  const proc = activeProcesses.get(request_id);
  if (proc) {
    proc.kill('SIGTERM');
    activeProcesses.delete(request_id);
    res.json({ cancelled: true });
  } else {
    res.json({ cancelled: false });
  }
});

// ── HTML ─────────────────────────────────────────────────────────────────────

function renderApp(fileId, fileName, accessToken) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Box PDF OCR</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f5f5; color: #333; padding: 20px; }
    h1 { font-size: 18px; font-weight: 700; color: #0061d5; margin-bottom: 4px; }
    .tabs { display: flex; gap: 0; margin-bottom: 20px; border-bottom: 2px solid #e0e0e0; }
    .tab { background: none; border: none; padding: 10px 18px; font-size: 14px; font-weight: 500; color: #666; cursor: pointer; border-bottom: 2px solid transparent; margin-bottom: -2px; }
    .tab.active { color: #0061d5; border-bottom-color: #0061d5; }
    .tab:hover:not(.active) { color: #333; }
    .panel { display: none; }
    .panel.active { display: block; }
    .actions { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
    button { background: #0061d5; color: #fff; border: none; border-radius: 6px; padding: 10px 18px; font-size: 14px; cursor: pointer; font-weight: 500; }
    button:hover { background: #004fad; }
    button:disabled { background: #999; cursor: default; }
    button.secondary { background: #fff; color: #0061d5; border: 1px solid #0061d5; }
    button.secondary:hover { background: #e8f0fe; }
    button.secondary:disabled { background: #eee; color: #999; border-color: #ccc; }
    button.danger { background: #c00; }
    button.danger:hover { background: #a00; }
    button.sm { padding: 5px 12px; font-size: 12px; }
    #log { background: #fff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); padding: 16px; max-height: 360px; overflow-y: auto; }
    .entry { padding: 6px 0; border-bottom: 1px solid #f0f0f0; font-size: 13px; display: flex; align-items: center; gap: 8px; }
    .entry:last-child { border-bottom: none; }
    .entry .name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .spinner { width: 14px; height: 14px; border: 2px solid #ddd; border-top-color: #0061d5; border-radius: 50%; animation: spin 0.6s linear infinite; flex-shrink: 0; }
    @keyframes spin { to { transform: rotate(360deg); } }
    .done { color: #2e7d32; font-weight: 600; flex-shrink: 0; }
    .fail { color: #c00; font-weight: 600; flex-shrink: 0; }
    .cancelled { color: #666; font-style: italic; flex-shrink: 0; }
    .summary { margin-top: 16px; padding: 12px 16px; border-radius: 6px; font-size: 14px; font-weight: 500; }
    .summary.ok { background: #e8f5e9; color: #2e7d32; }
    .summary.err { background: #fce4ec; color: #c00; }
    .summary.warn { background: #fff8e1; color: #f57c00; }
    .folder-row { display: flex; align-items: center; gap: 10px; padding: 10px 14px; background: #fff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); margin-bottom: 10px; font-size: 14px; }
    .folder-row .name { flex: 1; font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .badge { font-size: 11px; font-weight: 600; padding: 3px 8px; border-radius: 10px; }
    .badge.on { background: #e8f5e9; color: #2e7d32; }
    .badge.off { background: #f5f5f5; color: #999; }
    .info { font-size: 13px; color: #666; margin-bottom: 16px; line-height: 1.5; }
    .section-title { font-size: 13px; font-weight: 600; color: #666; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 10px; }
    .empty { color: #999; font-size: 13px; font-style: italic; padding: 12px 0; }
  </style>
</head>
<body>
  <h1>Box PDF OCR</h1>

  <div class="tabs">
    <button class="tab active" onclick="switchTab('ocr', this)">OCR</button>
    <button class="tab" onclick="switchTab('auto', this)">Auto-OCR</button>
  </div>

  <!-- OCR Tab -->
  <div id="panel-ocr" class="panel active">
    <div class="actions">
      <button id="btn-file" onclick="ocrSingleFile()">OCR this file</button>
      <button id="btn-folder" class="secondary" onclick="ocrFolder()">OCR all PDFs in folder</button>
      <button id="btn-cancel" class="danger" onclick="cancelOcr()" style="display:none;">Cancel</button>
    </div>
    <div id="log"></div>
    <div id="summary"></div>
  </div>

  <!-- Auto-OCR Tab -->
  <div id="panel-auto" class="panel">
    <p class="info">Auto-OCR watches a folder and automatically makes new PDFs searchable when they are uploaded — no manual steps needed.</p>

    <div class="section-title">This folder</div>
    <div id="current-folder-row">
      <div class="folder-row"><span class="name">Loading…</span></div>
    </div>

    <div class="section-title" style="margin-top:20px;">All watched folders</div>
    <div id="watched-list"><div class="empty">Loading…</div></div>
  </div>

  <script>
    const FILE_ID   = ${JSON.stringify(fileId)};
    const FILE_NAME = ${JSON.stringify(fileName)};
    const TOKEN     = ${JSON.stringify(accessToken)};

    // ── Tab switching ────────────────────────────────────────────────────────
    function switchTab(name, btn) {
      document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.getElementById('panel-' + name).classList.add('active');
      btn.classList.add('active');
      if (name === 'auto' && !autoLoaded) loadAutoOcr();
    }

    // ── OCR Tab ──────────────────────────────────────────────────────────────
    const log     = document.getElementById('log');
    const summary = document.getElementById('summary');
    let cancelled = false;
    let currentRequestId = null;

    function showCancel(show) { document.getElementById('btn-cancel').style.display = show ? 'inline-block' : 'none'; }
    function disable(yes) {
      document.getElementById('btn-file').disabled   = yes;
      document.getElementById('btn-folder').disabled = yes;
    }
    function addEntry(id, name) {
      const div = document.createElement('div');
      div.className = 'entry';
      div.id = 'entry-' + id;
      div.innerHTML = '<div class="spinner"></div><span class="name">' + esc(name) + '</span><span class="status">processing...</span>';
      log.appendChild(div);
      log.scrollTop = log.scrollHeight;
    }
    function updateEntry(id, ok, msg) {
      const el = document.getElementById('entry-' + id);
      if (!el) return;
      el.querySelector('.spinner')?.remove();
      const status = el.querySelector('.status');
      status.className = ok === null ? 'cancelled' : ok ? 'done' : 'fail';
      status.textContent = ok === null ? 'cancelled' : ok ? 'done' : msg || 'failed';
    }
    function showSummary(success, failed, cancelledCount) {
      if (cancelledCount > 0) {
        summary.className = 'summary warn';
        summary.textContent = success + ' done, ' + cancelledCount + ' cancelled' + (failed > 0 ? ', ' + failed + ' failed' : '') + '.';
      } else if (failed === 0) {
        summary.className = 'summary ok';
        summary.textContent = success === 1 ? 'File is now searchable in Box.' : success + ' files processed successfully.';
      } else {
        summary.className = 'summary err';
        summary.textContent = success + ' succeeded, ' + failed + ' failed.';
      }
    }

    function genId() { return Math.random().toString(36).slice(2); }

    async function ocrOne(fileId, fileName) {
      const reqId = genId();
      currentRequestId = reqId;
      const res = await fetch('/api/ocr', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ file_id: fileId, file_name: fileName, access_token: TOKEN, request_id: reqId })
      });
      const data = await res.json().catch(() => ({}));
      if (data.cancelled) return 'cancelled';
      if (!res.ok) throw new Error(data.error || 'Failed');
      return 'done';
    }

    async function cancelOcr() {
      cancelled = true;
      if (currentRequestId) {
        await fetch('/api/cancel', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ request_id: currentRequestId })
        });
      }
      showCancel(false);
    }

    async function ocrSingleFile() {
      cancelled = false;
      disable(true); showCancel(true); log.innerHTML = ''; summary.innerHTML = '';
      addEntry(FILE_ID, FILE_NAME);
      try {
        const result = await ocrOne(FILE_ID, FILE_NAME);
        updateEntry(FILE_ID, result === 'done' ? true : null);
        showSummary(result === 'done' ? 1 : 0, 0, result === 'cancelled' ? 1 : 0);
      } catch (e) {
        updateEntry(FILE_ID, false, e.message);
        showSummary(0, 1, 0);
      }
      showCancel(false); disable(false);
    }

    async function ocrFolder() {
      cancelled = false;
      disable(true); showCancel(true); log.innerHTML = ''; summary.innerHTML = '';
      try {
        const res = await fetch('/api/folder-pdfs?file_id=' + FILE_ID + '&access_token=' + encodeURIComponent(TOKEN));
        const { pdfs, folder_name, error } = await res.json();
        if (error) throw new Error(error);
        if (!pdfs?.length) {
          summary.className = 'summary ok';
          summary.textContent = 'No PDFs found in "' + (folder_name || 'folder') + '".';
          showCancel(false); disable(false); return;
        }
        let success = 0, failed = 0, cancelledCount = 0;
        for (const pdf of pdfs) {
          if (cancelled) { cancelledCount += pdfs.length - success - failed - cancelledCount; break; }
          addEntry(pdf.id, pdf.name);
          try {
            const result = await ocrOne(pdf.id, pdf.name);
            if (result === 'cancelled') { updateEntry(pdf.id, null); cancelledCount++; }
            else { updateEntry(pdf.id, true); success++; }
          } catch (e) { updateEntry(pdf.id, false, e.message); failed++; }
        }
        showSummary(success, failed, cancelledCount);
      } catch (e) {
        summary.className = 'summary err';
        summary.textContent = 'Error: ' + e.message;
      }
      showCancel(false); disable(false);
    }

    // ── Auto-OCR Tab ─────────────────────────────────────────────────────────
    let autoLoaded = false;
    let currentFolderId   = null;
    let currentFolderName = null;
    let watchedFolders    = {};

    async function loadAutoOcr() {
      autoLoaded = true;
      try {
        const [folderRes, watchedRes] = await Promise.all([
          fetch('/api/folder-pdfs?file_id=' + FILE_ID + '&access_token=' + encodeURIComponent(TOKEN)),
          fetch('/api/watched-folders')
        ]);
        const folderData  = await folderRes.json();
        watchedFolders    = await watchedRes.json();
        currentFolderId   = folderData.folder_id;
        currentFolderName = folderData.folder_name;
        renderAutoOcr();
      } catch (e) {
        document.getElementById('current-folder-row').innerHTML =
          '<div class="folder-row"><span class="name" style="color:#c00">Error loading folder info: ' + esc(e.message) + '</span></div>';
      }
    }

    function renderAutoOcr() {
      // Current folder row
      const isWatching = currentFolderId && watchedFolders[currentFolderId];
      document.getElementById('current-folder-row').innerHTML = currentFolderId ? \`
        <div class="folder-row">
          <span class="name">\${esc(currentFolderName || currentFolderId)}</span>
          <span class="badge \${isWatching ? 'on' : 'off'}">\${isWatching ? 'Watching' : 'Not watching'}</span>
          \${isWatching
            ? '<button class="secondary sm" onclick="unwatchFolder(' + JSON.stringify(currentFolderId) + ')">Stop</button>'
            : '<button class="sm" onclick="watchCurrentFolder()">Watch</button>'
          }
        </div>
      \` : '<div class="folder-row"><span class="name" style="color:#999">Could not determine folder</span></div>';

      // All watched folders
      const entries = Object.entries(watchedFolders);
      const listEl  = document.getElementById('watched-list');
      if (entries.length === 0) {
        listEl.innerHTML = '<div class="empty">No folders are being watched yet.</div>';
        return;
      }
      listEl.innerHTML = entries.map(([fid, info]) => \`
        <div class="folder-row">
          <span class="name">\${esc(info.folderName || fid)}</span>
          <span class="badge on">Watching</span>
          <button class="secondary sm" onclick="unwatchFolder(\${JSON.stringify(fid)})">Stop</button>
        </div>
      \`).join('');
    }

    async function watchCurrentFolder() {
      if (!currentFolderId) return;
      setFolderRowLoading();
      try {
        const res = await fetch('/api/watch-folder', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ folder_id: currentFolderId, folder_name: currentFolderName, access_token: TOKEN })
        });
        const data = await res.json();
        if (data.error) throw new Error(data.error);
        watchedFolders[currentFolderId] = { webhookId: data.webhookId, folderName: currentFolderName };
        renderAutoOcr();
      } catch (e) {
        document.getElementById('current-folder-row').innerHTML =
          '<div class="folder-row"><span class="name" style="color:#c00">Error: ' + esc(e.message) + '</span></div>';
      }
    }

    async function unwatchFolder(folderId) {
      try {
        const res = await fetch('/api/unwatch-folder', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ folder_id: folderId, access_token: TOKEN })
        });
        const data = await res.json();
        if (data.error) throw new Error(data.error);
        delete watchedFolders[folderId];
        renderAutoOcr();
      } catch (e) {
        alert('Error: ' + e.message);
      }
    }

    function setFolderRowLoading() {
      document.getElementById('current-folder-row').innerHTML =
        '<div class="folder-row"><div class="spinner"></div><span class="name">Enabling auto-OCR…</span></div>';
    }

    function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
  </script>
</body>
</html>`;
}

function renderError(title, detail) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"><title>Error</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f5f5; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .card { background: #fff; border-radius: 8px; box-shadow: 0 1px 4px rgba(0,0,0,0.1); padding: 40px; max-width: 500px; text-align: center; }
    h1 { font-size: 20px; color: #c00; margin-bottom: 12px; }
    p { color: #555; line-height: 1.5; font-size: 14px; }
  </style>
</head>
<body>
  <div class="card">
    <h1>${escHtml(title)}</h1>
    <p>${escHtml(detail)}</p>
  </div>
</body>
</html>`;
}

function escHtml(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

app.listen(PORT, () => console.log(`Box PDF OCR server running at http://localhost:${PORT}`));
