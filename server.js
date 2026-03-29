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
const progressMap    = new Map(); // requestId → { current, total }

// ── Service token storage (for automated webhook OCR) ────────────────────────
const SERVICE_TOKEN_FILE = path.join(os.tmpdir(), 'box-ocr-service-token.json');
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

// ── Box webhook list helpers ──────────────────────────────────────────────────
async function listOurWebhooks(accessToken) {
  const { data } = await axios.get('https://api.box.com/2.0/webhooks?limit=100', {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  return (data.entries || []).filter(w => w.address === BASE_URL + '/webhook' && w.target.type === 'folder');
}

async function getFolderName(folderId, accessToken) {
  try {
    const { data } = await axios.get(
      `https://api.box.com/2.0/folders/${folderId}?fields=name`,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );
    return data.name;
  } catch { return folderId; }
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

  // Fallback: try stored service token (fixes repeated Grant Access when browser blocks cookies)
  try {
    const stored = JSON.parse(fs.readFileSync(SERVICE_TOKEN_FILE, 'utf8'));
    const tokens = await refreshAccessToken(stored.refreshToken);
    saveServiceToken(tokens.refresh_token);
    setRefreshCookie(res, tokens.refresh_token);
    const fileName = file_name || await getFileName(file_id, tokens.access_token);
    return res.send(renderApp(file_id, fileName, tokens.access_token));
  } catch (e) {
    console.log('Service token fallback failed, starting OAuth:', e.message);
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

/// ── API: list watched folders (live from Box webhook registry) ────────────────
app.get('/api/watched-folders', async (req, res) => {
  const { access_token } = req.query;
  if (!access_token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    const webhooks = await listOurWebhooks(access_token);
    const names = await Promise.all(webhooks.map(w => getFolderName(w.target.id, access_token)));
    const result = {};
    webhooks.forEach((w, i) => {
      result[w.target.id] = { webhookId: w.id, folderName: names[i] };
    });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.response?.data?.message || err.message });
  }
});

app.post('/api/watch-folder', async (req, res) => {
  const { folder_id, folder_name, access_token } = req.body;
  if (!access_token) return res.status(401).json({ error: 'Not authenticated' });

  try {
    // Check if already watching (via Box registry)
    const existing = await listOurWebhooks(access_token);
    const already = existing.find(w => w.target.id === folder_id);
    if (already) return res.json({ ok: true, alreadyWatching: true, webhookId: already.id });

    const { data } = await axios.post(
      'https://api.box.com/2.0/webhooks',
      {
        target: { id: folder_id, type: 'folder' },
        address: BASE_URL + '/webhook',
        triggers: ['FILE.UPLOADED']
      },
      { headers: { Authorization: `Bearer ${access_token}`, 'Content-Type': 'application/json' } }
    );

    res.json({ ok: true, webhookId: data.id });
  } catch (err) {
    res.status(500).json({ error: err.response?.data?.message || err.message });
  }
});

app.post('/api/unwatch-folder', async (req, res) => {
  const { folder_id, access_token } = req.body;
  if (!access_token) return res.status(401).json({ error: 'Not authenticated' });

  try {
    const existing = await listOurWebhooks(access_token);
    const entry = existing.find(w => w.target.id === folder_id);
    if (!entry) return res.json({ ok: true, notWatching: true });

    try {
      await axios.delete(
        `https://api.box.com/2.0/webhooks/${entry.id}`,
        { headers: { Authorization: `Bearer ${access_token}` } }
      );
    } catch (e) {
      // Webhook may have already been removed; continue
      console.log('Webhook delete warning:', e.response?.data?.message || e.message);
    }

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
    if (requestId) progressMap.set(requestId, { current: 0, total: pageCount });

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

      if (requestId) progressMap.set(requestId, { current: i, total: pageCount });
      ocrPagePaths.push(pageOut);
    }

    await execFileAsync('qpdf', ['--empty', '--pages', ...ocrPagePaths, '--', outputPath]);
  } finally {
    if (requestId) progressMap.delete(requestId);
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
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Lato:wght@400;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --blue:        #0061d5;
      --blue-dark:   #004db3;
      --blue-light:  #e8f2ff;
      --green:       #26c281;
      --green-bg:    #e9f8f1;
      --green-text:  #1a6840;
      --red:         #e53935;
      --red-bg:      #fdecea;
      --red-text:    #b71c1c;
      --orange-bg:   #fff8e1;
      --orange-text: #e65100;
      --bg:          #f4f4f4;
      --surface:     #fff;
      --border:      #e8e8e8;
      --text:        #222;
      --muted:       #767676;
      --radius:      4px;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: Lato, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      font-size: 14px;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
    }

    /* ── Header ───────────────────────────────────── */
    .hdr {
      background: var(--blue);
      padding: 0 20px;
      height: 48px;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .hdr-icon { color: rgba(255,255,255,0.85); flex-shrink: 0; }
    .hdr-title { color: #fff; font-size: 15px; font-weight: 700; letter-spacing: .2px; }
    .hdr-file  { color: rgba(255,255,255,0.65); font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; }

    /* ── Tabs ─────────────────────────────────────── */
    .tabs { display: flex; background: var(--surface); border-bottom: 1px solid var(--border); padding: 0 20px; }
    .tab {
      background: none; border: none; border-bottom: 2px solid transparent;
      padding: 12px 16px; margin-bottom: -1px;
      font-family: inherit; font-size: 13px; font-weight: 700;
      color: var(--muted); cursor: pointer;
    }
    .tab.active { color: var(--blue); border-bottom-color: var(--blue); }
    .tab:hover:not(.active) { color: var(--text); }

    /* ── Panels ───────────────────────────────────── */
    .panel { display: none; padding: 20px; }
    .panel.active { display: block; }

    /* ── Buttons ──────────────────────────────────── */
    .btn {
      display: inline-flex; align-items: center; gap: 6px;
      height: 32px; padding: 0 16px;
      border: 1px solid transparent; border-radius: var(--radius);
      font-family: inherit; font-size: 13px; font-weight: 700;
      cursor: pointer; white-space: nowrap;
      transition: background .12s, border-color .12s;
    }
    .btn-primary { background: var(--blue); color: #fff; border-color: var(--blue); }
    .btn-primary:hover:not(:disabled) { background: var(--blue-dark); border-color: var(--blue-dark); }
    .btn-primary:disabled { background: #bcbcbc; border-color: #bcbcbc; cursor: default; }
    .btn-secondary { background: var(--surface); color: var(--blue); border-color: var(--blue); }
    .btn-secondary:hover:not(:disabled) { background: var(--blue-light); }
    .btn-secondary:disabled { color: #bcbcbc; border-color: #bcbcbc; cursor: default; }
    .btn-danger { background: var(--red); color: #fff; border-color: var(--red); }
    .btn-danger:hover { background: #c62828; border-color: #c62828; }
    .btn-sm { height: 28px; padding: 0 12px; font-size: 12px; }

    /* ── Action row ───────────────────────────────── */
    .actions { display: flex; align-items: center; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
    .hint { font-size: 12px; color: var(--muted); font-style: italic; margin-left: 4px; }

    /* ── File list ────────────────────────────────── */
    .file-list {
      border: 1px solid var(--border); border-radius: var(--radius);
      background: var(--surface); overflow: hidden;
      max-height: 340px; overflow-y: auto;
    }
    .file-row {
      display: flex; align-items: center; gap: 10px;
      padding: 9px 14px; border-bottom: 1px solid var(--border);
      font-size: 13px;
    }
    .file-row:last-child { border-bottom: none; }
    .file-pdf {
      flex-shrink: 0; width: 28px; height: 34px;
      background: #e53935; border-radius: 2px;
      display: flex; align-items: flex-end; justify-content: center;
      padding-bottom: 4px; position: relative;
    }
    .file-pdf::before {
      content: ''; position: absolute; top: 0; right: 0;
      width: 0; height: 0;
      border-style: solid; border-width: 0 7px 7px 0;
      border-color: transparent var(--bg) transparent transparent;
    }
    .file-pdf span { color: #fff; font-size: 8px; font-weight: 700; letter-spacing: .5px; }
    .file-name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 13px; }
    .file-meta { flex-shrink: 0; font-size: 12px; color: var(--muted); display: flex; align-items: center; gap: 6px; }
    .file-meta.processing { color: var(--blue); font-weight: 700; }
    .file-meta.done { color: var(--green-text); font-weight: 700; }
    .file-meta.fail { color: var(--red-text); font-weight: 700; }
    .file-meta.cancelled { color: var(--muted); font-style: italic; }

    /* ── Spinner ──────────────────────────────────── */
    .spinner {
      width: 13px; height: 13px;
      border: 2px solid #ddd; border-top-color: var(--blue);
      border-radius: 50%; animation: spin .65s linear infinite; flex-shrink: 0;
    }
    @keyframes spin { to { transform: rotate(360deg); } }

    /* ── Result banner ────────────────────────────── */
    .banner { margin-top: 12px; padding: 10px 14px; border-radius: var(--radius); font-size: 13px; font-weight: 700; display: flex; align-items: center; gap: 8px; }
    .banner.ok   { background: var(--green-bg);  color: var(--green-text); }
    .banner.err  { background: var(--red-bg);    color: var(--red-text);   }
    .banner.warn { background: var(--orange-bg); color: var(--orange-text);}

    /* ── Auto-OCR tab ─────────────────────────────── */
    .info { font-size: 13px; color: var(--muted); margin-bottom: 16px; line-height: 1.6; }
    .section-lbl {
      font-size: 11px; font-weight: 700; text-transform: uppercase;
      letter-spacing: .7px; color: var(--muted); margin-bottom: 8px;
    }
    .section-lbl + * { }
    .folder-card {
      display: flex; align-items: center; gap: 12px;
      padding: 11px 14px;
      background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
      margin-bottom: 8px; font-size: 13px;
    }
    .folder-icon { flex-shrink: 0; color: #f5a623; }
    .folder-name { flex: 1; font-weight: 700; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .badge { font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 10px; flex-shrink: 0; }
    .badge.on  { background: var(--green-bg);  color: var(--green-text); }
    .badge.off { background: var(--bg);        color: var(--muted); }
    .empty-state { color: var(--muted); font-size: 13px; padding: 24px 0; text-align: center; }
  </style>
</head>
<body>

  <!-- Header -->
  <div class="hdr">
    <svg class="hdr-icon" width="20" height="20" viewBox="0 0 20 20" fill="none">
      <rect x="2" y="4" width="10" height="13" rx="1" fill="rgba(255,255,255,0.9)"/>
      <rect x="8" y="3" width="8" height="11" rx="1" fill="rgba(255,255,255,0.55)"/>
      <text x="4" y="14" font-family="Lato,sans-serif" font-size="4" font-weight="700" fill="#e53935" letter-spacing=".3">PDF</text>
      <path d="M11 3l5 4h-5V3z" fill="rgba(255,255,255,0.35)"/>
    </svg>
    <span class="hdr-title">PDF OCR</span>
    <span class="hdr-file">${escHtml(fileName)}</span>
  </div>

  <!-- Tabs -->
  <div class="tabs">
    <button class="tab active" onclick="switchTab('ocr',this)">OCR</button>
    <button class="tab" onclick="switchTab('auto',this)">Auto-OCR</button>
  </div>

  <!-- OCR Panel -->
  <div id="panel-ocr" class="panel active">
    <div class="actions">
      <button class="btn btn-primary" id="btn-file" onclick="ocrSingleFile()">
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none"><path d="M7 1v8M3 5l4 4 4-4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/><path d="M1 11h12" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
        OCR this file
      </button>
      <button class="btn btn-secondary" id="btn-folder" onclick="ocrFolder()">
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none"><path d="M1 3.5A1.5 1.5 0 012.5 2H5l1.5 2H12a1.5 1.5 0 011.5 1.5v5A1.5 1.5 0 0112 12H2.5A1.5 1.5 0 011 10.5v-7z" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round"/></svg>
        OCR all in folder
      </button>
      <button class="btn btn-danger" id="btn-cancel" onclick="cancelOcr()" style="display:none;">
        <svg width="12" height="12" viewBox="0 0 12 12" fill="none"><path d="M2 2l8 8M10 2l-8 8" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>
        Cancel
      </button>
      <span id="hint" class="hint"></span>
    </div>
    <div class="file-list" id="log" style="display:none;"></div>
    <div id="summary"></div>
  </div>

  <!-- Auto-OCR Panel -->
  <div id="panel-auto" class="panel">
    <p class="info">Watched folders are automatically OCR'd when new PDFs are uploaded — no manual steps needed.</p>
    <div class="section-lbl">This folder</div>
    <div id="current-folder-row">
      <div class="folder-card"><div class="spinner"></div><span class="folder-name" style="color:var(--muted)">Loading…</span></div>
    </div>
    <div class="section-lbl" style="margin-top:20px;">All watched folders</div>
    <div id="watched-list"><div class="empty-state">Loading…</div></div>
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

    function showCancel(show) { document.getElementById('btn-cancel').style.display = show ? 'inline-flex' : 'none'; }
    function disable(yes) {
      document.getElementById('btn-file').disabled   = yes;
      document.getElementById('btn-folder').disabled = yes;
    }
    function addEntry(id, name) {
      log.style.display = '';
      const div = document.createElement('div');
      div.className = 'file-row';
      div.id = 'entry-' + id;
      div.innerHTML =
        '<div class="file-pdf"><span>PDF</span></div>' +
        '<span class="file-name">' + esc(name) + '</span>' +
        '<span class="file-meta processing"><div class="spinner"></div>processing…</span>';
      log.appendChild(div);
      log.scrollTop = log.scrollHeight;
    }
    function updateEntry(id, ok, msg) {
      const el = document.getElementById('entry-' + id);
      if (!el) return;
      const meta = el.querySelector('.file-meta');
      meta.querySelector('.spinner')?.remove();
      if (ok === null) {
        meta.className = 'file-meta cancelled';
        meta.textContent = '— cancelled';
      } else if (ok) {
        meta.className = 'file-meta done';
        meta.innerHTML = '<svg width="13" height="13" viewBox="0 0 13 13" fill="none"><path d="M2 7l3.5 3.5L11 3" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg> done';
      } else {
        meta.className = 'file-meta fail';
        meta.innerHTML = '<svg width="13" height="13" viewBox="0 0 13 13" fill="none"><path d="M2 2l9 9M11 2l-9 9" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg> ' + esc(msg || 'failed');
      }
    }
    function showSummary(success, failed, cancelledCount) {
      if (cancelledCount > 0) {
        summary.innerHTML = '<div class="banner warn">&#9888; ' + success + ' done, ' + cancelledCount + ' cancelled' + (failed > 0 ? ', ' + failed + ' failed' : '') + '.</div>';
      } else if (failed === 0) {
        summary.innerHTML = '<div class="banner ok"><svg width="14" height="14" viewBox="0 0 14 14" fill="none"><path d="M2 7.5l4 4L12 3" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>' +
          (success === 1 ? 'File is now searchable in Box.' : success + ' files processed successfully.') + '</div>';
      } else {
        summary.innerHTML = '<div class="banner err">&#10005; ' + success + ' succeeded, ' + failed + ' failed.</div>';
      }
    }

    function genId() { return Math.random().toString(36).slice(2); }

    async function ocrOne(fileId, fileName) {
      const reqId = genId();
      currentRequestId = reqId;
      const pollInterval = setInterval(async () => {
        try {
          const r = await fetch('/api/progress/' + reqId);
          const p = await r.json();
          if (p.total > 0) {
            const el = document.getElementById('entry-' + fileId);
            if (el) el.querySelector('.status').textContent = 'page ' + p.current + ' of ' + p.total;
            document.title = 'OCR: ' + p.current + '/' + p.total + ' pages';
          }
        } catch {}
      }, 1500);
      try {
        const res = await fetch('/api/ocr', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ file_id: fileId, file_name: fileName, access_token: TOKEN, request_id: reqId })
        });
        const data = await res.json().catch(() => ({}));
        if (data.cancelled) return 'cancelled';
        if (!res.ok) throw new Error(data.error || 'Failed');
        return 'done';
      } finally {
        clearInterval(pollInterval);
        document.title = 'Box PDF OCR';
      }
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
      document.getElementById('hint').textContent = 'Processing\u2026 you can minimize this window.';
      addEntry(FILE_ID, FILE_NAME);
      try {
        const result = await ocrOne(FILE_ID, FILE_NAME);
        updateEntry(FILE_ID, result === 'done' ? true : null);
        showSummary(result === 'done' ? 1 : 0, 0, result === 'cancelled' ? 1 : 0);
      } catch (e) {
        updateEntry(FILE_ID, false, e.message);
        showSummary(0, 1, 0);
      }
      document.getElementById('hint').textContent = '';
      showCancel(false); disable(false);
    }

    async function ocrFolder() {
      cancelled = false;
      disable(true); showCancel(true); log.innerHTML = ''; summary.innerHTML = '';
      document.getElementById('hint').textContent = 'Processing\u2026 you can minimize this window.';
      try {
        const res = await fetch('/api/folder-pdfs?file_id=' + FILE_ID + '&access_token=' + encodeURIComponent(TOKEN));
        const { pdfs, folder_name, error } = await res.json();
        if (error) throw new Error(error);
        if (!pdfs?.length) {
          summary.innerHTML = '<div class="banner ok">No PDFs found in \u201c' + esc(folder_name || 'folder') + '\u201d.</div>';
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
        summary.innerHTML = '<div class="banner err">&#10005; Error: ' + esc(e.message) + '</div>';
      }
      document.getElementById('hint').textContent = '';
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
          fetch('/api/watched-folders?access_token=' + encodeURIComponent(TOKEN))
        ]);
        const folderData  = await folderRes.json();
        watchedFolders    = await watchedRes.json();
        currentFolderId   = folderData.folder_id;
        currentFolderName = folderData.folder_name;
        renderAutoOcr();
      } catch (e) {
        document.getElementById('current-folder-row').innerHTML =
          '<div class="folder-card"><span class="folder-name" style="color:var(--red)">Error: ' + esc(e.message) + '</span></div>';
      }
    }

    const FOLDER_ICON = '<svg class="folder-icon" width="18" height="18" viewBox="0 0 18 18" fill="none"><path d="M1 4.5A2 2 0 013 2.5h3.5l2 2.5H16a2 2 0 012 2v7a2 2 0 01-2 2H3a2 2 0 01-2-2v-9z" fill="#f5a623" stroke="#e09000" stroke-width=".6"/></svg>';

    function renderAutoOcr() {
      const isWatching = currentFolderId && watchedFolders[currentFolderId];
      document.getElementById('current-folder-row').innerHTML = currentFolderId ? \`
        <div class="folder-card">
          \${FOLDER_ICON}
          <span class="folder-name">\${esc(currentFolderName || currentFolderId)}</span>
          <span class="badge \${isWatching ? 'on' : 'off'}">\${isWatching ? 'Watching' : 'Off'}</span>
          \${isWatching
            ? '<button class="btn btn-secondary btn-sm" onclick="unwatchFolder(' + JSON.stringify(currentFolderId) + ')">Stop</button>'
            : '<button class="btn btn-primary btn-sm" onclick="watchCurrentFolder()">Watch</button>'
          }
        </div>
      \` : '<div class="folder-card"><span class="folder-name" style="color:var(--muted)">Could not determine folder</span></div>';

      const entries = Object.entries(watchedFolders);
      const listEl  = document.getElementById('watched-list');
      if (entries.length === 0) {
        listEl.innerHTML = '<div class="empty-state">No folders are being watched yet.</div>';
        return;
      }
      listEl.innerHTML = entries.map(([fid, info]) => \`
        <div class="folder-card">
          \${FOLDER_ICON}
          <span class="folder-name">\${esc(info.folderName || fid)}</span>
          <span class="badge on">Watching</span>
          <button class="btn btn-secondary btn-sm" onclick="unwatchFolder(\${JSON.stringify(fid)})">Stop</button>
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
          '<div class="folder-card"><span class="folder-name" style="color:var(--red)">Error: ' + esc(e.message) + '</span></div>';
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
        '<div class="folder-card"><div class="spinner"></div><span class="folder-name" style="color:var(--muted)">Enabling auto-OCR…</span></div>';
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

// ── API: OCR progress ─────────────────────────────────────────────────────────
app.get('/api/progress/:request_id', (req, res) => {
  const p = progressMap.get(req.params.request_id);
  res.json(p || { current: 0, total: 0 });
});

app.listen(PORT, () => console.log(`Box PDF OCR server running at http://localhost:${PORT}`));
