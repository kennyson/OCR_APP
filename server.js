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

    // Store refresh token in encrypted cookie
    setRefreshCookie(res, data.refresh_token);

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

    res.json({ folder_name: fileInfo.parent.name, pdfs });
  } catch (err) {
    res.status(500).json({ error: err.response?.data?.message || err.message });
  }
});

// ── API: OCR a single file ───────────────────────────────────────────────────
app.post('/api/ocr', async (req, res) => {
  const { file_id, file_name, access_token, request_id } = req.body;
  if (!access_token) return res.status(401).json({ error: 'Not authenticated' });

  const inputPath = path.join(os.tmpdir(), `box-ocr-in-${file_id}.pdf`);
  const outputPath = path.join(os.tmpdir(), `box-ocr-out-${file_id}.pdf`);

  try {
    // Download
    const { data } = await axios.get(
      `https://api.box.com/2.0/files/${file_id}/content`,
      { headers: { Authorization: `Bearer ${access_token}` }, responseType: 'arraybuffer' }
    );
    fs.writeFileSync(inputPath, data);

    // OCR (cancellable, memory-efficient, 10-min timeout)
    const ocrProcess = execFile('ocrmypdf', [
      '--skip-text',
      '--rotate-pages',
      '--jobs', '1',          // single-threaded to limit memory use
      '--output-type', 'pdf', // skip PDF/A conversion (less memory)
      '--fast-web-view', '0', // skip linearization
      inputPath,
      outputPath
    ]);
    if (request_id) activeProcesses.set(request_id, ocrProcess);

    // Kill if it runs longer than 10 minutes
    const timeout = setTimeout(() => {
      ocrProcess.kill('SIGTERM');
    }, 10 * 60 * 1000);

    await new Promise((resolve, reject) => {
      ocrProcess.on('close', (code) => {
        clearTimeout(timeout);
        if (request_id) activeProcesses.delete(request_id);
        if (code === 0) resolve();
        else if (code === null) reject(Object.assign(new Error('OCR timed out or was cancelled'), { killed: true }));
        else reject(new Error(`ocrmypdf exited with code ${code}`));
      });
      ocrProcess.on('error', (err) => {
        clearTimeout(timeout);
        if (request_id) activeProcesses.delete(request_id);
        reject(err);
      });
    });

    // Upload new version
    const form = new FormData();
    form.append('attributes', JSON.stringify({ name: file_name }));
    form.append('file', fs.createReadStream(outputPath), {
      filename: file_name,
      contentType: 'application/pdf'
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
    h1 { font-size: 18px; font-weight: 700; color: #0061d5; margin-bottom: 16px; }
    .actions { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
    button { background: #0061d5; color: #fff; border: none; border-radius: 6px; padding: 10px 18px; font-size: 14px; cursor: pointer; font-weight: 500; }
    button:hover { background: #004fad; }
    button:disabled { background: #999; cursor: default; }
    button.secondary { background: #fff; color: #0061d5; border: 1px solid #0061d5; }
    button.secondary:hover { background: #e8f0fe; }
    button.secondary:disabled { background: #eee; color: #999; border-color: #ccc; }
    button.danger { background: #c00; }
    button.danger:hover { background: #a00; }
    #log { background: #fff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); padding: 16px; max-height: 400px; overflow-y: auto; }
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
  </style>
</head>
<body>
  <h1>Box PDF OCR</h1>
  <div class="actions">
    <button id="btn-file" onclick="ocrSingleFile()">OCR this file</button>
    <button id="btn-folder" class="secondary" onclick="ocrFolder()">OCR all PDFs in folder</button>
    <button id="btn-cancel" class="danger" onclick="cancelOcr()" style="display:none;">Cancel</button>
  </div>
  <div id="log"></div>
  <div id="summary"></div>
  <script>
    const FILE_ID = ${JSON.stringify(fileId)};
    const FILE_NAME = ${JSON.stringify(fileName)};
    const TOKEN = ${JSON.stringify(accessToken)};
    const log = document.getElementById('log');
    const summary = document.getElementById('summary');
    let cancelled = false;
    let currentRequestId = null;

    function showCancel(show) {
      document.getElementById('btn-cancel').style.display = show ? 'inline-block' : 'none';
    }
    function disable(yes) {
      document.getElementById('btn-file').disabled = yes;
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
