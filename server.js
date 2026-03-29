require('dotenv').config();
const express = require('express');
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

// Short-lived in-memory job store (file_id + token, expires in 10 minutes)
const jobs = new Map();
function createJob(fileId, token) {
  const id = crypto.randomBytes(16).toString('hex');
  jobs.set(id, { fileId, token });
  setTimeout(() => jobs.delete(id), 10 * 60 * 1000);
  return id;
}

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use((req, res, next) => {
  console.log(`${req.method} ${req.url}`);
  console.log('Query:', JSON.stringify(req.query));
  console.log('Body:', JSON.stringify(req.body));
  console.log('Content-Type:', req.headers['content-type']);
  next();
});
app.use(express.static(path.join(__dirname, 'public')));

// ── Box callback — POST from Box with file_id and file_name ──────────────────
// Box POSTs here when user triggers the integration.
// Start OAuth flow with file context stored in the state parameter.
app.post('/ocr-ui', upload.none(), (req, res) => {
  // Box may send params in body or query string
  const file_id = req.body.file_id || req.query.file_id;
  const file_name = req.body.file_name || req.query.file_name;
  console.log('file_id:', file_id, 'file_name:', file_name);
  if (!file_id) return res.status(400).send(renderError('Missing file_id', 'No file ID was provided by Box.'));

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

    const accessToken = data.access_token;
    let fileName = stateData.file_name;

    // If Box didn't provide file_name, fetch it
    if (!fileName || fileName === '{file_name}' || fileName === '#file_name#') {
      try {
        const { data: fileInfo } = await axios.get(
          `https://api.box.com/2.0/files/${stateData.file_id}?fields=name`,
          { headers: { Authorization: `Bearer ${accessToken}` } }
        );
        fileName = fileInfo.name;
      } catch { fileName = 'document.pdf'; }
    }

    res.send(renderApp(stateData.file_id, fileName, accessToken));
  } catch (err) {
    const msg = err.response?.data?.error_description || err.message;
    res.status(500).send(renderError('OAuth Failed', msg));
  }
});

// ── API routes ───────────────────────────────────────────────────────────────

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

app.post('/api/ocr', async (req, res) => {
  const { file_id, file_name, access_token } = req.body;
  if (!access_token) return res.status(401).json({ error: 'Not authenticated' });

  const inputPath = path.join(os.tmpdir(), `box-ocr-in-${file_id}.pdf`);
  const outputPath = path.join(os.tmpdir(), `box-ocr-out-${file_id}.pdf`);

  try {
    const { data } = await axios.get(
      `https://api.box.com/2.0/files/${file_id}/content`,
      { headers: { Authorization: `Bearer ${access_token}` }, responseType: 'arraybuffer' }
    );
    fs.writeFileSync(inputPath, data);

    await execFileAsync('ocrmypdf', ['--skip-text', '--rotate-pages', inputPath, outputPath]);

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
    res.status(500).json({ error: err.response?.data?.message || err.message });
  } finally {
    try { fs.unlinkSync(inputPath); } catch {}
    try { fs.unlinkSync(outputPath); } catch {}
  }
});

// ── HTML templates ────────────────────────────────────────────────────────────

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
    .actions { display: flex; gap: 10px; margin-bottom: 20px; }
    button { background: #0061d5; color: #fff; border: none; border-radius: 6px; padding: 10px 18px; font-size: 14px; cursor: pointer; font-weight: 500; }
    button:hover { background: #004fad; }
    button:disabled { background: #999; cursor: default; }
    button.secondary { background: #fff; color: #0061d5; border: 1px solid #0061d5; }
    button.secondary:hover { background: #e8f0fe; }
    button.secondary:disabled { background: #eee; color: #999; border-color: #ccc; }
    #log { background: #fff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); padding: 16px; max-height: 400px; overflow-y: auto; }
    .entry { padding: 6px 0; border-bottom: 1px solid #f0f0f0; font-size: 13px; display: flex; align-items: center; gap: 8px; }
    .entry:last-child { border-bottom: none; }
    .entry .name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .spinner { width: 14px; height: 14px; border: 2px solid #ddd; border-top-color: #0061d5; border-radius: 50%; animation: spin 0.6s linear infinite; flex-shrink: 0; }
    @keyframes spin { to { transform: rotate(360deg); } }
    .done { color: #2e7d32; font-weight: 600; flex-shrink: 0; }
    .fail { color: #c00; font-weight: 600; flex-shrink: 0; }
    .summary { margin-top: 16px; padding: 12px 16px; border-radius: 6px; font-size: 14px; font-weight: 500; }
    .summary.ok { background: #e8f5e9; color: #2e7d32; }
    .summary.err { background: #fce4ec; color: #c00; }
  </style>
</head>
<body>
  <h1>Box PDF OCR</h1>
  <div class="actions">
    <button id="btn-file" onclick="ocrSingleFile()">OCR this file</button>
    <button id="btn-folder" class="secondary" onclick="ocrFolder()">OCR all PDFs in folder</button>
  </div>
  <div id="log"></div>
  <div id="summary"></div>
  <script>
    const FILE_ID = ${JSON.stringify(fileId)};
    const FILE_NAME = ${JSON.stringify(fileName)};
    const TOKEN = ${JSON.stringify(accessToken)};
    const log = document.getElementById('log');
    const summary = document.getElementById('summary');

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
      status.className = ok ? 'done' : 'fail';
      status.textContent = ok ? 'done' : msg || 'failed';
    }
    function showSummary(success, failed) {
      summary.className = failed === 0 ? 'summary ok' : 'summary err';
      summary.textContent = failed === 0
        ? (success === 1 ? 'File is now searchable in Box.' : success + ' files processed successfully.')
        : success + ' succeeded, ' + failed + ' failed.';
    }
    async function ocrOne(fileId, fileName) {
      const res = await fetch('/api/ocr', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ file_id: fileId, file_name: fileName, access_token: TOKEN })
      });
      if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Failed');
    }
    async function ocrSingleFile() {
      disable(true); log.innerHTML = ''; summary.innerHTML = '';
      addEntry(FILE_ID, FILE_NAME);
      try { await ocrOne(FILE_ID, FILE_NAME); updateEntry(FILE_ID, true); showSummary(1, 0); }
      catch (e) { updateEntry(FILE_ID, false, e.message); showSummary(0, 1); }
      disable(false);
    }
    async function ocrFolder() {
      disable(true); log.innerHTML = ''; summary.innerHTML = '';
      try {
        const res = await fetch('/api/folder-pdfs?file_id=' + FILE_ID + '&access_token=' + encodeURIComponent(TOKEN));
        const { pdfs, folder_name, error } = await res.json();
        if (error) throw new Error(error);
        if (!pdfs?.length) {
          summary.className = 'summary ok';
          summary.textContent = 'No PDFs found in "' + (folder_name || 'folder') + '".';
          disable(false); return;
        }
        let success = 0, failed = 0;
        for (const pdf of pdfs) {
          addEntry(pdf.id, pdf.name);
          try { await ocrOne(pdf.id, pdf.name); updateEntry(pdf.id, true); success++; }
          catch (e) { updateEntry(pdf.id, false, e.message); failed++; }
        }
        showSummary(success, failed);
      } catch (e) {
        summary.className = 'summary err';
        summary.textContent = 'Error: ' + e.message;
      }
      disable(false);
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
