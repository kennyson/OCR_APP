require('dotenv').config();
const express = require('express');
const axios = require('axios');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.static(path.join(__dirname, 'public')));

// Box Web App Integration endpoint
// Box calls this URL with file_id, access_token, and file_name as query params
app.get('/ocr', async (req, res) => {
  const { file_id, access_token, file_name } = req.query;

  if (!file_id || !access_token) {
    return res.status(400).send(renderError(
      'Missing parameters',
      'This page must be opened from the Box web app. Required parameters file_id and access_token were not provided.'
    ));
  }

  try {
    const response = await axios.post(
      'https://api.box.com/2.0/ai/ask',
      {
        mode: 'single_item_qa',
        prompt: 'Extract and return all text content from this document verbatim, preserving the original structure and formatting as much as possible.',
        items: [{ type: 'file', id: file_id }]
      },
      {
        headers: {
          Authorization: `Bearer ${access_token}`,
          'Content-Type': 'application/json'
        }
      }
    );

    const extractedText = response.data.answer || '';
    res.send(renderResult(file_name || 'Document', extractedText));
  } catch (err) {
    const message = err.response?.data?.message || err.message || 'Unknown error';
    const status = err.response?.status;
    if (status === 403) {
      res.status(403).send(renderError(
        'Permission denied',
        'The Box AI feature is not enabled for your account or this file. Ensure your Box plan includes AI features and that the app has the "Use AI" scope enabled.'
      ));
    } else {
      res.status(500).send(renderError('Box AI request failed', message));
    }
  }
});

function renderResult(fileName, text) {
  const escaped = text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OCR Result – ${escapeAttr(fileName)}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f5f5; color: #333; }
    header { background: #0061d5; color: #fff; padding: 16px 24px; display: flex; align-items: center; gap: 12px; }
    header svg { flex-shrink: 0; }
    header h1 { font-size: 18px; font-weight: 600; }
    header p { font-size: 13px; opacity: 0.85; margin-top: 2px; }
    main { max-width: 900px; margin: 32px auto; padding: 0 24px 48px; }
    .card { background: #fff; border-radius: 8px; box-shadow: 0 1px 4px rgba(0,0,0,0.1); }
    .card-header { padding: 16px 20px; border-bottom: 1px solid #e5e5e5; display: flex; justify-content: space-between; align-items: center; }
    .card-header span { font-size: 13px; color: #666; }
    .copy-btn { background: #0061d5; color: #fff; border: none; border-radius: 4px; padding: 6px 14px; font-size: 13px; cursor: pointer; }
    .copy-btn:hover { background: #004fad; }
    pre { padding: 20px; white-space: pre-wrap; word-wrap: break-word; font-family: 'Courier New', monospace; font-size: 13px; line-height: 1.6; max-height: 70vh; overflow-y: auto; }
    .empty { padding: 40px 20px; text-align: center; color: #999; font-style: italic; }
  </style>
</head>
<body>
  <header>
    <svg width="28" height="28" viewBox="0 0 28 28" fill="none" xmlns="http://www.w3.org/2000/svg">
      <rect width="28" height="28" rx="6" fill="white" fill-opacity="0.2"/>
      <path d="M7 8h14v2H7V8zm0 5h14v2H7v-2zm0 5h9v2H7v-2z" fill="white"/>
    </svg>
    <div>
      <h1>OCR Result</h1>
      <p>${escapeHtml(fileName)}</p>
    </div>
  </header>
  <main>
    <div class="card">
      <div class="card-header">
        <span>Extracted text via Box AI</span>
        <button class="copy-btn" onclick="copyText()">Copy text</button>
      </div>
      ${escaped.trim() ? `<pre id="ocr-text">${escaped}</pre>` : '<div class="empty">No text could be extracted from this document.</div>'}
    </div>
  </main>
  <script>
    function copyText() {
      const el = document.getElementById('ocr-text');
      if (!el) return;
      navigator.clipboard.writeText(el.textContent).then(() => {
        const btn = document.querySelector('.copy-btn');
        btn.textContent = 'Copied!';
        setTimeout(() => btn.textContent = 'Copy text', 2000);
      });
    }
  </script>
</body>
</html>`;
}

function renderError(title, detail) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Error – Box OCR</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f5f5; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .box { background: #fff; border-radius: 8px; box-shadow: 0 1px 4px rgba(0,0,0,0.1); padding: 40px; max-width: 500px; text-align: center; }
    h1 { font-size: 20px; color: #c00; margin-bottom: 12px; }
    p { color: #555; line-height: 1.5; font-size: 14px; }
  </style>
</head>
<body>
  <div class="box">
    <h1>${escapeHtml(title)}</h1>
    <p>${escapeHtml(detail)}</p>
  </div>
</body>
</html>`;
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function escapeAttr(str) {
  return String(str).replace(/"/g, '&quot;');
}

app.listen(PORT, () => {
  console.log(`Box PDF OCR server running at http://localhost:${PORT}`);
});
