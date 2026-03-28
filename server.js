require('dotenv').config();
const express = require('express');
const axios = require('axios');
const FormData = require('form-data');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { execFile } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);
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

  const inputPath = path.join(os.tmpdir(), `box-ocr-in-${file_id}.pdf`);
  const outputPath = path.join(os.tmpdir(), `box-ocr-out-${file_id}.pdf`);

  try {
    // 1. Download the PDF from Box
    const download = await axios.get(
      `https://api.box.com/2.0/files/${file_id}/content`,
      {
        headers: { Authorization: `Bearer ${access_token}` },
        responseType: 'arraybuffer'
      }
    );
    fs.writeFileSync(inputPath, download.data);

    // 2. Run ocrmypdf to add a searchable text layer
    //    --skip-text: pass through pages that already have text (won't break existing searchable PDFs)
    //    --rotate-pages: auto-correct page orientation
    await execFileAsync('ocrmypdf', ['--skip-text', '--rotate-pages', inputPath, outputPath]);

    // 3. Upload the OCR'd PDF back to Box as a new version
    const form = new FormData();
    form.append('attributes', JSON.stringify({ name: file_name || `${file_id}.pdf` }));
    form.append('file', fs.createReadStream(outputPath), {
      filename: file_name || `${file_id}.pdf`,
      contentType: 'application/pdf'
    });

    await axios.post(
      `https://upload.box.com/api/2.0/files/${file_id}/content`,
      form,
      {
        headers: {
          Authorization: `Bearer ${access_token}`,
          ...form.getHeaders()
        }
      }
    );

    res.send(renderSuccess(file_name || 'Document'));
  } catch (err) {
    const status = err.response?.status;
    const message = err.response?.data?.message || err.message || 'Unknown error';

    if (err.code === 'ENOENT') {
      res.status(500).send(renderError(
        'ocrmypdf not installed',
        'The ocrmypdf tool was not found on the server. Install it with: pip install ocrmypdf  (also requires Tesseract: https://tesseract-ocr.github.io/tessdoc/Installation.html)'
      ));
    } else if (status === 403) {
      res.status(403).send(renderError(
        'Permission denied',
        'Unable to read or write this file. Ensure the app has "Read and write all files and folders" scope enabled in the Box Developer Console.'
      ));
    } else {
      res.status(500).send(renderError('OCR failed', message));
    }
  } finally {
    try { fs.unlinkSync(inputPath); } catch {}
    try { fs.unlinkSync(outputPath); } catch {}
  }
});

function renderSuccess(fileName) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OCR Complete – ${escapeAttr(fileName)}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f5f5; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .card { background: #fff; border-radius: 8px; box-shadow: 0 1px 4px rgba(0,0,0,0.1); padding: 48px 40px; max-width: 480px; text-align: center; }
    .icon { font-size: 48px; margin-bottom: 20px; }
    h1 { font-size: 22px; color: #111; margin-bottom: 12px; }
    p { color: #555; font-size: 14px; line-height: 1.6; }
    .file { font-weight: 600; color: #0061d5; }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">&#10003;</div>
    <h1>OCR complete</h1>
    <p><span class="file">${escapeHtml(fileName)}</span> has been OCR'd and saved back to Box. The file is now searchable and ready for use with Box AI.</p>
  </div>
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
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f5f5; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .card { background: #fff; border-radius: 8px; box-shadow: 0 1px 4px rgba(0,0,0,0.1); padding: 40px; max-width: 500px; text-align: center; }
    h1 { font-size: 20px; color: #c00; margin-bottom: 12px; }
    p { color: #555; line-height: 1.5; font-size: 14px; }
    code { background: #eee; border-radius: 4px; padding: 2px 6px; font-size: 12px; font-family: 'Courier New', monospace; }
  </style>
</head>
<body>
  <div class="card">
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
