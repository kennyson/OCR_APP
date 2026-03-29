#!/usr/bin/env node

require('dotenv').config();
const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);
const TOKEN = process.env.BOX_TOKEN;

if (!TOKEN) {
  console.error('Missing BOX_TOKEN in .env file.');
  console.error('Get one from: Box Developer Console → your app → Configuration → Developer Token → Generate');
  process.exit(1);
}

const boxApi = axios.create({
  baseURL: 'https://api.box.com/2.0',
  headers: { Authorization: `Bearer ${TOKEN}` }
});

async function listPdfsInFolder(folderId) {
  const pdfs = [];
  let marker = null;

  do {
    const params = { fields: 'id,name', limit: 1000 };
    if (marker) params.marker = marker;

    const { data } = await boxApi.get(`/folders/${folderId}/items`, { params });

    for (const item of data.entries) {
      if (item.type === 'file' && item.name.toLowerCase().endsWith('.pdf')) {
        pdfs.push({ id: item.id, name: item.name });
      }
    }

    marker = data.next_marker || null;
  } while (marker);

  return pdfs;
}

async function ocrFile(fileId, fileName) {
  const inputPath = path.join(os.tmpdir(), `box-ocr-in-${fileId}.pdf`);
  const outputPath = path.join(os.tmpdir(), `box-ocr-out-${fileId}.pdf`);

  try {
    // Download
    process.stdout.write(`  Downloading... `);
    const { data } = await boxApi.get(`/files/${fileId}/content`, { responseType: 'arraybuffer' });
    fs.writeFileSync(inputPath, data);
    process.stdout.write(`done\n`);

    // OCR
    process.stdout.write(`  Running OCR... `);
    await execFileAsync('ocrmypdf', ['--skip-text', '--rotate-pages', inputPath, outputPath]);
    process.stdout.write(`done\n`);

    // Upload new version
    process.stdout.write(`  Uploading to Box... `);
    const form = new FormData();
    form.append('attributes', JSON.stringify({ name: fileName }));
    form.append('file', fs.createReadStream(outputPath), {
      filename: fileName,
      contentType: 'application/pdf'
    });

    await axios.post(
      `https://upload.box.com/api/2.0/files/${fileId}/content`,
      form,
      { headers: { Authorization: `Bearer ${TOKEN}`, ...form.getHeaders() } }
    );
    process.stdout.write(`done\n`);

    return true;
  } catch (err) {
    const msg = err.response?.data?.message || err.message;
    console.error(`  FAILED: ${msg}`);
    return false;
  } finally {
    try { fs.unlinkSync(inputPath); } catch {}
    try { fs.unlinkSync(outputPath); } catch {}
  }
}

async function run() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.log('Usage:');
    console.log('  node ocr.js folder <folder_id>   OCR all PDFs in a Box folder');
    console.log('  node ocr.js file <file_id>        OCR a single PDF');
    console.log('');
    console.log('Get IDs from the Box URL:');
    console.log('  https://app.box.com/folder/123456  → folder 123456');
    console.log('  https://app.box.com/file/789012    → file 789012');
    process.exit(0);
  }

  const [mode, id] = args;

  if (!['file', 'folder'].includes(mode) || !id) {
    console.error('Invalid arguments. Run "node ocr.js" for usage.');
    process.exit(1);
  }

  if (mode === 'file') {
    // Get file info first
    const { data: fileInfo } = await boxApi.get(`/files/${id}`, { params: { fields: 'id,name' } });
    console.log(`\nProcessing: ${fileInfo.name}`);
    const ok = await ocrFile(fileInfo.id, fileInfo.name);
    console.log(ok ? '\nDone! File is now searchable in Box.' : '\nFailed.');
  } else {
    // Get folder info
    const { data: folderInfo } = await boxApi.get(`/folders/${id}`, { params: { fields: 'id,name' } });
    const pdfs = await listPdfsInFolder(id);

    if (pdfs.length === 0) {
      console.log(`\nNo PDFs found in folder "${folderInfo.name}".`);
      process.exit(0);
    }

    console.log(`\nFound ${pdfs.length} PDF(s) in "${folderInfo.name}":\n`);

    let success = 0;
    let failed = 0;

    for (let i = 0; i < pdfs.length; i++) {
      const pdf = pdfs[i];
      console.log(`[${i + 1}/${pdfs.length}] ${pdf.name}`);
      const ok = await ocrFile(pdf.id, pdf.name);
      if (ok) success++;
      else failed++;
      console.log('');
    }

    console.log(`Done! ${success} succeeded, ${failed} failed.`);
  }
}

run().catch(err => {
  console.error('Error:', err.response?.data?.message || err.message);
  process.exit(1);
});
