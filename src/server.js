import express from 'express';
import multer from 'multer';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs/promises';
import { analyzeApk } from './analyzer.js';

const app = express();
const upload = multer({ dest: os.tmpdir(), limits: { fileSize: 25 * 1024 * 1024 } });
app.use(express.static(path.join(process.cwd(), 'public')));

app.post('/api/analyze', upload.single('apk'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Please upload an APK file.' });
  try {
    if (!req.file.originalname.toLowerCase().endsWith('.apk')) throw new Error('Only .apk files are accepted.');
    const report = await analyzeApk(req.file.path, req.file.originalname);
    res.json(report);
  } catch (error) {
    res.status(400).json({ error: error.message || 'Analysis failed.' });
  } finally {
    await fs.unlink(req.file.path).catch(() => {});
  }
});

app.get('/health', (_req, res) => res.json({ status: 'ok' }));
app.use((error, _req, res, _next) => res.status(413).json({ error: error.code === 'LIMIT_FILE_SIZE' ? 'File exceeds the 25 MB limit.' : 'Upload failed.' }));

const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`APK Sentinel running at http://localhost:${port}`));
