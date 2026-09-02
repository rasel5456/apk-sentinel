import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import AdmZip from 'adm-zip';
import { analyzeApk } from '../src/analyzer.js';

test('analyzes an authorized APK archive and returns explainable findings', async () => {
  const zip = new AdmZip();
  zip.addFile('AndroidManifest.xml', Buffer.from('android.permission.CAMERA android.permission.RECEIVE_SMS RECEIVE_BOOT_COMPLETED'));
  zip.addFile('classes.dex', Buffer.from('AccessibilityService https://example.test/api Runtime.exec'));
  const file = path.join(os.tmpdir(), `apk-sentinel-${Date.now()}.apk`);
  await fs.writeFile(file, zip.toBuffer());
  const result = await analyzeApk(file, 'fixture.apk');
  assert.equal(result.file, 'fixture.apk');
  assert.equal(result.sha256.length, 64);
  assert.ok(result.permissions.includes('CAMERA'));
  assert.ok(result.indicators.length > 0);
  assert.ok(['Low','Medium','High','Critical'].includes(result.risk));
  await fs.unlink(file);
});

test('rejects archives without AndroidManifest.xml', async () => {
  const zip = new AdmZip(); zip.addFile('notes.txt', Buffer.from('not an apk'));
  const file = path.join(os.tmpdir(), `not-apk-${Date.now()}.apk`);
  await fs.writeFile(file, zip.toBuffer());
  await assert.rejects(() => analyzeApk(file), /AndroidManifest/);
  await fs.unlink(file);
});
