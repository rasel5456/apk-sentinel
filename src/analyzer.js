import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import AdmZip from 'adm-zip';

const SIGNALS = [
  { pattern: /BIND_ACCESSIBILITY_SERVICE|AccessibilityService/i, score: 20, title: 'Accessibility service', detail: 'May enable broad UI observation or interaction; verify the app purpose.' },
  { pattern: /RECEIVE_BOOT_COMPLETED|BOOT_COMPLETED/i, score: 15, title: 'Boot persistence', detail: 'Can request startup after device reboot.' },
  { pattern: /READ_SMS|RECEIVE_SMS|SEND_SMS/i, score: 18, title: 'SMS access', detail: 'Can read, receive, or send SMS depending on the declared capability.' },
  { pattern: /RECORD_AUDIO|CAMERA/i, score: 12, title: 'Sensor access', detail: 'Requests microphone or camera capability; validate necessity.' },
  { pattern: /DexClassLoader|PathClassLoader|loadLibrary/i, score: 15, title: 'Dynamic code loading', detail: 'Can load code at runtime and deserves additional review.' },
  { pattern: /Runtime\.exec|ProcessBuilder|su\s/i, score: 18, title: 'Shell execution indicator', detail: 'References process or shell execution APIs.' },
  { pattern: /DeviceAdminReceiver|BIND_DEVICE_ADMIN/i, score: 15, title: 'Device administration', detail: 'May request elevated device-management capabilities.' },
  { pattern: /https?:\/\/[^\s"'<>]+/ig, score: 8, title: 'External endpoint', detail: 'Contains a network endpoint; inspect ownership and purpose.' }
];

const PERMISSION_WEIGHTS = {
  'READ_SMS': 15, 'RECEIVE_SMS': 15, 'SEND_SMS': 12, 'RECORD_AUDIO': 10,
  'CAMERA': 8, 'ACCESS_FINE_LOCATION': 8, 'ACCESS_COARSE_LOCATION': 5,
  'READ_CONTACTS': 8, 'READ_CALL_LOG': 12, 'WRITE_EXTERNAL_STORAGE': 5,
  'REQUEST_INSTALL_PACKAGES': 15, 'SYSTEM_ALERT_WINDOW': 15,
  'BIND_ACCESSIBILITY_SERVICE': 20, 'RECEIVE_BOOT_COMPLETED': 10
};

function riskBand(score) {
  if (score >= 70) return 'Critical';
  if (score >= 45) return 'High';
  if (score >= 20) return 'Medium';
  return 'Low';
}

function unique(list) { return [...new Set(list)]; }

export async function analyzeApk(filePath, originalName = 'sample.apk') {
  const buffer = await fs.readFile(filePath);
  const hash = crypto.createHash('sha256').update(buffer).digest('hex');
  let zip;
  try { zip = new AdmZip(buffer); } catch { throw new Error('The uploaded file is not a readable APK/ZIP archive.'); }
  const entries = zip.getEntries().map((entry) => entry.entryName);
  if (!entries.includes('AndroidManifest.xml')) throw new Error('AndroidManifest.xml was not found; upload a valid APK.');

  const textParts = [];
  for (const entry of zip.getEntries()) {
    if (entry.isDirectory) continue;
    const data = entry.getData();
    const printable = data.toString('latin1').replace(/[^\x20-\x7E\n\r\t]/g, ' ');
    textParts.push(printable);
  }
  const corpus = textParts.join('\n');
  const permissions = unique([...corpus.matchAll(/android\.permission\.([A-Z0-9_]+)/g)].map((m) => m[1]));
  const components = unique([...corpus.matchAll(/(?:activity|service|receiver|provider)[^\n]{0,100}/gi)].map((m) => m[0].slice(0, 120)));
  const endpoints = unique([...corpus.matchAll(/https?:\/\/[^\s"'<>]+/ig)].map((m) => m[0].replace(/[),.;]+$/, ''))).slice(0, 30);
  const indicators = [];
  let score = 0;
  for (const signal of SIGNALS) {
    if (signal.pattern.test(corpus)) {
      const increment = signal.title === 'External endpoint' ? Math.min(12, endpoints.length * signal.score) : signal.score;
      score += increment;
      indicators.push({ title: signal.title, detail: signal.detail, score: increment });
    }
  }
  for (const permission of permissions) {
    if (PERMISSION_WEIGHTS[permission]) {
      score += PERMISSION_WEIGHTS[permission];
      indicators.push({ title: `Sensitive permission: ${permission}`, detail: 'Review whether this permission is necessary for the app’s stated function.', score: PERMISSION_WEIGHTS[permission] });
    }
  }
  score = Math.min(100, score);
  return {
    file: originalName, sha256: hash, sizeBytes: buffer.length, analyzedAt: new Date().toISOString(),
    archiveEntries: entries.length, permissions, components: components.slice(0, 30), endpoints,
    indicators, score, risk: riskBand(score), disclaimer: 'Heuristic static analysis only; review findings in an isolated, authorized lab.'
  };
}
