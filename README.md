# APK Sentinel

APK Sentinel is a small, defensive MVP for **static analysis of Android APK files that you own or are authorized to inspect**. It never installs, executes, controls, or exfiltrates data from a device. The analyzer reads the APK archive, extracts visible metadata and strings, and produces an explainable heuristic risk report.

## Features

- SHA-256 file hashing
- APK ZIP structure inspection
- Permission and component string discovery
- Suspicious API/domain/persistence indicators
- Explainable Low/Medium/High/Critical risk score
- Browser dashboard with JSON report download
- 25 MB upload limit and temporary-file cleanup

## Run locally

```bash
npm install
npm start
```

Open <http://localhost:3000>.

## Test

```bash
npm test
npm run lint
```

## Scope and limitations

This is a **heuristic static analyzer**, not a malware verdict. It does not decode every binary Android manifest, decompile code, execute samples, bypass permissions, or perform dynamic analysis. For an authorized lab, integrate a separately isolated MobSF/sandbox service after adding authentication, queueing, retention controls, and network isolation.

Only analyze samples in a controlled environment and only with appropriate authorization.
