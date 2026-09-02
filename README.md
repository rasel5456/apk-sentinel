# APK Sentinel

**APK Sentinel** is a defensive, explainable static analyzer for Android packages that you own or are authorized to inspect. It reads the APK archive, extracts visible metadata and strings, and produces a heuristic risk report. It never installs, executes, controls, or exfiltrates data from a device.

## Highlights

- SHA-256 artifact hashing
- APK ZIP structure validation
- Permission and component discovery
- Suspicious API, persistence, and endpoint indicators
- Explainable Low / Medium / High / Critical scoring
- Responsive dashboard with drag-and-drop upload
- JSON report download
- 25 MB upload limit, temporary-file cleanup, security headers

## Run locally

```bash
npm install
npm start
```

Open <http://localhost:3000>. Validate the installation with:

```bash
npm test
npm run lint
```

## Deploy to your website

This is a Node.js application, so it needs a Node-compatible host such as Render, Railway, Fly.io, an VPS, or your own server. Set the start command to `npm start`, expose the assigned `PORT`, and point a subdomain such as `sentinel.example.com` to the deployed service. The root URL serves the dashboard automatically.

For a website menu or landing page, link to the deployed URL:

```html
<a href="https://sentinel.example.com">Open APK Sentinel</a>
```

Embedding in an iframe is possible only when your host and security policy allow it:

```html
<iframe src="https://sentinel.example.com" title="APK Sentinel" width="100%" height="900" loading="lazy"></iframe>
```

Before public production use, add authentication, rate limiting, HTTPS, malware-sandbox isolation, upload retention rules, and an abuse-monitoring policy. Do not expose dynamic execution of APKs on the same server as the web app.

## Scope and limitations

This is a **heuristic static analyzer**, not a malware verdict. It does not fully decode every binary Android manifest, decompile code, execute samples, bypass permissions, or perform dynamic analysis. Findings should be reviewed by a qualified analyst in an isolated lab.

Only analyze samples in a controlled environment and only with appropriate authorization.

## License

Copyright © 2026 APK Sentinel contributors. See the repository for project terms.
