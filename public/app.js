const form = document.querySelector('#uploadForm');
const status = document.querySelector('#status');
const report = document.querySelector('#report');
const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
form.addEventListener('submit', async (event) => {
  event.preventDefault(); const file = document.querySelector('#apk').files[0]; if (!file) return;
  status.textContent = 'Analyzing locally on the server…'; report.classList.add('hidden');
  const body = new FormData(); body.append('apk', file);
  try {
    const response = await fetch('/api/analyze', { method:'POST', body }); const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Analysis failed'); render(data); status.textContent = 'Analysis complete. Temporary upload was deleted.';
  } catch (error) { status.textContent = error.message; }
});
function render(data) {
  const indicators = data.indicators.length ? `<ul>${data.indicators.map(i => `<li><strong>${esc(i.title)}</strong> <small>(+${i.score})</small><br>${esc(i.detail)}</li>`).join('')}</ul>` : '<p>No configured suspicious indicators were found.</p>';
  report.innerHTML = `<div class="summary"><div class="metric"><span>Risk</span><strong class="risk ${esc(data.risk)}">${esc(data.risk)}</strong></div><div class="metric"><span>Score</span><strong>${data.score}/100</strong></div><div class="metric"><span>Permissions</span><strong>${data.permissions.length}</strong></div><div class="metric"><span>Endpoints</span><strong>${data.endpoints.length}</strong></div></div><div class="grid"><section class="panel"><h2>Findings</h2>${indicators}</section><section class="panel"><h2>Artifact</h2><p><strong>File:</strong> ${esc(data.file)}</p><p><strong>Size:</strong> ${Number(data.sizeBytes).toLocaleString()} bytes</p><p class="hash"><strong>SHA-256:</strong><br>${esc(data.sha256)}</p><button id="download">Download JSON report</button></section></div><div class="grid"><section class="panel"><h2>Permissions</h2><div class="scroll">${data.permissions.length ? `<ul>${data.permissions.map(p => `<li>${esc(p)}</li>`).join('')}</ul>` : '<p>None found in printable archive strings.</p>'}</div></section><section class="panel"><h2>Endpoints</h2><div class="scroll">${data.endpoints.length ? `<ul>${data.endpoints.map(e => `<li class="hash">${esc(e)}</li>`).join('')}</ul>` : '<p>None found.</p>'}</div></section></div>`;
  report.classList.remove('hidden'); document.querySelector('#download').onclick = () => { const blob = new Blob([JSON.stringify(data,null,2)], {type:'application/json'}); const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `${data.file.replace(/[^a-z0-9.-]/gi,'_')}.report.json`; a.click(); URL.revokeObjectURL(a.href); };
}
