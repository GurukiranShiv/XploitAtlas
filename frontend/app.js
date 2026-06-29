const API = localStorage.getItem('apiBase') || 'http://localhost:8000';

const el = (id) => document.getElementById(id);

async function request(path, options = {}) {
  const response = await fetch(`${API}${path}`, options);
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`${response.status}: ${text}`);
  }
  return response.json();
}

function renderStats(stats) {
  const cards = [
    ['Total', stats.total_findings],
    ['Critical', stats.critical],
    ['High', stats.high],
    ['Medium', stats.medium],
    ['KEV', stats.kev_count],
    ['Exposed', stats.internet_exposed_count],
  ];
  el('statsCards').innerHTML = cards.map(([label, value]) => `
    <article class="card"><span>${label}</span><strong>${value}</strong></article>
  `).join('');
}

function renderFindings(findings) {
  el('findingsTable').innerHTML = findings.map((f) => `
    <tr>
      <td><span class="badge">${f.risk_rating} ${f.risk_score}</span></td>
      <td>${f.cve}<br><small>${f.title}</small></td>
      <td>${f.asset.hostname}<br><small>${f.asset.ip_address || ''}</small></td>
      <td>${f.asset.exposure}</td>
      <td>${f.cvss_score}</td>
      <td>${f.threat_intel?.epss_score ?? 'N/A'}</td>
      <td>${f.threat_intel?.is_kev ? 'Yes' : 'No'}</td>
      <td>${f.sla}</td>
      <td class="reason">${f.priority_reason}</td>
    </tr>
  `).join('') || '<tr><td colspan="9">No findings yet. Click “Load Sample Scanner Findings”.</td></tr>';
}

async function refresh() {
  const rating = el('ratingFilter').value;
  const [stats, findings] = await Promise.all([
    request('/stats'),
    request(`/findings${rating ? `?rating=${encodeURIComponent(rating)}` : ''}`),
  ]);
  renderStats(stats);
  renderFindings(findings);
}

async function importFile(type) {
  const input = type === 'nuclei' ? el('nucleiFile') : el('openvasFile');
  if (!input.files.length) {
    el('importOutput').textContent = `Choose a ${type} file first.`;
    return;
  }
  const form = new FormData();
  form.append('file', input.files[0]);
  const live = el('liveEnrich').checked;
  const path = type === 'nuclei'
    ? `/import/nuclei?live_enrich=${live}&default_exposure=internet&default_business_criticality=5`
    : `/import/openvas?live_enrich=${live}&default_exposure=internal&default_business_criticality=4`;
  const result = await request(path, { method: 'POST', body: form });
  el('importOutput').textContent = JSON.stringify(result, null, 2);
  await refresh();
}

async function scorePreview() {
  const body = {
    cvss_score: Number(el('cvss').value),
    epss_score: Number(el('epss').value),
    is_kev: el('isKev').checked,
    exploit_maturity: el('maturity').value,
    exploit_available: el('maturity').value !== 'none',
    exposure: el('exposure').value,
    business_criticality: Number(el('criticality').value),
  };
  const result = await request('/score-preview', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  el('scoreOutput').textContent = JSON.stringify(result, null, 2);
}

el('seedBtn').addEventListener('click', async () => {
  const result = await request('/seed-sample-data', { method: 'POST' });
  el('importOutput').textContent = JSON.stringify(result, null, 2);
  await refresh();
});
el('refreshBtn').addEventListener('click', refresh);
el('ratingFilter').addEventListener('change', refresh);
el('importNucleiBtn').addEventListener('click', () => importFile('nuclei').catch(err => el('importOutput').textContent = err.message));
el('importOpenvasBtn').addEventListener('click', () => importFile('openvas').catch(err => el('importOutput').textContent = err.message));
el('scoreBtn').addEventListener('click', () => scorePreview().catch(err => el('scoreOutput').textContent = err.message));

refresh().catch((err) => {
  el('statsCards').innerHTML = '<article class="card"><span>API</span><strong>Off</strong></article>';
  el('findingsTable').innerHTML = `<tr><td colspan="9">Start the backend first: ${err.message}</td></tr>`;
});
