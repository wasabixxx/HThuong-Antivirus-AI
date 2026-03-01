const API_BASE = '/api';

export async function scanFile(file) {
  const formData = new FormData();
  formData.append('file', file);

  const resp = await fetch(`${API_BASE}/scan/file`, {
    method: 'POST',
    body: formData,
  });
  if (!resp.ok) throw new Error(`Scan failed: ${resp.status}`);
  return resp.json();
}

export async function scanUrl(url) {
  const resp = await fetch(`${API_BASE}/scan/url`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  });
  if (!resp.ok) throw new Error(`URL scan failed: ${resp.status}`);
  return resp.json();
}

export async function checkWAF(payload) {
  const resp = await fetch(`${API_BASE}/waf/check`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ payload }),
  });
  if (!resp.ok) throw new Error(`WAF check failed: ${resp.status}`);
  return resp.json();
}

export async function getStats() {
  const resp = await fetch(`${API_BASE}/stats`);
  if (!resp.ok) throw new Error(`Stats failed: ${resp.status}`);
  return resp.json();
}

export async function getHealth() {
  const resp = await fetch(`${API_BASE}/health`);
  if (!resp.ok) throw new Error(`Health failed: ${resp.status}`);
  return resp.json();
}

export async function getHistory(limit = 50) {
  const resp = await fetch(`${API_BASE}/history?limit=${limit}`);
  if (!resp.ok) throw new Error(`History failed: ${resp.status}`);
  return resp.json();
}

export async function scanDirectory(path) {
  const resp = await fetch(`${API_BASE}/scan/directory`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path }),
  });
  if (!resp.ok) throw new Error(`Directory scan failed: ${resp.status}`);
  return resp.json();
}
