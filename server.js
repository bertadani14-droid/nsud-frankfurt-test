'use strict';

// Minimal outbound HTTPS diagnostic for the public Slovak Supreme Court site.
// Fixed destination URLs; NO arbitrary URL proxy, tokens, or user data.
const http = require('node:http');
const https = require('node:https');
const { lookup } = require('node:dns').promises;

const targets = [
  ['NSSR_HTTPS_HOME', 'https://www.nsud.sk/'],
  ['NSSR_OPENDATA', 'https://www.nsud.sk/ws/opendata.php?getDecision&id=124230'],
  ['NSSR_F018_PDF', 'https://www.nsud.sk/data/att/659/873803.b15efc.pdf'],
  ['NSSR_HTTP_CONTROL', 'http://www.nsud.sk/'],
  ['JUSTICE_HTTPS_CONTROL', 'https://www.justice.gov.sk/'],
];

const report = {
  title: 'NS SR connectivity test — Render instance',
  info: 'Single outbound probe on server startup. Browser access to this JSON never triggers new requests.',
  started_at: new Date().toISOString(),
  completed_at: null,
  region: process.env.RENDER_REGION || 'not supplied by Render',
  status: 'running',
  dns: null,
  results: [],
};

async function resolveDns() {
  try {
    return { ok: true, addresses: await lookup('www.nsud.sk', { all: true }) };
  } catch (err) {
    return { ok: false, code: err.code || 'DNS_ERROR', message: String(err.message || err) };
  }
}

function probe(label, urlString) {
  return new Promise((resolve) => {
    const started = Date.now();
    const address = new URL(urlString);
    const mod = address.protocol === 'https:' ? https : http;
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      resolve({ label, url: urlString, elapsed_ms: Date.now() - started, ...value });
    };
    const req = mod.get(urlString, {
      timeout: 10000,
      headers: {
        'User-Agent': 'NSSR-connectivity-diagnostic/1.0',
        Accept: '*/*',
      },
    }, (res) => {
      const result = {
        outcome: 'http_response',
        status_code: res.statusCode,
        remote_ip: res.socket?.remoteAddress || null,
        location: res.headers.location || null,
        content_type: res.headers['content-type'] || null,
      };
      // Do not download document content; only verify headers/connection.
      finish(result);
      res.destroy();
    });
    req.on('timeout', () => req.destroy(Object.assign(new Error('Connection timed out'), { code: 'ETIMEDOUT' })));
    req.on('error', (err) => finish({ outcome: 'connection_error', code: err.code || null, message: String(err.message || err) }));
  });
}

const port = Number(process.env.PORT || 10000);
const server = http.createServer((req, res) => {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  if (req.url === '/health') {
    res.writeHead(200);
    res.end(JSON.stringify({ status: 'ok' }));
    return;
  }
  if (req.url !== '/' && req.url !== '/report') {
    res.writeHead(404);
    res.end(JSON.stringify({ error: 'not found' }));
    return;
  }
  res.writeHead(200);
  res.end(JSON.stringify(report, null, 2));
});

server.listen(port, '0.0.0.0', async () => {
  report.dns = await resolveDns();
  for (const [label, url] of targets) {
    report.results.push(await probe(label, url));
  }
  report.completed_at = new Date().toISOString();
  report.status = 'completed';
});
