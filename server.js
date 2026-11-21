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
  // Bremen (HB) endpoints read from NEMET_TARTOMANYOK.gs v1.5.9.
  ['HB_NORM_PORTAL', 'https://www.transparenz.bremen.de/vorschriften-72741'],
  ['HB_NORM_SEARCH', 'https://www.transparenz.bremen.de/vorschriften-72741?id=72743&gsid=kogis_tp_berlin01.c.60176.de&_article_id=72743&fulltext=Bremische%20Landesverfassung&fileCnt=on&skip=0&max=50'],
  ['HB_OVG_CASE_LIST', 'https://www.oberverwaltungsgericht.bremen.de/entscheidungen/entscheidungsuebersicht-11265?max=100&skip=0'],
  ['HB_NORM_HTTP_CONTROL', 'http://www.transparenz.bremen.de/vorschriften-72741'],
  ['HB_OVG_HTTP_CONTROL', 'http://www.oberverwaltungsgericht.bremen.de/entscheidungen/entscheidungsuebersicht-11265'],
];

const report = {
  title: 'NS SR and Bremen (HB) connectivity test — Render instance',
  info: 'Single outbound probe on server startup. Browser access to this JSON never triggers new requests.',
  started_at: new Date().toISOString(),
  completed_at: null,
  region: process.env.RENDER_REGION || 'not supplied by Render',
  status: 'running',
  dns: null,
  bremen_dns: null,
  results: [],
};

async function resolveBremenDns() {
  const hosts = ['www.transparenz.bremen.de', 'www.oberverwaltungsgericht.bremen.de'];
  const results = [];
  for (const host of hosts) {
    try {
      results.push({ host, ok: true, addresses: await lookup(host, { all: true }) });
    } catch (err) {
      results.push({ host, ok: false, code: err.code || 'DNS_ERROR', message: String(err.message || err) });
    }
  }
  return results;
}

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
  // Separate read-only report for Bremen; no user-supplied URLs or live proxying.
  if (req.url === '/bremen') {
    res.writeHead(200);
    res.end(JSON.stringify({
      title: 'Bremen (HB) official-source connectivity test',
      note: 'A HTTP 200 response confirms connectivity only, not successful legal-text extraction.',
      started_at: report.started_at,
      completed_at: report.completed_at,
      region: report.region,
      status: report.status,
      dns: report.bremen_dns,
      results: report.results.filter(x => x.label.startsWith('HB_')),
    }, null, 2));
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
  report.bremen_dns = await resolveBremenDns();
  for (const [label, url] of targets) {
    report.results.push(await probe(label, url));
  }
  report.completed_at = new Date().toISOString();
  report.status = 'completed';
});
