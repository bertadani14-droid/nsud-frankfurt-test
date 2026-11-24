'use strict';
// NS SR official-source diagnostics + restricted, authenticated source relay.
// Public diagnostics remain read-only. No user-supplied arbitrary host is fetched.
const http = require('node:http');
const https = require('node:https');
const crypto = require('node:crypto');
const {lookup} = require('node:dns').promises;
const PORT = Number(process.env.PORT || 10000);
const TOKEN = String(process.env.NSSR_PROXY_TOKEN || '');
const MAX_REQUEST_BYTES = 12 * 1024;
const MAX_SOURCE_BYTES = 16 * 1024 * 1024;
const targets = [
  ['NSSR_HTTPS_HOME', 'https://www.nsud.sk/'],
  ['NSSR_OPENDATA', 'https://www.nsud.sk/ws/opendata.php?getDecision&id=124230'],
  ['NSSR_F018_PDF', 'https://www.nsud.sk/data/att/659/873803.b15efc.pdf'],
  ['NSSR_HTTP_CONTROL', 'http://www.nsud.sk/'],
  ['JUSTICE_HTTPS_CONTROL', 'https://www.justice.gov.sk/'],
  ['HB_NORM_PORTAL', 'https://www.transparenz.bremen.de/vorschriften-72741'],
  ['HB_NORM_SEARCH', 'https://www.transparenz.bremen.de/vorschriften-72741?id=72743&gsid=kogis_tp_berlin01.c.60176.de&_article_id=72743&fulltext=Bremische%20Landesverfassung&fileCnt=on&skip=0&max=50'],
  ['HB_OVG_CASE_LIST', 'https://www.oberverwaltungsgericht.bremen.de/entscheidungen/entscheidungsuebersicht-11265?max=100&skip=0'],
  ['HB_NORM_HTTP_CONTROL', 'http://www.transparenz.bremen.de/vorschriften-72741'],
  ['HB_OVG_HTTP_CONTROL', 'http://www.oberverwaltungsgericht.bremen.de/entscheidungen/entscheidungsuebersicht-11265']
];
const report = {
  title: 'NS SR and Bremen (HB) connectivity test — Render instance',
  info: 'Single outbound probe on server startup. Browser access to this JSON never triggers new requests.',
  started_at: new Date().toISOString(), completed_at: null,
  region: process.env.RENDER_REGION || 'not supplied by Render',
  status: 'running', dns: null, bremen_dns: null, results: []
};
async function resolveDns() {
  try { return {ok:true,addresses:await lookup('www.nsud.sk',{all:true})}; }
  catch(err) { return {ok:false,code:err.code || 'DNS_ERROR',message:String(err.message || err)}; }
}
async function resolveBremenDns() {
  const output=[];
  for (const host of ['www.transparenz.bremen.de','www.oberverwaltungsgericht.bremen.de']) {
    try { output.push({host,ok:true,addresses:await lookup(host,{all:true})}); }
    catch(err) { output.push({host,ok:false,code:err.code || 'DNS_ERROR',message:String(err.message || err)}); }
  }
  return output;
}
function probe(label,urlString) {
  return new Promise(resolve => {
    const started=Date.now(); let settled=false;
    const finish=value=>{if(settled)return;settled=true;resolve({label,url:urlString,elapsed_ms:Date.now()-started,...value});};
    const address=new URL(urlString);
    const transport=address.protocol==='https:'?https:http;
    const req=transport.get(urlString,{timeout:10000,headers:{'User-Agent':'NSSR-connectivity-diagnostic/1.0',Accept:'*/*'}},res=>{
      finish({outcome:'http_response',status_code:res.statusCode,remote_ip:res.socket?.remoteAddress || null,
        location:res.headers.location || null,content_type:res.headers['content-type'] || null});
      res.destroy();
    });
    req.on('timeout',()=>req.destroy(Object.assign(new Error('Connection timed out'),{code:'ETIMEDOUT'})));
    req.on('error',err=>finish({outcome:'connection_error',code:err.code || null,message:String(err.message || err)}));
  });
}
function json(res,status,data) {
  if(res.headersSent)return;
  res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});
  res.end(JSON.stringify(data));
}
function tokenMatches(req) {
  if(!TOKEN || Buffer.byteLength(TOKEN,'utf8') < 32)return false;
  const auth=String(req.headers.authorization || '');
  if(!auth.startsWith('Bearer '))return false;
  const a=Buffer.from(auth.slice(7),'utf8'),b=Buffer.from(TOKEN,'utf8');
  return a.length===b.length && crypto.timingSafeEqual(a,b);
}
function validateOfficialTarget(rawUrl,method) {
  if(typeof rawUrl!=='string' || rawUrl.length>3000 || !['GET','POST'].includes(method))return null;
  let u;
  try {u=new URL(rawUrl);}catch{return null;}
  if(u.protocol!=='https:' || !['www.nsud.sk','nsud.sk'].includes(u.hostname) ||
     u.port || u.username || u.password || u.hash || u.search.length>2400)return null;
  const p=u.pathname;
  const decision = /^\/rozhodnutia\/(?:[a-z0-9-]{1,100}\/)?$/i.test(p);
  const collection = p==='/zbierka-stanovisk-a-rozhodnuti/';
  const api = p==='/ws/opendata.php';
  const pdf = /^\/data\/att\/(?:[a-z0-9-]+\/)?[a-z0-9._-]+\.pdf$/i.test(p);
  if(!decision && !collection && !api && !pdf)return null;
  if(method==='POST' && !collection)return null;
  return u;
}
function officialHeaders(incoming,method,contentType) {
  const out={'User-Agent':'NSSR-source-relay/1.0 (+official-document-fetch)',Accept:'*/*'};
  const h=incoming && typeof incoming==='object'?incoming:{};
  const accept=String(h.Accept || h.accept || '').slice(0,150);
  if(/^[\w\s,;.*\/+=-]+$/.test(accept))out.Accept=accept;
  const cookie=String(h.Cookie || h.cookie || '');
  if(/^PHPSESSID=[A-Za-z0-9_-]{5,100}$/.test(cookie))out.Cookie=cookie;
  const referer=String(h.Referer || h.referer || '');
  if(/^https:\/\/(?:www\.)?nsud\.sk\/[a-z0-9\/?=&%._-]*$/i.test(referer))out.Referer=referer;
  if(method==='POST')out['Content-Type']=contentType;
  return out;
}
function receiveBody(req) {
  return new Promise((resolve,reject)=>{
    const chunks=[];let size=0;
    req.on('data',chunk=>{
      size+=chunk.length;
      if(size>MAX_REQUEST_BYTES){reject(new Error('REQUEST_TOO_LARGE'));req.destroy();return;}
      chunks.push(chunk);
    });
    req.on('end',()=>resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error',reject);
  });
}
function requestOfficial(url,method,headers,payload) {
  return new Promise((resolve,reject)=>{
    const upstream=https.request({protocol:'https:',hostname:url.hostname,port:443,
      path:url.pathname+url.search,method,headers,timeout:22000},response=>{
      const chunks=[];let size=0;
      response.on('data',chunk=>{
        size+=chunk.length;
        if(size>MAX_SOURCE_BYTES){upstream.destroy(new Error('SOURCE_TOO_LARGE'));return;}
        chunks.push(chunk);
      });
      response.on('end',()=>resolve({status:response.statusCode,headers:response.headers,body:Buffer.concat(chunks)}));
      response.on('error',reject);
    });
    upstream.on('timeout',()=>upstream.destroy(new Error('SOURCE_TIMEOUT')));
    upstream.on('error',reject);
    if(method==='POST' && payload)upstream.write(payload);
    upstream.end();
  });
}
async function relay(req,res) {
  if(req.method!=='POST')return json(res,405,{error:'method not allowed'});
  if(!TOKEN || Buffer.byteLength(TOKEN,'utf8')<32)return json(res,503,{error:'relay not configured'});
  if(!tokenMatches(req))return json(res,401,{error:'unauthorized'});
  let input;
  try {input=JSON.parse(await receiveBody(req));}
  catch {return json(res,400,{error:'invalid request JSON'});}
  const method=String(input.method || 'GET').toUpperCase();
  const url=validateOfficialTarget(input.url,method);
  if(!url)return json(res,400,{error:'source URL or method not allowed'});
  const contentType=String(input.contentType || 'application/x-www-form-urlencoded');
  if(method==='POST' && !['application/x-www-form-urlencoded','application/json'].includes(contentType))
    return json(res,400,{error:'content type not allowed'});
  const payload=input.payload==null?'':String(input.payload);
  if(Buffer.byteLength(payload,'utf8')>8000)return json(res,400,{error:'POST content too large'});
  const headers=officialHeaders(input.headers,method,contentType);
  if(method==='POST')headers['Content-Length']=Buffer.byteLength(payload,'utf8');
  try {
    const upstream=await requestOfficial(url,method,headers,payload);
    if(upstream.status>=300 && upstream.status<400)
      return json(res,502,{error:'official source redirect not followed',upstream_status:upstream.status});
    const replyHeaders={
      'Content-Type':upstream.headers['content-type'] || 'application/octet-stream',
      'Cache-Control':'no-store','X-NSSR-Proxy':'nssr-relay-v1',
      'X-NSSR-Upstream-Status':String(upstream.status)
    };
    // Preserve the official PHP session for the F018 year-filter POST.
    if(upstream.headers['set-cookie'])replyHeaders['Set-Cookie']=upstream.headers['set-cookie'];
    res.writeHead(upstream.status,replyHeaders);
    res.end(upstream.body);
  }catch(err){return json(res,502,{error:'official source fetch failed',reason:String(err.message || 'NETWORK_ERROR').slice(0,100)});}
}
// Bulgaria court relay — isolated namespace, same server and token.
const bgCourtsRelay = (() => {
'use strict';
// Additive Bulgaria transport for the existing Frankfurt server. No dependencies.
// Only public, already identified court endpoints. No redirects, cookies or credentials upstream.
const https = require('node:https');
const crypto = require('node:crypto');
const MAX_REQUEST = 12 * 1024;
const MAX_RESPONSE = 16 * 1024 * 1024;
const TIMEOUT = 22000;
function send(res, code, data) {
  if (res.destroyed || res.headersSent) return;
  res.writeHead(code, {'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});
  res.end(JSON.stringify(data));
}
function authorized(req, token) {
  const a = Buffer.from(String(req.headers.authorization || ''), 'utf8');
  const b = Buffer.from('Bearer ' + token, 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a,b);
}
function validatedUrl(raw) {
  if (typeof raw !== 'string' || raw.length > 3000 || /[\r\n\\]/.test(raw)) return null;
  let u; try { u = new URL(raw); } catch { return null; }
  if (u.protocol !== 'https:' || u.username || u.password || u.port || u.hash) return null;
  const p = u.pathname;
  if (u.hostname === 'www.vks.bg') return p === '/search.html' && !u.search ? u : null;
  if (u.hostname === 'www.constcourt.bg') {
    if (p === '/bg/search-acts' && !u.search) return u;
    if (/^\/bg\/(?:act-\d+|case-\d+|dl-[a-f0-9]+)$/i.test(p) && !u.search) return u;
    if (p !== '/') return null;
    const keys = ['mode','year','number','act_type','judge','status','search'];
    if ([...u.searchParams.keys()].some(k => !keys.includes(k))) return null;
    if (u.searchParams.getAll('mode').length !== 1 || !['search_acts','search_cases'].includes(u.searchParams.get('mode'))) return null;
    return u;
  }
  if (u.hostname === 'sac.justice.bg') {
    const base = '/wp-json/vas/v1/edis/';
    if (!p.startsWith(base)) return null;
    const endpoint = p.slice(base.length);
    if (endpoint === 'bodies' || /^cases\/[a-zA-Z0-9_-]{1,100}$/.test(endpoint)) return !u.search ? u : null;
    if (endpoint === 'search') {
      const keys = ['reference_no','year','inst','predmet','material','department_id','reg_no','reg_year','kind','doc_type','appealed_case_no','appealed_case_year','administrative_body','ot_data','do_data','order','q','limit','offset'];
      return [...u.searchParams.keys()].every(k => keys.includes(k)) ? u : null;
    }
    if (endpoint === 'document' || endpoint === 'document/pdf') {
      if ([...u.searchParams.keys()].length !== 1 || u.searchParams.getAll('url').length !== 1) return null;
      const rawNested = u.searchParams.get('url');
      if (!/^https:\/\/info-adc\.justice\.bg\/courts\/portal\/edis\.nsf\/e_(?:act|document|protocol|reportslist)\.xsp\?[^#\s\\]+$/i.test(rawNested)) return null;
      let nested; try { nested = new URL(rawNested); } catch { return null; }
      return nested.hostname === 'info-adc.justice.bg' && !nested.username && !nested.password && !nested.port && !nested.hash ? u : null;
    }
  }
  return null;
}
function body(req) {
  return new Promise((resolve,reject) => {
    const chunks=[]; let size=0, tooLarge=false;
    req.on('data', c => { size += c.length; if(size > MAX_REQUEST) {tooLarge=true; chunks.length=0;} else if(!tooLarge) chunks.push(c); });
    req.on('end', () => tooLarge ? reject(new Error('REQUEST_TOO_LARGE')) : resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject); req.on('aborted', () => reject(new Error('REQUEST_ABORTED')));
  });
}
function requestOfficial(u, accept) {
  return new Promise((resolve,reject) => {
    const req = https.request({protocol:'https:',hostname:u.hostname,port:443,path:u.pathname+u.search,method:'GET',headers:{'User-Agent':'BHGY-BG-public-source-relay/1.0',Accept:accept,'Accept-Encoding':'identity'},timeout:TIMEOUT}, response => {
      const chunks=[]; let size=0;
      response.on('data', c => {size+=c.length; if(size>MAX_RESPONSE) req.destroy(Object.assign(new Error('SOURCE_TOO_LARGE'),{code:'SOURCE_TOO_LARGE'})); else chunks.push(c);});
      response.on('end', () => resolve({status:response.statusCode,headers:response.headers,body:Buffer.concat(chunks)}));
      response.on('aborted',()=>reject(Object.assign(new Error('SOURCE_ABORTED'),{code:'SOURCE_ABORTED'})));
      response.on('error',reject);
    });
    const timer=setTimeout(()=>req.destroy(Object.assign(new Error('SOURCE_TIMEOUT'),{code:'SOURCE_TIMEOUT'})),TIMEOUT);
    req.on('close',()=>clearTimeout(timer));
    req.on('timeout',()=>req.destroy(Object.assign(new Error('SOURCE_TIMEOUT'),{code:'SOURCE_TIMEOUT'})));
    req.on('error',reject); req.end();
  });
}
async function bgRelay(req,res) {
  if(req.method!=='POST') return send(res,405,{error:'method not allowed',relay:'bg-courts-v1'});
  const token=String(process.env.NSSR_PROXY_TOKEN || '');
  if(Buffer.byteLength(token,'utf8')<32) return send(res,503,{error:'relay not configured'});
  if(!authorized(req,token)) return send(res,401,{error:'unauthorized'});
  let input; try {input=JSON.parse(await body(req));} catch(e){return send(res,400,{error:e.message==='REQUEST_TOO_LARGE'?'request too large':'invalid request JSON'});}
  if(!input || typeof input!=='object' || String(input.method || 'GET').toUpperCase()!=='GET' || input.payload) return send(res,400,{error:'only GET source requests allowed'});
  const u=validatedUrl(input.url);
  if(!u) return send(res,400,{error:'source URL not allowed'});
  const rawAccept=String((input.headers||{}).Accept || '*/*');
  const accept=/^[\w\s,;.*\/+=-]{1,150}$/.test(rawAccept) && !/[\r\n]/.test(rawAccept)?rawAccept:'*/*';
  try {
    const upstream=await requestOfficial(u,accept);
    if(res.destroyed) return;
    const h={'Content-Type':upstream.headers['content-type']||'application/octet-stream','Cache-Control':'no-store','X-BG-Proxy':'bg-courts-v1','X-BG-Upstream-Status':String(upstream.status)};
    if(upstream.headers['content-encoding']) h['Content-Encoding']=upstream.headers['content-encoding'];
    // No redirect following and no upstream cookies. Preserve status for diagnostics.
    if(upstream.headers.location && /^[\x20-\x7e]{1,1000}$/.test(upstream.headers.location)) h['X-BG-Upstream-Location']=upstream.headers.location;
    res.writeHead(upstream.status,h); res.end(upstream.body);
  } catch(e) { return send(res,502,{error:'official source fetch failed',reason:String(e.code||'NETWORK_ERROR').slice(0,80)}); }
}
return bgRelay;

})();
const server=http.createServer((req,res)=>{
  if(req.url==='/api/bg-courts') {void bgCourtsRelay(req,res);return;}
  if(req.url==='/api/nssr') {void relay(req,res);return;}
  if(req.url==='/health')return json(res,200,{status:'ok',relay_configured:Boolean(TOKEN && Buffer.byteLength(TOKEN,'utf8')>=32)});
  if(req.url==='/bremen')return json(res,200,{
    title:'Bremen (HB) official-source connectivity test',
    note:'A HTTP 200 response confirms connectivity only, not successful legal-text extraction.',
    started_at:report.started_at,completed_at:report.completed_at,region:report.region,
    status:report.status,dns:report.bremen_dns,results:report.results.filter(x=>x.label.startsWith('HB_'))
  });
  if(req.url==='/' || req.url==='/report')return json(res,200,report);
  return json(res,404,{error:'not found'});
});
server.listen(PORT,'0.0.0.0',async()=>{
  report.dns=await resolveDns();
  report.bremen_dns=await resolveBremenDns();
  for(const [label,url] of targets) report.results.push(await probe(label,url));
  report.completed_at=new Date().toISOString();
  report.status='completed';
});
