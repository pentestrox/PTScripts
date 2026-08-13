// JS Recon v7 — paste into browser console on target site
// Passive scan (static JS/HTML) + LIVE hooks (fetch/XHR/WS/postMessage) + DOM-XSS sink/source analysis
(function(){
var R={
  paths:/(?<=("|%27|`))\/[:a-zA-Z0-9_.?&=\/\-\#]*(?=("|`|'))/g,
  urls:/\b(?:https?|wss?):\/\/[^\s"'`<>()\[\]{}]+/gi,
  secrets:/(?:api[_-]?key|apikey|secret|token|password|passwd|pwd|auth|bearer|access[_-]?key|client[_-]?secret|private[_-]?key|session[_-]?id|aws[_-]?key|s3[_-]?key|stripe[_-]?key|twilio|sendgrid|slack[_-]?token|github[_-]?token|jwt|x-api-key|authorization)["' \t]*[:=]+["' \t]*([a-zA-Z0-9\-_\.~+\/=]{8,80})/gi,
  emails:/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
  ips:/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
  graphql:/\/graphql|\/api\/graphql|\/gql|ApolloClient|urql|hasura/gi,
  comments:/(?:\/\/[ \t]*(?:TODO|FIXME|HACK|DEBUG|XXX|NOTE|BUG|TEMP|NOCOMMIT)[^\n]*|\/\*[\s\S]*?\*\/)/gi,
  sourcemap:/\/\/[#@][ \t]sourceMappingURL=([^\s]+)/g
};
var TOK=[
  [/AKIA[0-9A-Z]{16}/g,'aws'],[/ASIA[0-9A-Z]{16}/g,'aws-sts'],[/AIza[0-9A-Za-z\-_]{35}/g,'google'],
  [/ya29\.[0-9A-Za-z\-_]+/g,'google-oauth'],[/eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{6,}/g,'jwt'],
  [/xox[baprs]-[0-9A-Za-z\-]{10,72}/g,'slack'],[/(?:sk|pk|rk)_(?:live|test)_[0-9A-Za-z]{16,}/g,'stripe'],
  [/gh[pousr]_[0-9A-Za-z]{36,}/g,'github'],[/glpat-[0-9A-Za-z\-_]{20}/g,'gitlab'],[/sk-[A-Za-z0-9]{20,}/g,'openai'],
  [/SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}/g,'sendgrid'],[/-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,'private-key'],
  [/firebaseio\.com|firebaseapp\.com/g,'firebase']
];
var INT=/(admin|internal|debug|config|secret|token|passwd|password|upload|backup|\.git|\.env|swagger|api-docs|actuator|graphql|console|private|credential|oauth|sudo|\/root|staging|\.bak|\.old|\.sql|\.json|\.yml|\.yaml|\.xml|\.config)/i;
var ASSET=/\.(?:css|js|mjs|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|map|mp4|webm|avif|pdf)(?:$|[?#])/i;
// DOM-XSS: [regex, sink-label, base-severity]
var SINKS=[
  [/\.(?:inner|outer)HTML\s*=/g,'innerHTML=','high'],
  [/insertAdjacentHTML\s*\(/g,'insertAdjacentHTML','high'],
  [/document\.write(?:ln)?\s*\(/g,'document.write','high'],
  [/\beval\s*\(/g,'eval','high'],
  [/new\s+Function\s*\(/g,'new Function','high'],
  [/dangerouslySetInnerHTML/g,'dangerouslySetInnerHTML','high'],
  [/set(?:Timeout|Interval)\s*\(\s*['"`]/g,'setTimeout(string)','med'],
  [/(?:location\.(?:href|assign|replace)|window\.location)\s*[=(]/g,'location=','med'],
  [/\.(?:html|append|prepend|after|before|replaceWith|wrap)\s*\(/g,'jQuery html/append','med'],
  [/\.(?:src|action)\s*=\s*[^=]/g,'.src/.action=','low'],
  [/window\.open\s*\(/g,'window.open','low']
];
// taint sources (attacker-controllable)
var SRC=/location\.(?:hash|search|href|pathname)|document\.(?:URL|documentURI|baseURI|referrer|cookie)|window\.name|\breferrer\b|\.data\b|localStorage|sessionStorage|getItem\s*\(|URLSearchParams|params\.get/;

var D={paths:new Map,urls:new Set,secrets:new Map,emails:new Set,ips:new Set,graphql:new Set,comments:new Set,sourcemaps:new Set,jsfiles:new Set,cookies:[],storage:[],network:[],params:new Map,forms:[],domxss:[]};
var seenSink=new Set;
var base=location.origin;

// ---------- helpers ----------
function copyText(str){str=(str==null)?'':String(str);if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(str).catch(function(){fallbackCopy(str);});}else{fallbackCopy(str);}}
function fallbackCopy(str){try{var ta=document.createElement('textarea');ta.value=str;ta.style.cssText='position:fixed;top:0;left:0;width:1px;height:1px;opacity:0;';document.body.appendChild(ta);ta.focus();ta.select();document.execCommand('copy');document.body.removeChild(ta);}catch(e){}}
function flash(el){el.style.background='#10b98122';setTimeout(function(){el.style.background='';},500);}
function addParam(name,src){if(!name||name.length>60)return;if(!D.params.has(name))D.params.set(name,new Set());D.params.get(name).add(src||'?');}
function qsParams(u,src){try{var q=u.split('#')[0].split('?')[1];if(!q)return;q.split('&').forEach(function(kv){var k=kv.split('=')[0];if(k)addParam(decodeURIComponent(k),src);});}catch(e){}}
function bodyParams(body,src){if(!body||typeof body!=='string')return;if(/^[^=&]+=[^=&]*(&|$)/.test(body)){body.split('&').forEach(function(kv){var k=kv.split('=')[0];if(k)addParam(decodeURIComponent(k),src);});return;}try{var o=JSON.parse(body);(function walk(x,d){if(!x||d>3)return;if(Array.isArray(x))x.forEach(function(i){walk(i,d+1);});else if(typeof x==='object')Object.keys(x).forEach(function(k){addParam(k,src);walk(x[k],d+1);});})(o,0);}catch(e){}}
function recordSink(sink,sev,tainted,snippet,src){var key=sink+'|'+(snippet||'').substring(0,80);if(seenSink.has(key))return;seenSink.add(key);if(D.domxss.length>400)return;D.domxss.push({sink:sink,sev:tainted?'HIGH':sev,tainted:!!tainted,snippet:(snippet||'').substring(0,150),src:src||'page'});}

// ---------- passive scan ----------
function scanSinks(t,src){
  SINKS.forEach(function(p){var re=p[0];re.lastIndex=0;var m,guard=0;while((m=re.exec(t))!==null&&guard++<2000){var start=m.index;var ctx=t.substring(Math.max(0,start-100),start+140);var tainted=SRC.test(ctx);var snip=ctx.replace(/\s+/g,' ').trim();recordSink(p[1],p[2],tainted,snip,src);if(m.index===re.lastIndex)re.lastIndex++;}});
}
function scanText(t,src){
  var m;R.paths.lastIndex=0;
  while((m=R.paths.exec(t))!==null){
    var method='?';var ctx=t.substring(Math.max(0,m.index-80),m.index+80);
    var mm=/\b(GET|POST|PUT|DELETE|PATCH)\b/i.exec(ctx);
    if(mm) method=mm[1].toUpperCase();else if(/fetch\s*\(/.test(ctx)) method='GET?';else if(/\.post\s*\(/.test(ctx)) method='POST';else if(/\.get\s*\(/.test(ctx)) method='GET';else if(/\.put\s*\(/.test(ctx)) method='PUT';else if(/\.delete\s*\(/.test(ctx)) method='DELETE';
    D.paths.set(m[0],method);qsParams(m[0],'path');
  }
  var u=t.matchAll(R.urls); for(var x of u){var uu=x[0].replace(/[.,)'">]+$/,'');D.urls.add(uu);qsParams(uu,'url');}
  var s=t.matchAll(R.secrets); for(var x of s) D.secrets.set(x[0].trim().substring(0,120),'kw');
  TOK.forEach(function(p){var r=t.matchAll(p[0]);for(var y of r)D.secrets.set(y[0].substring(0,120),p[1]);});
  var e=t.matchAll(R.emails); for(var x of e) D.emails.add(x[0]);
  var i=t.matchAll(R.ips); for(var x of i){if(!x[0].startsWith('0.')&&x[0]!='127.0.0.1')D.ips.add(x[0]);}
  var g=t.matchAll(R.graphql); for(var x of g) D.graphql.add(x[0].trim().substring(0,80));
  var c=t.matchAll(R.comments); for(var x of c){var cc=x[0].trim();if(cc.length>5&&cc.length<300)D.comments.add(cc);}
  R.sourcemap.lastIndex=0;while((m=R.sourcemap.exec(t))!==null) D.sourcemaps.add({ref:m[1],js:src||'inline'});
  scanSinks(t,src);
}
function scanWebStorage(){try{for(var i=0;i<localStorage.length;i++){var k=localStorage.key(i);D.storage.push({store:'localStorage',key:k,value:localStorage.getItem(k)});}}catch(e){}try{for(var j=0;j<sessionStorage.length;j++){var k2=sessionStorage.key(j);D.storage.push({store:'sessionStorage',key:k2,value:sessionStorage.getItem(k2)});}}catch(e){}}
function scanIDB(){if(!window.indexedDB||!indexedDB.databases) return Promise.resolve();return indexedDB.databases().then(function(dbs){return Promise.all((dbs||[]).map(function(info){if(!info.name) return Promise.resolve();return new Promise(function(res){var req;try{req=indexedDB.open(info.name);}catch(e){return res();}req.onsuccess=function(){var db=req.result;var stores=Array.from(db.objectStoreNames);if(!stores.length){db.close();return res();}var tx;try{tx=db.transaction(stores,'readonly');}catch(e){db.close();return res();}var pending=stores.length;function done(){if(--pending===0){try{db.close();}catch(e){}res();}}stores.forEach(function(sn){var count=0,cur;try{cur=tx.objectStore(sn).openCursor();}catch(e){return done();}cur.onsuccess=function(ev){var c=ev.target.result;if(c&&count<25){var v;try{v=JSON.stringify(c.value);}catch(e){v=String(c.value);}D.storage.push({store:'idb:'+info.name+'/'+sn,key:String(c.key),value:v||''});count++;c.continue();}else{done();}};cur.onerror=function(){done();};});};req.onerror=function(){res();};req.onblocked=function(){res();};});}));}).catch(function(){});}
function scanCaches(){if(!window.caches||!caches.keys) return Promise.resolve();return caches.keys().then(function(names){return Promise.all((names||[]).map(function(n){return caches.open(n).then(function(cache){return cache.keys().then(function(reqs){reqs.slice(0,60).forEach(function(rq){D.storage.push({store:'cache:'+n,key:rq.url,value:(rq.method||'GET')});});});});}));}).catch(function(){});}
function scanCookies(){document.cookie.split(';').forEach(function(c){var p=c.trim().split('=');if(p[0]) D.cookies.push({name:p[0].trim(),value:p.slice(1).join('=').trim()});});}
function scanForms(){Array.from(document.forms).forEach(function(f){var inputs=Array.from(f.querySelectorAll('input,select,textarea')).map(function(el){var nm=el.name||el.id||'';if(nm)addParam(nm,'form');return{name:nm,type:el.type||el.tagName.toLowerCase()};});D.forms.push({action:f.action||location.href,method:(f.method||'GET').toUpperCase(),inputs:inputs});});}

// ---------- LIVE instrumentation ----------
var refTimer=null;
function scheduleRefresh(){if(refTimer)return;refTimer=setTimeout(function(){refTimer=null;renderTab(activeTab);updateCounts();},350);}
function recordNet(method,url,kind,body){var e={method:method,url:url,kind:kind,status:'',t:Date.now()};D.network.push(e);if(/^(https?|wss?):/i.test(url))D.urls.add(url.split('#')[0]);else if(url.charAt(0)==='/')D.paths.set(url.split('?')[0],method);qsParams(url,kind);bodyParams(body,kind);if(D.network.length>500)D.network.shift();scheduleRefresh();return e;}
function installHooks(){
  try{var _f=window.fetch;if(_f&&!_f.__rx){var nf=function(){var a=arguments;var req=a[0];var url=(req&&req.url)||req;var opt=a[1]||{};var method=((opt&&opt.method)||(req&&req.method)||'GET').toUpperCase();var e=recordNet(method,String(url),'fetch',opt&&opt.body);return _f.apply(this,a).then(function(r){try{e.status=r.status;}catch(x){}scheduleRefresh();return r;});};nf.__rx=1;window.fetch=nf;}}catch(e){}
  try{var _o=XMLHttpRequest.prototype.open;if(_o&&!_o.__rx){var no=function(m,u){this.__m=m;this.__u=u;return _o.apply(this,arguments);};no.__rx=1;XMLHttpRequest.prototype.open=no;var _s=XMLHttpRequest.prototype.send;var ns=function(body){var e=recordNet((this.__m||'GET').toUpperCase(),String(this.__u),'xhr',body);this.addEventListener('load',function(){e.status=this.status;scheduleRefresh();});return _s.apply(this,arguments);};ns.__rx=1;XMLHttpRequest.prototype.send=ns;}}catch(e){}
  try{var _W=window.WebSocket;if(_W&&!_W.__rx){var nW=function(url,proto){recordNet('WS',String(url),'ws');return new _W(url,proto);};nW.prototype=_W.prototype;nW.__rx=1;window.WebSocket=nW;}}catch(e){}
  try{window.addEventListener('message',function(ev){var d=ev.data;recordNet('MSG',(ev.origin||'*'),'pmsg',typeof d==='string'?d:(function(){try{return JSON.stringify(d);}catch(e){return String(d);}})());},true);}catch(e){}
  // runtime DOM-XSS sink hooks (safe pass-throughs)
  try{var _st=window.setTimeout;if(_st&&!_st.__rx){var nst=function(f){if(typeof f==='string'){recordSink('setTimeout(string)[live]','med',true,f,'runtime');scheduleRefresh();}return _st.apply(this,arguments);};nst.__rx=1;window.setTimeout=nst;}}catch(e){}
  try{var _si=window.setInterval;if(_si&&!_si.__rx){var nsi=function(f){if(typeof f==='string'){recordSink('setInterval(string)[live]','med',true,f,'runtime');scheduleRefresh();}return _si.apply(this,arguments);};nsi.__rx=1;window.setInterval=nsi;}}catch(e){}
  try{var _dw=document.write;if(_dw&&!_dw.__rx){var ndw=function(){var a=Array.from(arguments).join('');recordSink('document.write[live]','high',true,a,'runtime');scheduleRefresh();return _dw.apply(document,arguments);};ndw.__rx=1;document.write=ndw;}}catch(e){}
}

// ---------- fingerprint / jwt ----------
function fingerprint(){var T=[];function add(n,v){T.push(v?n+' '+v:n);}try{if(window.React||document.querySelector('[data-reactroot]')||window.__REACT_DEVTOOLS_GLOBAL_HOOK__)add('React',window.React&&React.version);}catch(e){}try{if(window.__NEXT_DATA__)add('Next.js');}catch(e){}try{if(window.Vue||document.querySelector('[data-v-app]'))add('Vue',window.Vue&&Vue.version);}catch(e){}try{if(window.__NUXT__)add('Nuxt');}catch(e){}try{var ng=document.querySelector('[ng-version]');if(ng)add('Angular',ng.getAttribute('ng-version'));else if(window.angular)add('AngularJS',window.angular.version&&window.angular.version.full);}catch(e){}try{if(window.jQuery)add('jQuery',window.jQuery.fn&&window.jQuery.fn.jquery);}catch(e){}try{if(window.webpackChunk||window.webpackJsonp)add('webpack');}catch(e){}try{if(window.__APOLLO_CLIENT__)add('Apollo');}catch(e){}try{if(window.Shopify)add('Shopify');}catch(e){}try{var gen=document.querySelector('meta[name="generator"]');if(gen)add('generator: '+gen.content);}catch(e){}try{if(window.wp||document.querySelector('link[href*="wp-content"]'))add('WordPress');}catch(e){}try{if(window.gtag||window.ga||window.dataLayer)add('Analytics/GTM');}catch(e){}try{if(window.Stripe)add('Stripe.js');}catch(e){}try{if(window.grecaptcha)add('reCAPTCHA');}catch(e){}try{if(window.Sentry)add('Sentry');}catch(e){}return T;}
function b64urlDecode(s){try{s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';return atob(s);}catch(e){return null;}}
function decodeJWT(tok){try{var p=tok.split('.');var h=JSON.parse(b64urlDecode(p[0]));var pl=JSON.parse(b64urlDecode(p[1]));return{h:h,pl:pl};}catch(e){return null;}}

// ---------- run ----------
scanText(document.documentElement.outerHTML,'page');
scanWebStorage();scanCookies();scanForms();installHooks();
var fetches=[scanIDB(),scanCaches()];
Array.from(document.scripts).forEach(function(s){if(s.src){D.jsfiles.add(s.src);fetches.push(fetch(s.src).then(function(r){return r.text();}).then(function(t){scanText(t,s.src);}).catch(function(){}));}});

// ---------- UI ----------
var panel=document.createElement('div');panel.style.cssText='position:fixed;top:0;right:0;width:440px;height:100vh;background:#111827;color:#d1d5db;font-family:monospace;font-size:12px;z-index:2147483647;display:flex;flex-direction:column;border-left:2px solid #10b981;box-sizing:border-box;';
var hdr=document.createElement('div');hdr.style.cssText='padding:8px 12px;border-bottom:1px solid #1f2937;display:flex;justify-content:space-between;align-items:center;flex-shrink:0;background:#0d1117;';
hdr.innerHTML='<span style="color:#10b981;font-weight:bold;font-size:13px">&#9889; JS Recon v7</span><div style="display:flex;gap:6px"><button id="_x_ej" style="background:#374151;border:none;color:#9ca3af;cursor:pointer;padding:2px 8px;border-radius:3px;font-size:10px">JSON</button><button id="_x_em" style="background:#374151;border:none;color:#9ca3af;cursor:pointer;padding:2px 8px;border-radius:3px;font-size:10px">MD</button><button id="_x_close" style="background:#ef4444;border:none;color:white;cursor:pointer;padding:2px 8px;border-radius:3px;font-size:11px">X</button></div>';
var tabBar=document.createElement('div');tabBar.style.cssText='display:flex;flex-wrap:wrap;border-bottom:1px solid #1f2937;flex-shrink:0;background:#0d1117;';
var TABS=['paths','params','urls','network','domxss','secrets','forms','storage','cookies','graphql','maps','comments','jsfiles','tech'];
var tabEls={};
TABS.forEach(function(n){var t=document.createElement('button');t.id='_x_t_'+n;t.textContent=n;t.style.cssText='padding:5px 7px;border:none;background:none;color:#6b7280;cursor:pointer;font-size:10px;border-bottom:2px solid transparent;font-family:monospace;';t.onclick=function(){switchTab(n);};tabBar.appendChild(t);tabEls[n]=t;});
var toolbar=document.createElement('div');toolbar.style.cssText='padding:6px 10px;border-bottom:1px solid #1f2937;display:flex;gap:8px;align-items:center;flex-shrink:0;flex-wrap:wrap;';
toolbar.innerHTML='<input id="_x_search" placeholder="filter…" style="flex:1;min-width:90px;background:#0d1117;border:1px solid #1f2937;color:#d1d5db;font-family:monospace;font-size:10px;padding:3px 6px;border-radius:3px;outline:none">'
  +'<label id="_x_fu_l" style="font-size:10px;color:#9ca3af;display:flex;align-items:center;gap:4px;cursor:pointer"><input type="checkbox" id="_x_fu" style="margin:0"> +base URL</label>'
  +'<label id="_x_as_l" style="font-size:10px;color:#9ca3af;display:flex;align-items:center;gap:4px;cursor:pointer"><input type="checkbox" id="_x_assets" style="margin:0"> hide assets</label>'
  +'<button id="_x_ca" style="margin-left:auto;background:#10b981;border:none;color:#0a0a0a;cursor:pointer;padding:3px 10px;border-radius:3px;font-size:10px;font-weight:bold">copy all</button>';
var content=document.createElement('div');content.style.cssText='flex:1;overflow-y:auto;padding:6px 10px;';
var statusBar=document.createElement('div');statusBar.style.cssText='padding:4px 10px;border-top:1px solid #1f2937;font-size:10px;color:#4b5563;flex-shrink:0;background:#0d1117;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;';statusBar.textContent='Scanning...';
panel.appendChild(hdr);panel.appendChild(tabBar);panel.appendChild(toolbar);panel.appendChild(content);panel.appendChild(statusBar);
document.body.appendChild(panel);
document.getElementById('_x_close').onclick=function(){panel.remove();};
var activeTab='paths';
var C={paths:'#a3e635',params:'#facc15',urls:'#38bdf8',network:'#22d3ee',domxss:'#f87171',secrets:'#f97316',forms:'#a78bfa',storage:'#60a5fa',cookies:'#c084fc',graphql:'#f472b6',maps:'#fb923c',comments:'#94a3b8',jsfiles:'#34d399',tech:'#4ade80',emails:'#67e8f9',ips:'#fde68a',interesting:'#fb7185'};
var KIND={fetch:'#22d3ee',xhr:'#38bdf8',ws:'#f472b6',pmsg:'#fb7185'};
var SEV={HIGH:'#ef4444',high:'#f97316',med:'#eab308',low:'#94a3b8'};
function storeColor(store){if(store.indexOf('idb:')===0)return '#c084fc';if(store.indexOf('cache:')===0)return '#fb923c';if(store==='sessionStorage')return '#67e8f9';return '#60a5fa';}
function assetsHidden(){return document.getElementById('_x_assets').checked;}
function pathList(){var out=[];D.paths.forEach(function(method,path){if(assetsHidden()&&ASSET.test(path))return;out.push([path,method]);});return out;}
function empty(msg){return '<div style="color:#4b5563;padding:20px 0;text-align:center">'+(msg||'none found')+'</div>';}
function makeRow(name,text,color,extra){var el=document.createElement('div');el.style.cssText='padding:4px 0;border-bottom:1px solid #1f2937;word-break:break-all;cursor:pointer;display:flex;gap:6px;align-items:flex-start;';if(extra){var b=document.createElement('span');b.style.cssText='flex-shrink:0;font-size:9px;padding:1px 5px;border-radius:3px;background:#1f2937;color:'+(C[extra]||'#9ca3af')+';margin-top:1px;';b.textContent=extra;el.appendChild(b);}var tx=document.createElement('span');tx.style.color=color||'#d1d5db';tx.textContent=text;el.appendChild(tx);el.title='click to copy';el.onclick=function(){var val=document.getElementById('_x_fu').checked&&name==='paths'?base+text:text;copyText(val);flash(el);};return el;}
function twoLineRow(top,topColor,bottom,onCopy){var el=document.createElement('div');el.style.cssText='padding:5px 0;border-bottom:1px solid #1f2937;cursor:pointer;';var a=document.createElement('div');a.style.cssText='color:'+topColor+';word-break:break-all;';a.textContent=top;var bt=document.createElement('div');bt.style.cssText='color:#6b7280;font-size:10px;margin-top:2px;word-break:break-all;';bt.textContent=bottom;el.appendChild(a);el.appendChild(bt);el.onclick=function(){copyText(onCopy);flash(el);};return el;}
function sinkRow(x){var el=document.createElement('div');el.style.cssText='padding:5px 0;border-bottom:1px solid #1f2937;cursor:pointer;';var head=document.createElement('div');head.style.cssText='display:flex;gap:6px;align-items:center;';var sev=document.createElement('span');sev.style.cssText='font-size:9px;font-weight:bold;padding:1px 5px;border-radius:3px;background:#1f2937;color:'+(SEV[x.sev]||'#94a3b8')+';flex-shrink:0;';sev.textContent=x.sev+(x.tainted?'*':'');var sk=document.createElement('span');sk.style.cssText='color:'+C.domxss+';font-weight:bold;';sk.textContent=x.sink;head.appendChild(sev);head.appendChild(sk);var snip=document.createElement('div');snip.style.cssText='color:#9ca3af;font-size:10px;margin-top:3px;word-break:break-all;';snip.textContent=x.snippet;var srcl=document.createElement('div');srcl.style.cssText='color:#4b5563;font-size:9px;margin-top:1px;word-break:break-all;';srcl.textContent=(x.tainted?'⚠ taint source nearby · ':'')+x.src;el.appendChild(head);el.appendChild(snip);el.appendChild(srcl);el.onclick=function(){copyText(x.sink+' | '+x.snippet+' | '+x.src);flash(el);};return el;}
function renderTab(name){
  content.innerHTML='';
  if(name==='paths'){var pl=pathList();if(!pl.length){content.innerHTML=empty();return;}pl.forEach(function(e){content.appendChild(makeRow(name,e[0],INT.test(e[0])?C.interesting:C.paths,e[1]));});}
  else if(name==='params'){if(!D.params.size){content.innerHTML=empty();return;}Array.from(D.params.keys()).sort().forEach(function(k){content.appendChild(makeRow(name,k,C.params,Array.from(D.params.get(k)).join('/')));});}
  else if(name==='urls'){if(!D.urls.size){content.innerHTML=empty();return;}D.urls.forEach(function(u){var ext=false;try{ext=new URL(u).origin!==base;}catch(e){}content.appendChild(makeRow(name,u,ext?C.urls:'#7dd3fc',ext?'ext':null));});}
  else if(name==='network'){if(!D.network.length){content.innerHTML=empty('no live requests yet — interact with the page');return;}D.network.slice().reverse().forEach(function(n){content.appendChild(twoLineRow(n.url,KIND[n.kind]||'#d1d5db',n.method+(n.status?' '+n.status:'')+'  ·  '+n.kind,n.url));});}
  else if(name==='domxss'){if(!D.domxss.length){content.innerHTML=empty('no sinks found');return;}var order={HIGH:0,high:1,med:2,low:3};D.domxss.slice().sort(function(a,b){return (order[a.sev]-order[b.sev])||(b.tainted-a.tainted);}).forEach(function(x){content.appendChild(sinkRow(x));});}
  else if(name==='secrets'){if(!D.secrets.size&&!D.emails.size&&!D.ips.size){content.innerHTML=empty();return;}D.secrets.forEach(function(label,val){if(label==='jwt'){var dec=decodeJWT(val);var info='jwt';if(dec){var exp=dec.pl.exp?(' exp '+new Date(dec.pl.exp*1000).toISOString().substring(0,10)+(dec.pl.exp*1000<Date.now()?' EXPIRED':' valid')):'';info='jwt '+(dec.h.alg||'?')+exp;}content.appendChild(twoLineRow(val,C.secrets,info+(dec?'  ·  '+JSON.stringify(dec.pl).substring(0,90):''),val));}else{content.appendChild(makeRow(name,val,C.secrets,label==='kw'?null:label));}});D.emails.forEach(function(e){content.appendChild(makeRow(name,e,C.emails,'email'));});D.ips.forEach(function(i){content.appendChild(makeRow(name,i,C.ips,'ip'));});}
  else if(name==='forms'){if(!D.forms.length){content.innerHTML=empty();return;}D.forms.forEach(function(f){var names=f.inputs.map(function(i){return i.name||'('+i.type+')';}).join(', ');content.appendChild(twoLineRow('['+f.method+'] '+f.action,C.forms,names||'(no named inputs)',f.action));});}
  else if(name==='storage'){if(!D.storage.length){content.innerHTML=empty();return;}D.storage.forEach(function(s){var el=document.createElement('div');el.style.cssText='padding:5px 0;border-bottom:1px solid #1f2937;cursor:pointer;';var row=document.createElement('div');row.style.display='flex';row.style.gap='6px';var badge=document.createElement('span');badge.style.cssText='font-size:9px;padding:1px 5px;border-radius:3px;background:#1f2937;color:'+storeColor(s.store)+';flex-shrink:0;word-break:break-all;';badge.textContent=s.store;var key=document.createElement('span');key.style.cssText='color:#a3e635;word-break:break-all;';key.textContent=s.key;row.appendChild(badge);row.appendChild(key);var val=document.createElement('div');val.style.cssText='color:#9ca3af;word-break:break-all;margin-top:2px;padding-left:4px;';val.textContent=(s.value==null?'':String(s.value)).substring(0,200);el.appendChild(row);el.appendChild(val);el.onclick=function(){copyText(s.value);flash(el);};content.appendChild(el);});}
  else if(name==='cookies'){if(!D.cookies.length){content.innerHTML=empty('none readable (may be HttpOnly)');return;}D.cookies.forEach(function(c){var el=document.createElement('div');el.style.cssText='padding:5px 0;border-bottom:1px solid #1f2937;cursor:pointer;';var n=document.createElement('span');n.style.color='#c084fc';n.textContent=c.name;var sep=document.createElement('span');sep.style.color='#4b5563';sep.textContent=' = ';var v=document.createElement('span');v.style.cssText='color:#9ca3af;word-break:break-all;';v.textContent=c.value.substring(0,150);el.appendChild(n);el.appendChild(sep);el.appendChild(v);el.onclick=function(){copyText(c.name+'='+c.value);flash(el);};content.appendChild(el);});}
  else if(name==='graphql'){if(!D.graphql.size){content.innerHTML=empty();return;}D.graphql.forEach(function(g){content.appendChild(makeRow(name,g,C.graphql));});}
  else if(name==='maps'){if(!D.sourcemaps.size){content.innerHTML=empty();return;}D.sourcemaps.forEach(function(s){content.appendChild(twoLineRow(s.ref,'#fb923c','from: '+s.js.substring(0,80),s.ref));});}
  else if(name==='comments'){if(!D.comments.size){content.innerHTML=empty();return;}D.comments.forEach(function(c){content.appendChild(makeRow(name,c,C.comments));});}
  else if(name==='jsfiles'){if(!D.jsfiles.size){content.innerHTML=empty();return;}D.jsfiles.forEach(function(f){content.appendChild(makeRow(name,f,C.jsfiles));});}
  else if(name==='tech'){var T=fingerprint();if(!T.length){content.innerHTML=empty();return;}T.forEach(function(t){content.appendChild(makeRow(name,t,C.tech));});}
  applyFilter();
}
function applyFilter(){var q=(document.getElementById('_x_search').value||'').toLowerCase();Array.from(content.children).forEach(function(el){el.style.display=el.textContent.toLowerCase().indexOf(q)>-1?'':'none';});}
function switchTab(name){activeTab=name;TABS.forEach(function(n){tabEls[n].style.color=n===name?'#10b981':'#6b7280';tabEls[n].style.borderBottom=n===name?'2px solid #10b981':'2px solid transparent';});var po=name==='paths';document.getElementById('_x_fu_l').style.display=po?'flex':'none';document.getElementById('_x_as_l').style.display=po?'flex':'none';renderTab(name);}
function updateCounts(){var counts={paths:pathList().length,params:D.params.size,urls:D.urls.size,network:D.network.length,domxss:D.domxss.length,secrets:D.secrets.size+D.emails.size+D.ips.size,forms:D.forms.length,storage:D.storage.length,cookies:D.cookies.length,graphql:D.graphql.size,maps:D.sourcemaps.size,comments:D.comments.size,jsfiles:D.jsfiles.size,tech:fingerprint().length};TABS.forEach(function(n){tabEls[n].textContent=n+'('+counts[n]+')';});var hi=D.domxss.filter(function(x){return x.sev==='HIGH';}).length;statusBar.textContent='total: '+Object.values(counts).reduce(function(a,b){return a+b;},0)+(hi?' | '+hi+' tainted sinks':'')+' | live ON | '+base;renderTab(activeTab);}
document.getElementById('_x_search').oninput=applyFilter;
document.getElementById('_x_assets').onchange=function(){renderTab(activeTab);updateCounts();};
document.getElementById('_x_ca').onclick=function(){var useBase=document.getElementById('_x_fu').checked;var lines=[];
  if(activeTab==='paths') pathList().forEach(function(e){lines.push((useBase?base:'')+e[0]);});
  else if(activeTab==='params') Array.from(D.params.keys()).sort().forEach(function(k){lines.push(k);});
  else if(activeTab==='urls') D.urls.forEach(function(u){lines.push(u);});
  else if(activeTab==='network') D.network.forEach(function(n){lines.push(n.method+' '+(n.status||'')+' '+n.url);});
  else if(activeTab==='domxss') D.domxss.forEach(function(x){lines.push('['+x.sev+(x.tainted?'*':'')+'] '+x.sink+' :: '+x.snippet+' ('+x.src+')');});
  else if(activeTab==='secrets'){D.secrets.forEach(function(l,s){lines.push(s);});D.emails.forEach(function(e){lines.push(e);});D.ips.forEach(function(i){lines.push(i);});}
  else if(activeTab==='forms') D.forms.forEach(function(f){lines.push('['+f.method+'] '+f.action+' :: '+f.inputs.map(function(i){return i.name;}).join(','));});
  else if(activeTab==='storage') D.storage.forEach(function(s){lines.push('['+s.store+'] '+s.key+' = '+s.value);});
  else if(activeTab==='cookies') D.cookies.forEach(function(c){lines.push(c.name+'='+c.value);});
  else if(activeTab==='graphql') D.graphql.forEach(function(g){lines.push(g);});
  else if(activeTab==='maps') D.sourcemaps.forEach(function(s){lines.push(s.ref+' (from '+s.js+')');});
  else if(activeTab==='comments') D.comments.forEach(function(c){lines.push(c);});
  else if(activeTab==='jsfiles') D.jsfiles.forEach(function(f){lines.push(f);});
  else if(activeTab==='tech') fingerprint().forEach(function(t){lines.push(t);});
  copyText(lines.join('\n'));var b=document.getElementById('_x_ca');b.textContent='copied '+lines.length+'!';setTimeout(function(){b.textContent='copy all';},1400);};
function exportJSON(){var out={url:location.href,timestamp:new Date().toISOString(),paths:Array.from(D.paths.entries()).map(function(e){return{path:e[0],method:e[1]};}),params:Array.from(D.params.keys()),urls:Array.from(D.urls),network:D.network,domxss:D.domxss,secrets:Array.from(D.secrets.entries()).map(function(e){return{value:e[0],type:e[1]};}),emails:Array.from(D.emails),ips:Array.from(D.ips),forms:D.forms,graphql:Array.from(D.graphql),sourcemaps:Array.from(D.sourcemaps),comments:Array.from(D.comments),jsfiles:Array.from(D.jsfiles),storage:D.storage,cookies:D.cookies,tech:fingerprint()};copyText(JSON.stringify(out,null,2));var b=document.getElementById('_x_ej');b.textContent='copied!';setTimeout(function(){b.textContent='JSON';},1500);}
function exportMD(){var lines=['# JS Recon Report','**URL:** '+location.href,'**Date:** '+new Date().toISOString(),''];
  lines.push('## Tech');fingerprint().forEach(function(t){lines.push('- '+t);});
  lines.push('## DOM-XSS Sinks');D.domxss.forEach(function(x){lines.push('- ['+x.sev+(x.tainted?'*':'')+'] '+x.sink+' — `'+x.snippet+'` ('+x.src+')');});
  lines.push('## Paths ('+D.paths.size+')');D.paths.forEach(function(m,p){lines.push('- ['+m+'] '+p);});
  lines.push('## Params');Array.from(D.params.keys()).sort().forEach(function(k){lines.push('- '+k);});
  lines.push('## URLs');D.urls.forEach(function(u){lines.push('- '+u);});
  lines.push('## Network');D.network.forEach(function(n){lines.push('- '+n.method+' '+(n.status||'')+' '+n.url);});
  lines.push('## Secrets');D.secrets.forEach(function(l,s){lines.push('- '+(l==='kw'?'':'['+l+'] ')+s);});
  lines.push('## Emails');D.emails.forEach(function(e){lines.push('- '+e);});
  lines.push('## IPs');D.ips.forEach(function(i){lines.push('- '+i);});
  lines.push('## Forms');D.forms.forEach(function(f){lines.push('- ['+f.method+'] '+f.action+' :: '+f.inputs.map(function(i){return i.name;}).join(','));});
  lines.push('## GraphQL');D.graphql.forEach(function(g){lines.push('- '+g);});
  lines.push('## Source Maps');D.sourcemaps.forEach(function(s){lines.push('- '+s.ref+' from '+s.js);});
  lines.push('## Storage');D.storage.forEach(function(s){lines.push('- ['+s.store+'] '+s.key+' = '+(s.value==null?'':String(s.value)).substring(0,100));});
  lines.push('## Cookies');D.cookies.forEach(function(c){lines.push('- '+c.name+' = '+c.value.substring(0,80));});
  lines.push('## Comments');D.comments.forEach(function(c){lines.push('- '+c.replace(/\n/g,' ').substring(0,120));});
  lines.push('## JS Files');D.jsfiles.forEach(function(f){lines.push('- '+f);});
  copyText(lines.join('\n'));var b=document.getElementById('_x_em');b.textContent='copied!';setTimeout(function(){b.textContent='MD';},1500);}
document.getElementById('_x_ej').onclick=exportJSON;document.getElementById('_x_em').onclick=exportMD;
switchTab('paths');
Promise.all(fetches).then(function(){updateCounts();statusBar.textContent='passive done — live hooks ON | '+base;});
setTimeout(updateCounts,1000);setTimeout(updateCounts,3500);
})();