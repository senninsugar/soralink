// /oauth-test : OAuth 2.0 動作確認ページ(認可 → トークン交換 → API呼び出し → リフレッシュ → 失効)
// Worker自身が配信するので、リダイレクトURIには「<WorkerのURL>/oauth-test」を登録するだけで試せます。
// 注意: このスクリプトは String.raw テンプレート内なので、バッククォートと ${ } は使わないこと。
export function oauthTestHtml(nonce) {
  return String.raw`<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>OAuth 2.0 テスト — Sennin Account</title>
<style>
:root{--blue:#1a73e8;--bd:#dadce0;--tx:#202124;--sub:#5f6368;--red:#d93025;--green:#137333}
*{box-sizing:border-box}body{margin:0;font-family:Roboto,"Noto Sans JP",-apple-system,"Segoe UI",sans-serif;color:var(--tx);background:#f6f8fc;font-size:14px}
main{max-width:860px;margin:0 auto;padding:20px}h1{font-size:20px;font-weight:500;margin:0 0 4px}h2{font-size:15px;margin:0 0 10px;font-weight:500}
.sub{color:var(--sub);margin:0 0 16px;line-height:1.6}.card{background:#fff;border:1px solid var(--bd);border-radius:8px;padding:16px;margin-bottom:14px}
label.f{display:block;font-size:12px;color:var(--sub);margin:10px 0 4px}input[type=text],input[type=password],input[type=number]{width:100%;font:inherit;padding:9px 10px;border:1px solid var(--bd);border-radius:4px}
input:focus{outline:2px solid var(--blue);border-color:transparent}.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
button{font:inherit;font-weight:500;padding:8px 14px;border-radius:4px;border:1px solid var(--bd);background:#fff;color:var(--blue);cursor:pointer}
button:hover{background:#e8f0fe}button.p{background:var(--blue);color:#fff;border-color:var(--blue)}button.p:hover{background:#1557b0}button.d{color:var(--red)}button:disabled{opacity:.5;cursor:default}
.mono,pre{font-family:monospace;font-size:12px;word-break:break-all;white-space:pre-wrap}pre{background:#f1f3f4;border-radius:6px;padding:10px;margin:6px 0;max-height:320px;overflow:auto}
.chk{display:inline-block;margin-right:14px;font-size:13px}.pill{display:inline-block;padding:2px 9px;border-radius:10px;font-size:11px;font-weight:600;background:#e8eaed;color:var(--sub)}
.pill.ok{background:#e6f4ea;color:var(--green)}.pill.ng{background:#fce8e6;color:var(--red)}details{border:1px solid var(--bd);border-radius:6px;margin:8px 0;background:#fff}
summary{cursor:pointer;padding:8px 10px;font-weight:500}details>div{padding:0 10px 8px}.note{background:#fef7e0;border:1px solid #f9e0a0;border-radius:6px;padding:10px 12px;font-size:12px;line-height:1.6;margin:10px 0}
</style></head><body><main>
<h1>OAuth 2.0 テスト</h1>
<p class="sub">このページで「認可 → トークン交換 → API呼び出し → リフレッシュ → 失効」を一通り確認できます。仕様書: <a href="/llms.txt">/llms.txt</a>(AIに読ませるならこのURLか API.md)</p>

<div class="card"><h2>① アプリ設定</h2>
<div class="note">先にアカウント画面の「開発者設定」(または管理者パネル)でアプリを登録し、<b>リダイレクトURI</b>に下の値を<b>そのまま</b>入れてください:<br><span class="mono" id="redir"></span> <button id="copyRedir" type="button">コピー</button></div>
<label class="f">client_id</label><input type="text" id="cid" autocomplete="off" placeholder="sa_...">
<label class="f">client_secret(このページのブラウザ内だけで使います。テスト専用)</label><input type="password" id="csec" autocomplete="off" placeholder="sas_...">
<label class="f">スコープ(アプリに許可されたものだけ選べます。points:write は管理者承認が必要)</label>
<div id="scopes"></div>
<div style="margin-top:10px"><label class="chk"><input type="checkbox" id="pkce" checked> PKCE (S256) を使う(推奨)</label></div>
<div class="row" style="margin-top:12px"><button class="p" id="start">認可を開始 →</button><button id="reset" class="d">保存した状態を消去</button></div>
<div id="authurl" class="mono" style="margin-top:10px"></div>
</div>

<div class="card"><h2>② トークンの状態</h2><div id="tokstate" class="mono">未取得</div>
<div class="row" style="margin-top:10px"><button id="refresh">リフレッシュ</button><button id="revoke" class="d">アクセストークンを失効</button></div></div>

<div class="card"><h2>③ API を呼ぶ</h2>
<div class="row"><button id="ui">GET /oauth/userinfo</button><button id="pts">GET /api/v1/points</button></div>
<h2 style="margin-top:16px">ポイント加算・減算 (points:write)</h2>
<div class="row"><input type="number" id="amt" step="1" value="10" style="width:120px"><input type="text" id="rsn" value="OAuthテスト" style="flex:1;min-width:160px"><button id="adj">POST /api/v1/points/adjust</button></div>
<div class="mono" style="color:var(--sub);margin-top:6px">idempotency_key は押すたびに自動生成します。<label class="chk"><input type="checkbox" id="samekey"> 直前と同じキーで再送(二重加算されないことの確認)</label></div></div>

<div class="card"><h2>④ ログ(リクエストとレスポンス)</h2><div class="row"><button id="clearlog">ログを消す</button></div><div id="log"></div></div>
</main>
<script nonce="${nonce}">
(function(){
'use strict';
var B=location.origin, REDIR=B+'/oauth-test', K='sa_oauth_test', ALL=['profile','email','points:read','points:write'];
function $(i){return document.getElementById(i);}
function load(){try{return JSON.parse(sessionStorage.getItem(K)||'{}');}catch(e){return {};}}
function save(o){var c=load();Object.keys(o).forEach(function(k){c[k]=o[k];});try{sessionStorage.setItem(K,JSON.stringify(c));}catch(e){}}
function b64u(buf){var s='',a=new Uint8Array(buf);for(var i=0;i<a.length;i++)s+=String.fromCharCode(a[i]);return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
function rnd(n){var a=new Uint8Array(n);crypto.getRandomValues(a);return b64u(a);}
function sha256(s){return crypto.subtle.digest('SHA-256',new TextEncoder().encode(s)).then(b64u);}
function el(tag,props){var e=document.createElement(tag);for(var k in (props||{}))e.setAttribute(k,props[k]);for(var i=2;i<arguments.length;i++){var c=arguments[i];if(c!=null)e.append(c.nodeType?c:document.createTextNode(String(c)));}return e;}
function mask(s){return String(s).replace(/(sas_|sat_|srt_|sac_)[A-Za-z0-9_-]{6,}/g,function(m){return m.slice(0,8)+'…('+m.length+')';});}

function log(title,status,obj){
  var ok=typeof status==='number'?(status>=200&&status<400):true;
  var body=typeof obj==='string'?obj:JSON.stringify(obj,null,2);
  var d=el('details',{open:''},el('summary',{},title+' ',el('span',{'class':'pill '+(ok?'ok':'ng')},String(status))),el('div',{},el('pre',{},body)));
  $('log').insertBefore(d,$('log').firstChild);}

function showScopes(sel){var box=$('scopes');box.textContent='';
  ALL.forEach(function(s){var c=el('input',{type:'checkbox',value:s});if(sel.indexOf(s)>=0)c.checked=true;box.append(el('label',{'class':'chk'},c,s));});}
function picked(){return Array.prototype.map.call($('scopes').querySelectorAll('input:checked'),function(c){return c.value;});}

function tokState(){
  var t=load().tok;
  if(!t){$('tokstate').textContent='未取得';return;}
  var left=Math.round((t.expiresAt-Date.now())/1000);
  $('tokstate').textContent='access_token : '+mask(t.access_token)+'\nrefresh_token: '+mask(t.refresh_token)+'\nscope        : '+t.scope+'\n有効期限     : '+(left>0?'あと '+left+' 秒':'期限切れ(リフレッシュしてください)');}
setInterval(tokState,1000);

/* ---------- フロー ---------- */
$('start').addEventListener('click',function(){
  var cid=$('cid').value.trim(),sc=picked();
  if(!cid){alert('client_id を入力してください');return;}
  if(!sc.length){alert('スコープを1つ以上選んでください');return;}
  var state=rnd(16),verifier=rnd(48),usePkce=$('pkce').checked;
  (usePkce?sha256(verifier):Promise.resolve(null)).then(function(ch){
    var p={response_type:'code',client_id:cid,redirect_uri:REDIR,scope:sc.join(' '),state:state};
    if(ch){p.code_challenge=ch;p.code_challenge_method='S256';}
    save({cid:cid,csec:$('csec').value,scopes:sc,pkce:usePkce,state:state,verifier:verifier});
    var url=B+'/oauth/authorize?'+new URLSearchParams(p).toString();
    $('authurl').textContent=url;
    location.href=url;});});

function exchange(code){
  var s=load();
  var body={grant_type:'authorization_code',code:code,redirect_uri:REDIR,client_id:s.cid,client_secret:s.csec};
  if(s.pkce)body.code_verifier=s.verifier;
  post('POST /oauth/token (authorization_code)','/oauth/token',body).then(function(r){
    if(r.status===200&&r.data.access_token)storeTok(r.data);});}
function storeTok(d){save({tok:{access_token:d.access_token,refresh_token:d.refresh_token,scope:d.scope,expiresAt:Date.now()+d.expires_in*1000}});tokState();}

function post(title,path,form){
  var shown=Object.assign({},form);if(shown.client_secret)shown.client_secret='(hidden)';
  return fetch(B+path,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams(form).toString()})
    .then(function(r){return r.text().then(function(t){var d;try{d=JSON.parse(t);}catch(e){d=t;}log(title+'\n→ '+JSON.stringify(shown),r.status,mask(typeof d==='string'?d:JSON.stringify(d,null,2)));return {status:r.status,data:d};});})
    .catch(function(e){log(title,'通信エラー',String(e));return {status:0,data:{}};});}

function api(title,method,path,json){
  var t=load().tok;if(!t){alert('先にトークンを取得してください');return Promise.resolve();}
  var o={method:method,headers:{'Authorization':'Bearer '+t.access_token}};
  if(json){o.headers['Content-Type']='application/json';o.body=JSON.stringify(json);}
  return fetch(B+path,o).then(function(r){return r.text().then(function(x){var d;try{d=JSON.parse(x);}catch(e){d=x;}
    log(title+(json?'\n→ '+JSON.stringify(json):''),r.status,typeof d==='string'?d:d);return d;});})
    .catch(function(e){log(title,'通信エラー',String(e));});}

$('ui').addEventListener('click',function(){api('GET /oauth/userinfo','GET','/oauth/userinfo');});
$('pts').addEventListener('click',function(){api('GET /api/v1/points','GET','/api/v1/points');});
var lastKey='';
$('adj').addEventListener('click',function(){
  var a=parseInt($('amt').value,10);if(!a){alert('amount は0以外の整数');return;}
  if(!($('samekey').checked&&lastKey))lastKey='test-'+Date.now()+'-'+rnd(6);
  api('POST /api/v1/points/adjust','POST','/api/v1/points/adjust',{amount:a,reason:$('rsn').value,idempotency_key:lastKey});});
$('refresh').addEventListener('click',function(){
  var s=load();if(!s.tok){alert('トークンがありません');return;}
  post('POST /oauth/token (refresh_token)','/oauth/token',{grant_type:'refresh_token',refresh_token:s.tok.refresh_token,client_id:s.cid,client_secret:s.csec})
    .then(function(r){if(r.status===200&&r.data.access_token)storeTok(r.data);});});
$('revoke').addEventListener('click',function(){
  var s=load();if(!s.tok){alert('トークンがありません');return;}
  post('POST /oauth/revoke','/oauth/revoke',{token:s.tok.access_token,client_id:s.cid,client_secret:s.csec});});
$('reset').addEventListener('click',function(){try{sessionStorage.removeItem(K);}catch(e){}location.href=REDIR;});
$('clearlog').addEventListener('click',function(){$('log').textContent='';});
$('copyRedir').addEventListener('click',function(){try{navigator.clipboard.writeText(REDIR);}catch(e){}});

/* ---------- 初期化 / コールバック処理 ---------- */
var s0=load();
$('redir').textContent=REDIR;$('cid').value=s0.cid||'';$('csec').value=s0.csec||'';$('pkce').checked=s0.pkce!==false;
showScopes(s0.scopes||['profile','email']);tokState();
var q=new URLSearchParams(location.search);
if(q.has('code')||q.has('error')){
  history.replaceState(null,'',REDIR);
  var cb={};q.forEach(function(v,k){cb[k]=v;});
  var stateOk=cb.state&&cb.state===s0.state;
  log('認可サーバーからのコールバック',q.has('error')?'エラー':'成功',mask(JSON.stringify(cb,null,2))+'\nstate 検証: '+(stateOk?'OK(一致)':'NG(不一致!処理を中止)')+'\niss: '+(cb.iss===B?'OK':String(cb.iss)));
  if(q.has('code')&&stateOk)exchange(cb.code);
}
})();
</script></body></html>`;
}
