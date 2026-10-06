"""Local, behavioral conformance through the public-method stdin adapter."""
import hashlib, base64, json, subprocess, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
COMMAND = ["elixir","-pa","_build/dev/lib/anyoauth_sdk/ebin","-pa","_build/dev/lib/jason/ebin","tests/conformance.exs"]
seen = []
mode = 'normal'
override = None
token = 'aop_' + 'a'*43
profile = dict(subject='google:1', provider='google', providerSubject='1', name=None, username=None, email=None, emailVerified=False, avatarUrl=None)
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self): self.respond()
    def do_POST(self): self.respond()
    def respond(self):
        body = self.rfile.read(int(self.headers.get('Content-Length',0)))
        seen.append((self.command,self.path,{k.lower():v for k,v in self.headers.items()},body))
        if mode == 'slow':
            time.sleep(11)
            try:
                self.send_response(200); self.end_headers(); self.wfile.write(b'[]')
            except (BrokenPipeError, ConnectionResetError): pass
            return
        if mode == 'redirect':
            self.send_response(302); self.send_header('Location','/trap'); self.end_headers(); return
        if mode == 'error':
            self.send_response(401); self.end_headers(); self.wfile.write(b'{"error":"invalid_token"}'); return
        if mode == 'html':
            self.send_response(503); self.end_headers(); self.wfile.write(b'<html>upstream</html>'); return
        if self.path == '/v1/revoke':
            self.send_response(204); self.end_headers(); return
        data = {'access_token':token,'token_type':'Bearer','expires_in':900,'scope':'profile'} if self.path == '/v1/token' else profile if self.path == '/v1/profile' else [{'id':'google','configured':True,'enabled':True,'available':True}]
        if mode == 'wrong': data = {'unexpected':'value'}
        if mode == 'nullwrong': data = {**profile,'emailVerified':None}
        if mode == 'enumwrong': data = {**profile,'provider':'unsupported'}
        if mode == 'numberwrong': data = {'access_token':token,'token_type':'Bearer','expires_in':900.5,'scope':'profile'}
        if override is not None: data = override
        if mode == 'additive' and isinstance(data,dict): data = {**data,'future':{'ok':True}}
        self.send_response(200); self.send_header('Content-Type','application/json'); self.end_headers()
        self.wfile.write(b'not-json' if mode == 'invalidjson' else json.dumps(data).encode())
server = ThreadingHTTPServer(('127.0.0.1',0),Handler)
threading.Thread(target=server.serve_forever,daemon=True).start()
origin = 'http://127.0.0.1:'+str(server.server_port)
def run(action, params=None, **extra):
    payload = dict(action=action,baseUrl=origin,clientId='dummy-id',clientSecret='dummy-secret',params=params or {})
    payload.update(extra)
    p = subprocess.run(COMMAND,input=json.dumps(payload),text=True,capture_output=True,cwd=ROOT,timeout=30)
    assert p.returncode == 0, p.stderr
    assert not p.stderr, p.stderr
    return json.loads(p.stdout)
def success(action, params=None, **extra):
    r = run(action,params,**extra); assert r['ok'],r; return r['result']
def failure(action, params=None, code=None, status=None, **extra):
    r = run(action,params,**extra); assert not r['ok'],r
    assert set(r['error']) == {'status','code','message'},r
    if code: assert r['error']['code'] == code,r
    if status is not None: assert r['error']['status'] == status,r
    assert 'dummy-secret' not in json.dumps(r),r
verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
challenge = success('pkceChallenge',{'codeVerifier':verifier})
assert challenge == 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
failure('pkceChallenge',{'codeVerifier':'short'})
tx = success('createTransaction'); tx2 = success('createTransaction')
assert tx['state'] != tx2['state'] and tx['codeVerifier'] != tx2['codeVerifier']
assert len(tx['state']) == 43 and tx['expiresAt']-tx['createdAt'] == 600
assert tx['codeChallenge'] == base64.urlsafe_b64encode(hashlib.sha256(tx['codeVerifier'].encode()).digest()).decode().rstrip('=')
redirect = 'https://example.test/callback'
params = dict(provider='google',redirectUri=redirect,state='s &+%?'*4,codeChallenge=challenge)
from urllib.parse import urlsplit, parse_qs, urlencode
url = success('authorizationUrl',params)
q = parse_qs(urlsplit(url).query)
assert q['state'] == [params['state']] and q['redirect_uri'] == [redirect] and q['client_id'] == ['dummy-id'] and q['response_type'] == ['code'] and q['code_challenge_method'] == ['S256']
assert 'dummy-secret' not in url
for change in [dict(provider='other'),dict(state='short'),dict(codeChallenge='bad'),dict(redirectUri='http://example.test/cb'),dict(redirectUri=redirect+'?x=1'),dict(redirectUri='https://u:p@example.test/cb')]:
    failure('authorizationUrl',{**params,**change})
cb = dict(redirectUri=redirect,state=tx['state'],expiresAt=int(time.time())+60)
for key in ['code','error']:
    value = 'ok +&'
    assert success('validateCallback',{**cb,'callbackUrl':redirect+'?'+urlencode({'state':tx['state'],key:value})}) == {key:value,'state':tx['state']}
for tail in ['state=x&code=a', 'state='+tx['state']+'&code=a&code=b', 'state='+tx['state']+'&code=a&error=b', 'state='+tx['state']+'&code=', 'state='+tx['state'], 'state='+tx['state']+'&state='+tx['state']+'&code=a','state='+tx['state']+'&error=a&error=b','state='+tx['state']+'&code=%XX']:
    failure('validateCallback',{**cb,'callbackUrl':redirect+'?'+tail})
validcb = redirect+'?'+urlencode({'state':tx['state'],'code':'a'})
failure('validateCallback',{**cb,'callbackUrl':validcb,'expiresAt':0})
failure('validateCallback',{**cb,'callbackUrl':validcb.replace('/callback','/other')})
failure('validateCallback',{**cb,'callbackUrl':validcb+'#fragment'})
exchange = dict(code='dummy-code',codeVerifier=verifier,redirectUri=redirect)
assert success('exchangeCode',exchange)['access_token'] == token
method,path,headers,body = seen[-1]
assert method == 'POST' and path == '/v1/token'
assert json.loads(body) == dict(grant_type='authorization_code',client_id='dummy-id',client_secret='dummy-secret',code='dummy-code',redirect_uri=redirect,code_verifier=verifier)
assert headers.get('content-type') == 'application/json' and 'authorization' not in headers
assert success('profile',dict(accessToken=token)) == profile
assert seen[-1][2]['authorization'] == 'Bearer '+token
assert success('revoke',dict(accessToken=token)) is None
assert seen[-1][0] == 'POST' and not seen[-1][3]
assert success('providers')[0]['id'] == 'google'
for mode in ['wrong','invalidjson','nullwrong','enumwrong']:
    failure('profile',dict(accessToken=token),code='protocol_error',status=200)
mode = 'normal'
for override in [{k:v for k,v in profile.items() if k != 'name'}, {**profile,'emailVerified':0}, {**profile,'email':42}, [], None]:
    if override is not None: failure('profile',dict(accessToken=token),code='protocol_error',status=200)
override = None
mode = 'numberwrong'; failure('exchangeCode',exchange,code='protocol_error',status=200)
mode = 'normal'
for override in [{'access_token':'wrong','token_type':'Bearer','expires_in':900,'scope':'profile'}, {'access_token':token,'token_type':'bearer','expires_in':900,'scope':'profile'}, {'access_token':token,'token_type':'Bearer','expires_in':True,'scope':'profile'}, {'access_token':token,'token_type':'Bearer','expires_in':900}, {}]:
    failure('exchangeCode',exchange,code='protocol_error',status=200)
override = [{'id':'unknown','configured':True,'enabled':True,'available':True}]
failure('providers',code='protocol_error',status=200)
override = None
mode = 'additive'; assert success('profile',dict(accessToken=token))['future'] == {'ok':True}
mode = 'error'; failure('profile',dict(accessToken=token),code='invalid_token',status=401)
mode = 'html'; failure('exchangeCode',exchange,code='protocol_error',status=503)
mode = 'redirect'; before=len(seen); failure('exchangeCode',exchange,code='protocol_error',status=302); assert len(seen) == before+1
mode = 'normal'
before = len(seen)
failure('profile',dict(accessToken='bad\r\nInjected: header'))
failure('exchangeCode',{**exchange,'codeVerifier':'short'})
for base in ['http://example.test','https://user:pass@example.test','https://example.test/path','https://example.test?x=1','https://example.test#x','https://example.test\\evil']:
    failure('providers',baseUrl=base)
assert len(seen) == before
mode = 'slow'; before = len(seen); start = time.monotonic()
failure('providers',code='transport_error',status=0)
assert 9 <= time.monotonic()-start <= 15 and len(seen) == before+1
server.shutdown(); server.server_close()
failure('providers',code='transport_error',status=0)
print('PASS: RFC 7636, transactions, authorization/callback validation, JSON exchange, nullable profile, providers, revoke, schema failures/additions, errors, no redirects/retries, URL/header safety, 10-second timeout, network failure')
