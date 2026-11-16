#!/usr/bin/env python3
"""Actividad 4: API educativa solo en loopback, no apta para produccion."""
import base64, collections, hashlib, hmac, json, re, secrets, sqlite3, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse, urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError
KEY = secrets.token_bytes(32)
CLIENT_SECRET = secrets.token_urlsafe(32)
ISSUER = 'actividad4-local'
AUDIENCE = 'api-laboratorio'
WINDOW = collections.defaultdict(collections.deque)
LOCK = threading.Lock()
def b64(x): return base64.urlsafe_b64encode(x).rstrip(b'=').decode()
def unb64(x): return base64.urlsafe_b64decode(x + '=' * (-len(x) % 4))
def issue(**overrides):
    claims = dict(iss=ISSUER, aud=AUDIENCE, sub='alumno', scope='read:records', exp=int(time.time())+300)
    claims.update(overrides)
    text = b64(json.dumps(dict(alg='HS256',typ='JWT')).encode())+'.'+b64(json.dumps(claims).encode())
    return text+'.'+b64(hmac.new(KEY,text.encode(),hashlib.sha256).digest())
def verify(token):
    a,b,c=token.split('.')
    header=json.loads(unb64(a))
    if header != dict(alg='HS256',typ='JWT'): raise ValueError('algorithm')
    if not hmac.compare_digest(hmac.new(KEY,(a+'.'+b).encode(),hashlib.sha256).digest(),unb64(c)): raise ValueError('signature')
    p=json.loads(unb64(b))
    if p['iss']!=ISSUER or p['aud']!=AUDIENCE or p['exp']<=time.time(): raise ValueError('claims')
    return p
class API(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def reply(self,status,data,extra=None):
        body=json.dumps(data).encode(); self.send_response(status)
        self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(body)))
        self.send_header('Cache-Control','no-store'); self.send_header('X-Content-Type-Options','nosniff')
        for k,v in (extra or {}).items(): self.send_header(k,v)
        self.end_headers(); self.wfile.write(body)
    def do_POST(self):
        if self.path!='/oauth/token': return self.reply(404,dict(error='not_found'))
        if int(self.headers.get('Content-Length','0'))>2048: return self.reply(413,dict(error='too_large'))
        data=parse_qs(self.rfile.read(int(self.headers.get('Content-Length','0'))).decode())
        auth=self.headers.get('Authorization','')
        expected='Basic '+base64.b64encode(('alumno:'+CLIENT_SECRET).encode()).decode()
        if not hmac.compare_digest(auth,expected): return self.reply(401,dict(error='invalid_client'))
        if data.get('grant_type')!=['client_credentials']: return self.reply(400,dict(error='unsupported_grant_type'))
        scope=data.get('scope',['read:records'])[0]
        if scope!='read:records': return self.reply(400,dict(error='invalid_scope'))
        return self.reply(200,dict(access_token=issue(),token_type='Bearer',expires_in=300,scope=scope))
    def do_GET(self):
        path=urlparse(self.path)
        if path.path=='/health': return self.reply(200,dict(status='ok',environment='local_academic'))
        if path.path not in ['/api/records','/api/admin']: return self.reply(404,dict(error='not_found'))
        try:
            auth=self.headers.get('Authorization','')
            if not auth.startswith('Bearer '): raise ValueError('missing')
            claims=verify(auth[7:])
        except Exception: return self.reply(401,dict(error='invalid_token'),{'WWW-Authenticate':'Bearer'})
        required='admin' if path.path=='/api/admin' else 'read:records'
        if required not in claims.get('scope','').split(): return self.reply(403,dict(error='insufficient_scope'))
        with LOCK:
            now=time.monotonic(); q=WINDOW[claims['sub']]
            while q and q[0]<=now-60: q.popleft()
            if len(q)>=100: return self.reply(429,dict(error='rate_limit'),{'Retry-After':str(max(1,int(60-(now-q[0]))+1))})
            q.append(now)
        ids=parse_qs(path.query).get('id',['1'])
        if len(ids)!=1 or not re.fullmatch('[1-9][0-9]{0,5}',ids[0]): return self.reply(400,dict(error='invalid_id'))
        db=sqlite3.connect(':memory:'); db.execute('CREATE TABLE records(id INTEGER, owner TEXT, value TEXT)')
        db.executemany('INSERT INTO records VALUES(?,?,?)',[(1,'alumno','registro propio'),(2,'otro','registro privado')])
        row=db.execute('SELECT id,value FROM records WHERE id=? AND owner=?',(int(ids[0]),claims['sub'])).fetchone(); db.close()
        if row is None: return self.reply(404,dict(error='not_found'))
        return self.reply(200,dict(id=row[0],value=row[1]))
def call(path,token=None,data=None,headers=None):
    h=headers or {}
    if token: h['Authorization']='Bearer '+token
    req=Request('http://127.0.0.1:8765'+path,data=data,headers=h)
    try:
        with urlopen(req,timeout=4) as r: return r.status,dict(r.headers),json.load(r)
    except HTTPError as e: return e.code,dict(e.headers),json.load(e)
def check(label,got,expected):
    print(('PASS' if got==expected else 'FAIL')+' | '+label+' | obtenido='+str(got)+' esperado='+str(expected),flush=True)
    assert got==expected
if __name__=='__main__':
    server=ThreadingHTTPServer(('127.0.0.1',8765),API)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    print('ACTIVIDAD 4 - API LOCAL - OAuth 2.0 client_credentials + JWT HS256',flush=True)
    print('Servidor: 127.0.0.1:8765 | sin exposicion a otras interfaces',flush=True)
    check('sin token',call('/api/records')[0],401)
    check('cliente OAuth invalido',call('/oauth/token',data=b'grant_type=client_credentials')[0],401)
    basic='Basic '+base64.b64encode(('alumno:'+CLIENT_SECRET).encode()).decode()
    status,_,body=call('/oauth/token',data=b'grant_type=client_credentials&scope=read%3Arecords',headers={'Authorization':basic,'Content-Type':'application/x-www-form-urlencoded'})
    check('emision OAuth',status,200); token=body['access_token']
    check('JWT valido',call('/api/records?id=1',token)[0],200)
    check('JWT expirado',call('/api/records',issue(exp=1))[0],401)
    check('audiencia incorrecta',call('/api/records',issue(aud='otra-api'))[0],401)
    check('emisor incorrecto',call('/api/records',issue(iss='otro'))[0],401)
    a,b,c=token.split('.'); fake=a+'.'+b+'.'+b64(b'x'*32)
    check('firma alterada',call('/api/records',fake)[0],401)
    fake=b64(b'{"alg":"none","typ":"JWT"}')+'.'+b+'.'
    check('alg none rechazado',call('/api/records',fake)[0],401)
    check('scope insuficiente admin',call('/api/admin',token)[0],403)
    check('IDOR registro ajeno',call('/api/records?id=2',token)[0],404)
    payload=urlencode({'id':"1 OR 1=1"})
    check('inyeccion SQL bloqueada',call('/api/records?'+payload,token)[0],400)
    check('XSS bloqueado en id',call('/api/records?'+urlencode({'id':'<script>alert(1)</script>'}),token)[0],400)
    with LOCK: WINDOW.clear()
    codes=[call('/api/records?id=1',token)[0] for _ in range(101)]
    check('primeras 100 peticiones',codes[:100],[200]*100)
    status,headers,_=call('/api/records?id=1',token)
    check('peticion 101',codes[100],429); check('limite persistente',status,429)
    check('Retry-After presente','Retry-After' in headers,True)
    print('RESUMEN: autenticacion, autorizacion, validacion y limite comprobados.',flush=True)
    print('Demo educativa: HTTP loopback, estado en memoria; produccion exige TLS, IdP y librerias auditadas.',flush=True)
    print('Servidor activo. Ctrl+C termina el laboratorio.',flush=True)
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt: server.shutdown()
