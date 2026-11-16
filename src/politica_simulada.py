"""Simulacion logica; no configura pfSense ni intercepta trafico."""
def firewall(role,target,port):
 return 'ALLOW' if role=='admin' and target=='interna' and port==443 else 'DENY'
def dns(domain):
 return 'BLOCK' if domain.lower().rstrip('.') in {'phishing.invalid','login-falso.invalid'} else 'FORWARD'
print('ACTIVIDAD 4 - SIMULACION DE POLITICA PERIMETRAL')
print('Sin modificacion de firewall real; dominio .invalid de laboratorio')
for role,expected in [('no_autorizado','DENY'),('admin','ALLOW')]:
 result=firewall(role,'interna',443);assert result==expected
 print('PASS',role,'-> interna:443',result)
for domain,expected in [('phishing.invalid','BLOCK'),('sitio-legitimo.invalid','FORWARD')]:
 result=dns(domain);assert result==expected;print('PASS DNS',domain,result)
print('Pendiente: aplicar y verificar estas politicas en pfSense compatible.')
