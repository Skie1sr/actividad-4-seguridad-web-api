# Guía del laboratorio local

## 1. Preparar dependencias

Se utilizó Kali ARM64 con Java, PHP con mysqli, MariaDB, Python, Nmap y dumpcap disponibles. La práctica requiere permisos para capturar en loopback. Comprobar primero:

```bash
command -v java php mariadbd mariadb-install-db python3 nmap dumpcap
php -m | grep -E 'mysqli|PDO'
```

Si faltan herramientas, instalarlas desde los repositorios oficiales de Kali con los permisos de administración correspondientes. No es necesario exponer la aplicación vulnerable a la LAN.

## 2. Crear una carpeta desechable

Desde la raíz del repositorio:

```bash
mkdir -p lab
cd lab
apt-get download zaproxy dvwa snort libdaq3
for package in *.deb; do dpkg-deb -x "$package" tools; done
```

Los comandos extraen paquetes en una carpeta de trabajo y no instalan pfSense. La ejecución documentada utilizó ZAP 2.17.0, DVWA 2.5 y Snort 3.12.2.0. Si la distribución actual usa otras versiones o rutas, ajustar las rutas a los archivos descargados.

El paquete DVWA contiene un enlace de configuración a `/etc/dvwa/config`. Para mantener los archivos dentro de esta carpeta de práctica, únicamente en la copia recién extraída:

```bash
if [ -L tools/usr/share/dvwa/config ]; then
  mv tools/usr/share/dvwa/config tools/usr/share/dvwa/config.packaged-link
  mkdir tools/usr/share/dvwa/config
fi
cp tools/etc/dvwa/config/config.inc.php.dist \
  tools/usr/share/dvwa/config/config.inc.php
```

## 3. Inicializar MariaDB de laboratorio

Ejecutar una sola vez para un directorio de datos nuevo:

```bash
mkdir -p db
mariadb-install-db --no-defaults --datadir="$PWD/db" \
  --auth-root-authentication-method=normal
```

En una terminal dedicada, desde `lab`:

```bash
mariadbd --no-defaults --datadir "$PWD/db" \
  --socket "$PWD/db.sock" --pid-file "$PWD/db.pid" \
  --bind-address 127.0.0.1 --port 3307
```

En otra terminal, desde `lab`, crear únicamente el usuario y la base ficticios utilizados por DVWA:

```bash
mariadb --no-defaults --socket "$PWD/db.sock" -u root <<'SQL'
CREATE DATABASE IF NOT EXISTS dvwa;
CREATE USER IF NOT EXISTS 'dvwa'@'127.0.0.1' IDENTIFIED BY 'p@ssw0rd';
GRANT ALL ON dvwa.* TO 'dvwa'@'127.0.0.1';
SQL
```

`p@ssw0rd`, `admin/password` y `gordonb/abc123` son credenciales de demostración de DVWA. No son credenciales personales ni deben reutilizarse fuera del laboratorio. El método de autenticación de esta base desechable no representa una configuración productiva.

## 4. Iniciar DVWA y ZAP

En terminales separadas y desde `lab`:

```bash
DB_PORT=3307 php -S 127.0.0.1:8088 -t tools/usr/share/dvwa
```

```bash
java -jar tools/usr/share/zaproxy/zap-2.17.0.jar -daemon \
  -host 127.0.0.1 -port 8090 -config api.key=actividad4
```

La clave `actividad4` corresponde exclusivamente a la API local de ZAP de esta práctica. No cambiar el enlace a todas las interfaces. Esperar a que la API de ZAP responda:

```bash
curl 'http://127.0.0.1:8090/JSON/core/view/version/?apikey=actividad4'
```

## 5. Ejecutar pruebas autenticadas

Desde `lab`, con el entorno Python del repositorio activado:

```bash
python -u ../src/dvwa_pruebas.py | tee dvwa_resultados.txt
python ../src/dvwa_acceso.py | tee acceso_resultados.txt
```

El primer script usa Create / Reset Database, inicia sesión en DVWA, configura la sesión del escáner y prueba los módulos SQLi y XSS. La política activa de ZAP se limita a las reglas 40018 y 40012. El segundo script compara el acceso de un usuario ordinario en low y high. No ejecutarlos contra una instalación ajena ni con datos que se deseen conservar.

## 6. Capturar Nmap y evaluar Snort

Volver a la raíz del repositorio:

```bash
bash scripts/capturar_y_detectar.sh
```

La captura necesita los permisos correspondientes de dumpcap. En el equipo evaluado ya estaban disponibles. El script no modifica capacidades ni permisos del sistema. Usa un escaneo TCP connect de `127.0.0.1`, guarda archivos en `lab` y lee el resultado con Snort.

## 7. Cerrar el laboratorio

Detener con Ctrl+C los procesos iniciados en sus terminales: API Python, ZAP, PHP y MariaDB. Esperar a que MariaDB cierre y después comprobar:

```bash
ss -lnt
```

Conservar las salidas de las pruebas y el PCAP como evidencia local. No subir directorios de bases de datos ni secretos reales. La carpeta `lab` está excluida de Git.

## Limitaciones registradas

- SQLi se confirmó mediante lectura de registros adicionales; no se realizaron cambios destructivos.
- XSS se confirmó en la respuesta HTML y mediante ZAP; no se documentó robo de sesión ni ejecución manual en navegador.
- El módulo de autorización de DVWA devolvió HTTP 200 con un objeto de error en high; no se reporta como HTTP 403.
- Snort se evaluó sobre PCAP. La práctica no prueba bloqueo IPS inline ni integración con pfSense.
- La interfaz de Postman/Insomnia y el despliegue real de pfSense quedaron pendientes.
- La parte de diseño de red fue excluida por indicación docente comunicada para la actividad.
