# 🔍 Splunk Queries: Volt Typhoon Investigation

## 📊 Tabla de Contenidos

1. Initial Access Detection
2. Persistence Detection
3. Execution & LOLBins
4. Credential Access
5. Discovery Techniques
6. Lateral Movement
7. Collection & Staging
8. Command and Control
9. Defense Evasion

1. Initial Access Detection
🔓 Query 1.1: ADSelfService Plus Password Resets

- Propósito: Detectar password resets sospechosos en ADSelfService Plus que puedan indicar explotación.

index="main" sourcetype="adselfserviceplus" 
| stats count by user, action, src_ip, status
| where count > 3
| sort -count

- Explicación: 
Filtra logs de ADSelfService Plus
Agrupa por usuario, acción, IP y estado
Muestra solo aquellos con más de 3 eventos (umbral de anomalía)
Ordena descendente por count

- Resultados Esperados: Usuarios con múltiples password resets, especialmente fuera de horario laboral.

🔓 Query 1.2: Initial Compromise Timeline
Propósito: Reconstruir timeline de eventos iniciales de compromiso.

index="main" sourcetype="adselfserviceplus" user="dean-admin"
| table _time, action, status, src_ip, message
| sort _time ASC
| head 20

- Explicación:
Filtra eventos específicos del usuario comprometido
Muestra timestamp, acción, estado, IP y mensaje
Ordena cronológicamente (ASC) para ver el primer evento
Limita a 20 resultados

- Resultados Esperados: Timeline completo de actividades del usuario dean-admin.

2. Persistence Detection
🔐 Query 2.1: Backdoor Account Creation
- Propósito: Detectar creación de cuentas sospechosas (backdoors).

index="main" EventID=4720 
| search target_user="*admin*" OR target_user="*[0-9]*" OR target_user="*[@$]*"
| table _time, creator_user, target_user, host, source_ip
| sort _time DESC

- Explicación:
EventID 4720 = Account Created en Windows Security Logs
Busca patrones sospechosos: "admin", números, caracteres especiales
Muestra quién creó la cuenta, nombre de cuenta, host e IP

- Resultados Esperados: Cuentas como voltyp-admin, d5ag0nm@5t3r.

🔐 Query 2.2: Web Shell Detection
- Propósito: Detectar creación de archivos .aspx/.jspx en directorios web.

index="main" sourcetype="sysmon" EventID=11 
| search (file_path="*inetpub*wwwroot*" OR file_path="*wwwroot*") 
    AND (file_name="*.aspx" OR file_name="*.jspx" OR file_name="*.ashx")
| table _time, host, file_path, file_name, user
| sort _time DESC

- Explicación:
EventID 11 = File Create en Sysmon
Busca en directorios wwwroot de IIS
Filtra extensiones ejecutables web
Muestra ruta completa y usuario que creó el archivo

- Resultados Esperados: Web shells como iisstart.aspx, AuditReport.jspx.

🔐 Query 2.3: Malicious Enrollment Detection
- Propósito: Detectar enrollment malicioso en aplicaciones de self-service.

index="main" sourcetype="adselfserviceplus" 
| search action="Enrollment" OR action="*enroll*"
| table _time, user, enrollment_method, src_ip, status
| sort _time DESC

- Explicación:
Busca acciones de enrollment en ADSelfService Plus
Muestra método de enrollment (email, SMS, security questions)
Identifica enrollments fuera de proceso normal

- Resultados Esperados: Enrollment sospechoso de dean-admin para persistencia.

3. Execution & LOLBins
⚡ Query 3.1: WMIC Remote Execution
- Propósito: Detectar uso de WMIC para ejecución remota y descubrimiento.

index="main" sourcetype="cmd" OR "powershell"
| search "wmic" AND ("/node:" OR "logicaldisk" OR "datafile" OR "os get")
| table _time, user, host, command
| sort _time ASC

- Explicación:
Busca comandos WMIC en logs de CMD/PowerShell
Filtra por flags de ejecución remota (/node:) y discovery
Muestra timeline completo de actividad WMIC

- Resultados Esperados: Comandos como wmic /node:server01,server02 logicaldisk get...

⚡ Query 3.2: PowerShell Encoded Commands
Propósito: Detectar PowerShell con comandos codificados en Base64.

index="main" sourcetype="powershell"
| search "-E" OR "-EncodedCommand" OR "-enc" OR "FromBase64String"
| table _time, user, host, command, encoded_command
| sort _time DESC

- Explicación:
Busca flags de codificación: -E, -EncodedCommand, -enc
Incluye FromBase64String para detección de decodificación
Muestra comando codificado completo si está disponible

- Resultados Esperados: PowerShell -E con Base64 para download de Mimikatz.

⚡ Query 3.3: LOLBins Usage Summary
- Propósito: Resumen de uso de LOLBins (Living Off The Land Binaries).

index="main" sourcetype="cmd" OR "powershell" OR "sysmon"
| search "ntdsutil" OR "mimikatz" OR "netsh" OR "wevtutil" OR "wmic" OR "xcopy"
| stats count by command_tool, user, host
| sort -count
| rename command_tool as "LOLBin", count as "Ejecuciones"

- Explicación:
Agrega todos los LOLBins principales usados por Volt Typhoon
Cuenta ejecuciones por herramienta, usuario y host
Proporciona visión general de actividad LOLBin

- Resultados Esperados: Lista de LOLBins usados con frecuencia.

4. Credential Access
🔑 Query 4.1: NTDS Dump Detection
- Propósito: Detectar dump de Active Directory con ntdsutil.

index="main" sourcetype="cmd" OR "powershell"
| search "ntdsutil" AND ("ifm" OR "create" OR "full")
| table _time, user, host, command, dest_path
| sort _time ASC

- Explicación:
Busca ntdsutil con parámetros de dump (ifm create full)
Muestra ruta de destino del archivo .dit
Critical: Esto indica compromiso total del dominio

- Resultados Esperados: ntdsutil "ifm create full" → temp.dit

🔑 Query 4.2: LSASS Access Detection
- Propósito: Detectar acceso a LSASS para credential dumping.

index="main" sourcetype="sysmon" EventID=10
| search target_image="*lsass.exe"
| table _time, process_name, target_image, user, granted_access
| sort _time DESC

- Explicación:
EventID 10 = Process Access en Sysmon
Filtra accesos a lsass.exe
Muestra qué proceso accedió y con qué permisos

- Resultados Esperados: mimikatz.exe o taskmgr accediendo lsass.exe.

🔑 Query 4.3: Registry Credential Hunting
- Propósito: Detectar consultas a registry keys con credenciales almacenadas.

index="main" sourcetype="sysmon" EventID=13
| search registry_path="*OpenSSH*" OR registry_path="*PuTTY*" OR registry_path="*RealVNC*" OR registry_path="*WinSCP*"
| table _time, user, host, registry_path, operation
| sort _time ASC

- Explicación:
EventID 13 = Registry Value Set/Query en Sysmon
Busca rutas de software que almacenan credenciales
Identifica robo de credenciales SSH, VNC, FTP

- Resultados Esperados: reg query en HKCU\Software\OpenSSH, PuTTY, RealVNC.

5. Discovery Techniques
🔍 Query 5.1: System Information Discovery
- Propósito: Detectar recolección de información del sistema.

index="main" sourcetype="cmd" OR "powershell"
| search "wmic" AND ("os get" OR "timezone" OR "computersystem" OR "bios")
| table _time, user, host, command
| sort _time ASC

- Explicación:
Busca WMIC queries de descubrimiento de sistema
Incluye timezone, OS info, BIOS, computer system
Indica fase de reconnaissance

- Resultados Esperados: wmic os get lastbootuptime, wmic timezone get...

🔍 Query 5.2: File and Directory Discovery
- Propósito: Detectar enumeración de archivos y directorios.

index="main" sourcetype="cmd" OR "powershell"
| search "wmic datafile" OR "dir" OR "Get-ChildItem"
| search "Windows" OR "Users" OR "Program Files" OR "finance"
| table _time, user, host, command
| sort _time ASC

- Explicación:
Busca comandos de enumeración de archivos
Filtra por directorios sensibles
Puede indicar búsqueda de datos valiosos

- Resultados Esperados: wmic datafile where "drive='C:' and path='\\Windows\\'"

🔍 Query 5.3: Virtualization Detection
Propósito: Detectar consultas para evasión de sandbox/VM.

index="main" sourcetype="sysmon" EventID=13
| search registry_path="*SystemInformation*" OR registry_path="*BiosVersion*" OR registry_path="*Virtual*"
| table _time, user, host, registry_path, registry_value_name
| sort _time ASC

- Explicación:
Busca consultas a registry keys de virtualización
SystemInformation contiene manufacturer/product que revelan VM
Indica técnica anti-analysis

- Resultados Esperados: reg query HKLM\SYSTEM\...\SystemInformation

6. Lateral Movement
🔄 Query 6.1: SMB Admin Share Usage
- Propósito: Detectar uso de administrative shares para movimiento lateral.

index="main" sourcetype="wineventlog" EventID=5145
| search ShareName="*c$" OR ShareName="*ADMIN$" OR ShareName="*ipc$"
| stats count by user, source_ip, ShareName, dest_host
| where count > 5
| sort -count

- Explicación:
EventID 5145 = Network Share Object Accessed
Filtra administrative shares (C$, ADMIN$, IPC$)
Agrupa por usuario e IP origen
Umbral de 5 accesos para detectar anomalías

- Resultados Esperados: xcopy ... \\webserver-01\c$\...

🔄 Query 6.2: Remote File Copy Detection
- Propósito: Detectar copias de archivos a sistemas remotos.

index="main" sourcetype="cmd" OR "powershell"
| search "xcopy" OR "robocopy" OR "copy-item" AND "\\\\*"
| search "c$" OR "ADMIN$" OR "wwwroot" OR "temp"
| table _time, user, host, command, destination
| sort _time ASC

- Explicación:
Busca comandos de copia con rutas UNC (\server\share)
Filtra por administrative shares o directorios web
Indica movimiento de herramientas o datos

- Resultados Esperados: xcopy C:\Temp\temp.dit \\webserver-01\c$\wwwroot

7. Collection & Staging
📦 Query 7.1: Archive Creation Detection
- Propósito: Detectar compresión de datos sensibles.

index="main" sourcetype="cmd" OR "powershell"
| search "7z" OR "winrar" OR "zip" OR "Compress-Archive"
| search "-p" OR "password" OR ".dit" OR ".csv" OR "finance"
| table _time, user, host, command, file_size
| sort _time ASC

- Explicación:
Busca herramientas de compresión (7z, winrar, zip)
Filtra por uso de contraseña (-p) o archivos sensibles (.dit, .csv)
Indica preparación para exfiltración

- Resultados Esperados: 7z a -v100m -p d5ag0nm@5t3r cisco-up.7z temp.dit

📦 Query 7.2: Financial Data Collection
- Propósito: Detectar colección de archivos financieros.

index="main" sourcetype="powershell"
| search "Copy-Item" OR "Get-ChildItem" OR "Move-Item"
| search "2022" OR "2023" OR "2024" AND (".csv" OR ".xlsx" OR ".pdf")
| search "finance" OR "budget" OR "account" OR "transaction"
| table _time, user, host, command, source, destination
| sort _time ASC

- Explicación:
Busca PowerShell copiando archivos con años (2022, 2023, 2024)
Filtra extensiones de documentos financieros
Indica colección de datos sensibles organizacionales

- Resultados Esperados: Copy-Item 2022.csv, 2023.csv, 2024.csv

8. Command and Control
🎯 Query 8.1: Netsh Portproxy Detection
- Propósito: Detectar configuración de proxy para C2.

index="main" sourcetype="cmd" OR "powershell"
| search "netsh" AND "portproxy" AND "add v4tov4"
| table _time, user, host, command, connectaddress, connectport, listenaddress, listenport
| sort _time DESC

- Explicación:
Busca configuración de portproxy con netsh
Extrae parámetros: connectaddress, connectport, listenaddress, listenport
Indica establecimiento de redirector C2

- Resultados Esperados: netsh interface portproxy add v4tov4 connectaddress=10.2.30.1 connectport=8443

🎯 Query 8.1: Malware Download Detection
- Propósito: Detectar descargas de herramientas ofensivas.

index="main" sourcetype="proxy" OR "dns"
| search "mimikatz" OR "voltyp.com" OR ".exe" AND ("download" OR "GET")
| table _time, src_ip, dest_ip, uri, user_agent, action
| sort _time DESC

- Explicación:
Busca en logs de proxy o DNS
Filtra por nombres de herramientas (mimikatz) o dominios sospechosos
Incluye user-agent para detectar scripts/curl
Indica download de herramientas ofensivas

- Resultados Esperados: http://voltyp.com/3/tlz/mimikatz.exe

9. Defense Evasion
- Propósito: Detectar limpieza de logs de Windows.

index="main" sourcetype="wineventlog" EventID=1102
| table _time, user, host, log_name, message
| sort _time DESC

- Explicación:
EventID 1102 = The audit log was cleared
CRITICAL: Esto ES un indicador de compromiso
Muestra qué log fue limpiado y por quién

- Resultados Esperados: wevtutil cl Security/System/Application/Setup

