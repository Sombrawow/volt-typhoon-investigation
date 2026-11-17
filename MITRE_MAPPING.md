# 🗺️ Mapeo MITRE ATT&CK

[⬅️ README](./README.md) · [📅 Timeline](./TIMELINE.md) · [🎯 IOCs](./IOCs.md)

> **Versión.** IDs y tácticas según ATT&CK anterior a la reestructuración de las versiones 19/20 (noviembre de 2026). En la versión actual, T1070.001 redirige a **T1685.005 (Disable or Modify Tools: Clear Windows Event Logs)**, en la nueva táctica Defense Impairment, y TA0005 ha cambiado de nombre. Se mantienen los IDs anteriores porque son los que usan la mayoría de reglas y herramientas existentes.

Cada técnica lleva el evento que la sustenta. **Confianza**: *Alta* = el log muestra la acción; *Media* = la acción se deduce del log con un paso de razonamiento; *Inferida* = depende de contexto externo al log.

---

## Técnicas por táctica

### Initial Access
| ID | Nombre | Evidencia | Confianza |
|---|---|---|---|
| T1190 | Exploit Public-Facing Application | No observada. Inferida del escenario (ADSelfService Plus) y del aviso CISA AA23-144A, que incluye CVE-2021-40539 entre las vulnerabilidades explotadas por Volt Typhoon. Fecha desconocida: la cuenta ya muestra actividad exclusiva desde el 17/03 | Inferida |

### Execution
| ID | Nombre | Evidencia | Confianza |
|---|---|---|---|
| T1047 | Windows Management Instrumentation | `wmic useraccount create` (24/03) y `wmic process call create`, local y con `/node:` (25/03–29/03) | Alta |
| T1059.001 | PowerShell | Comando `-E` con mimikatz (26/03 21:53:41) | Alta |

### Persistence
| ID | Nombre | Evidencia | Confianza |
|---|---|---|---|
| T1136 | Create Account | `wmic useraccount create UserName='voltyp-admin'` (24/03 11:11:12). El log no distingue cuenta local (.001) o de dominio (.002); la inscripción posterior en ADSS sugiere dominio | Alta |
| T1098 | Account Manipulation | Cambio de contraseña de `dean-admin` (24/03 11:10:22); inscripción, desbloqueo, cambio de contraseña y pregunta de seguridad de `voltyp-admin` (24/03 11:12–11:14) | Alta |
| T1098.005 | Account Manipulation: Device Registration | MFA Setup de `voltyp-admin` (24/03 11:14:45): registro de un factor propio en una cuenta controlada por el atacante | Alta |
| T1505.003 | Server Software Component: Web Shell | `AuditReport.jspx` en `wwwroot` de `server-02` (29/03 19:47:43). IIS no ejecuta `.jspx` sin un handler específico: funcionalidad no confirmada | Media |

### Defense Evasion
| ID | Nombre | Evidencia | Confianza |
|---|---|---|---|
| T1036.005 | Masquerading: Match Legitimate Name or Location | `ntuser.ini` → `iisstart.aspx` → `AuditReport.jspx` (28–29/03) | Alta |
| T1036.008 | Masquerading: Masquerade File Type | `cisco-up.7z` → `cl64.gif` (26/03 02:02:35) | Alta |
| T1140 | Deobfuscate/Decode Files or Information | `certutil -decode` (28/03 21:19:23) | Alta |
| T1070.001 | Indicator Removal: Clear Windows Event Logs | `wevtutil cl Application Security Setup System` (29/03 22:04:23) | Alta |
| T1070.004 | Indicator Removal: File Deletion | `rd /S C:\Windows\Temp` en `webserver-01` (26/03 02:04:28) | Alta |
| T1070.007 | Indicator Removal: Clear Network Connection History and Configurations | Borrado de `MRU0` de RDP (25/03 21:48:28) | Alta |
| T1497.001 | Virtualization/Sandbox Evasion: System Checks | `Get-ItemProperty ... \| Select-Object -Property *Virtual*` (26/03 21:15:18) | Alta |
| T1078.002 | Valid Accounts: Domain Accounts | Credenciales de `dean-admin` en `wmic /user:` (29/03) | Alta |

### Credential Access
| ID | Nombre | Evidencia | Confianza |
|---|---|---|---|
| T1003.003 | OS Credential Dumping: NTDS | `ntdsutil "ifm create full ...temp.dit"` (25/03 22:44:31) | Alta |
| T1003.001 | OS Credential Dumping: LSASS Memory | Procesado de un `lsass.dmp` preexistente con `sekurlsa::minidump` (26/03 21:53:41); creación del volcado no observada | Media |
| T1552.001 | Unsecured Credentials: Credentials In Files | `wmic DATAFILE ... Name like '%password%'` (17/03 17:44:31) | Media |
| T1552.002 | Unsecured Credentials: Credentials in Registry | `reg query` sobre OpenSSH, RealVNC y PuTTY (27/03); el log no muestra el resultado | Media |

### Discovery
| ID | Nombre | Evidencia | Confianza |
|---|---|---|---|
| T1082 | System Information Discovery | `wmic /node:server01, server02 logicaldisk get ...` (25/03 21:30:03) | Alta |
| T1083 | File and Directory Discovery | Búsqueda de ficheros `%password%` (17/03) | Alta |
| T1016 | System Network Configuration Discovery | `wmic nicconfig ...` (17/03 07:14:30) | Alta |
| T1057 | Process Discovery | `wmic process list brief` x3 en `.133` (23/03) | Alta |
| T1654 | Log Enumeration | `wmic nteventlog where logfile=...` (17/03, 24/03) y `wevtutil` 4624/4625/4769 (25–29/03) | Alta |

### Lateral Movement
| ID | Nombre | Evidencia | Confianza |
|---|---|---|---|
| T1570 | Lateral Tool Transfer | `Copy-Item` del web shell a `\\server-02\C$` (29/03 19:47:43) | Alta |

### Collection
| ID | Nombre | Evidencia | Confianza |
|---|---|---|---|
| T1005 | Data from Local System | Copia de `2022.csv`, `2023.csv`, `2024.csv` a `faudit` (27/03) | Alta |
| T1074.002 | Data Staged: Remote Data Staging | `xcopy temp.dit` a `\\webserver-01\c$\inetpub\wwwroot` (25/03 22:45:27) | Alta |
| T1560.001 | Archive Collected Data: Archive via Utility | `7z a -v100m -p ...` (25/03 23:47:07) | Alta |

### Command and Control
| ID | Nombre | Evidencia | Confianza |
|---|---|---|---|
| T1090.001 | Proxy: Internal Proxy | `netsh interface portproxy add v4tov4 ... connectaddress=10.2.30.1` (29/03 23:13:09) | Alta |
| T1105 | Ingress Tool Transfer | `Invoke-WebRequest` de `mimikatz.exe` desde `voltyp.com` (26/03 21:53:41) | Alta |

### Exfiltration
Sin técnicas mapeadas: hay preparación (staging, compresión, camuflaje en una ruta servida por HTTP), pero ningún log confirma la salida de datos.

---

## Correcciones respecto a la versión anterior del repositorio

| Antes | Ahora | Motivo |
|---|---|---|
| T1098.003 (Additional Cloud Roles) para el enrollment | T1098 + T1098.005 | T1098.003 describe roles en entornos cloud; el caso es un portal on-premise. Registrar un factor MFA propio es Device Registration (T1098.005), no la modificación del mecanismo MFA (T1556.006) |
| T1190 sobre el cambio de contraseña del 24/03 | T1098 (observada) + T1190 (inferida, aparte) | El log muestra una manipulación de cuenta, no la explotación |
| T1136.001 | T1136 | El log no permite saber si la cuenta es local o de dominio |
| T1036.008 para `AuditReport.jspx` | T1036.005 | Cambiar `.aspx` por `.jspx` no disfraza el tipo de fichero; es un nombre legítimo para pasar desapercibido |
| T1567 / T1041 (Exfiltration) | Retiradas | No hay evidencia de salida de datos |
| T1555 (Credentials from Password Stores) | T1552.002 | Las consultas son a claves de registro, no a un gestor de contraseñas |
| T1497.001 solo en Discovery | Defense Evasion | Se agrupa por su finalidad (evitar el análisis); ATT&CK la lista también en Discovery |
| T1213 (Data from Information Repositories) | T1005 | Los CSV se copian del sistema de ficheros local |
| T1003.001 atribuido a un volcado de LSASS observado | Matizado | Solo se observa el procesado de un `lsass.dmp` existente |

---

## Nota sobre atribución

- **Vector inicial.** El aviso conjunto CISA AA23-144A sobre Volt Typhoon incluye CVE-2021-40539 (ManageEngine ADSelfService Plus) entre las vulnerabilidades explotadas por el actor. La ficha del grupo en ATT&CK (G1017) no lo recoge, y Microsoft atribuyó en 2021 otra campaña contra el mismo producto a DEV-0322: un mismo CVE lo explotan varios actores.
- **Comportamiento.** La mayoría de las técnicas observadas figuran como procedimientos de G1017 en ATT&CK, entre ellas `ntdsutil` IFM (T1003.003), copias del NTDS con extensión `.gif` (T1036.008), archivos 7z con contraseña (T1560.001), `certutil` (T1140), copia de web shells entre servidores (T1570), comprobación de virtualización (T1497.001), `wevtutil` (T1654) y `netsh portproxy` (T1090.001).
- **Conclusión.** El caso es muy coherente con los TTPs publicados de Volt Typhoon, pero las técnicas Living off the Land no son exclusivas de un actor y los logs no permiten una atribución independiente.

Referencias:
- [MITRE ATT&CK — Volt Typhoon (G1017)](https://attack.mitre.org/groups/G1017/)
- [CISA — AA23-144A: PRC State-Sponsored Cyber Actor Living off the Land to Evade Detection](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a)
- [MITRE ATT&CK — T1098.005 Device Registration](https://attack.mitre.org/techniques/T1098/005/)
- [MITRE ATT&CK — T1654 Log Enumeration](https://attack.mitre.org/techniques/T1654/)
- [MITRE ATT&CK — T1090.001 Internal Proxy](https://attack.mitre.org/techniques/T1090/001/)
- [Microsoft — Threat actor DEV-0322 exploiting ZOHO ManageEngine ADSelfService Plus](https://www.microsoft.com/en-us/security/blog/2021/11/08/threat-actor-dev-0322-exploiting-zoho-manageengine-adselfservice-plus/)
