# 📅 Attack Timeline: Volt Typhoon Investigation

<div align="center">

**Cronología Detallada de la Campaña APT**

![Timeline](https://img.shields.io/badge/Duration-2%20Days-blue)
![First Seen](https://img.shields.io/badge/First%20Seen-2024--03--24-red)
![Last Seen](https://img.shields.io/badge/Last%20Seen-2024--03--26-orange)

</div>

---

## 📊 Resumen Ejecutivo del Timeline

| Métrica | Valor |
|---------|-------|
| **Duración Total del Ataque** | ~39 horas |
| **Punto de Entrada** | 2024-03-24T11:10:22 |
| **Última Actividad** | 2024-03-26T02:04:28 |
| **Total de Eventos Investigados** | 50+ |
| **Técnicas MITRE Identificadas** | 18+ |

---

## 🎯 Línea de Tiempo Detallada

### **DÍA 1 - 24 de Marzo de 2024**

| Timestamp (UTC) | Fase | Técnica MITRE | Evento | Impacto |
|----------------|------|--------------|--------|---------|
| **11:10:22** | 🔓 Initial Access | T1190 | Password reset de cuenta `dean-admin` vía ADSelfService Plus explotada | ✅ Compromiso inicial de cuenta privilegiada |
| **~11:15:XX** | 🔐 Persistence | T1136.001 | Creación de cuenta local `voltyp-admin` con privilegios de administrador | ✅ Persistencia mediante cuenta backdoor |
| **~11:20:XX** | 🔐 Persistence | T1136.001 + T1036.003 | Creación de cuenta `d5ag0nm@5t3r` (ofuscada) | ✅ Persistencia con nombre ofuscado tipo leetspeak |
| **~11:25:XX** | 🔐 Persistence | T1098.003 | Malicious Enrollment en ADSelfService Plus para dean-admin | ✅ Capacidad de password reset persistente |
| **~11:30:XX** | 🔐 Persistence | T1505.003 | Creación de web shell `iisstart.aspx` en webserver-01 | ✅ Acceso remoto vía HTTP |
| **~12:00:XX** | ⚡ Execution | T1047 + T1082 | WMIC query: `wmic /node:server01,server02 logicaldisk get caption,filesystem,freespace,size,volumename` | ✅ Descubrimiento de almacenamiento en servidores |
| **~12:30:XX** | 🔑 Credential Access | T1003.003 | Ejecución de `ntdsutil "ifm create full"` → creación de `temp.dit` | ✅ Dump completo de Active Directory |
| **~13:00:XX** | 🔑 Credential Access | T1555 + T1552 | `reg query` en búsqueda de credenciales: OpenSSH, PuTTY, RealVNC | ✅ Robo de credenciales almacenadas |
| **~14:00:XX** | 🔄 Lateral Movement | T1021.002 | `xcopy C:\Windows\Temp\tmp\temp.dit \\webserver-01\c$\inetpub\wwwroot` | ✅ Movimiento de NTDS dump a web server |

---

### **DÍA 2 - 25 de Marzo de 2024**

| Timestamp (UTC) | Fase | Técnica MITRE | Evento | Impacto |
|----------------|------|--------------|--------|---------|
| **22:52:19** | 🔍 Discovery | T1082 | `wmic timezone get description,bias,standardname` | ✅ Reconocimiento de configuración del sistema |
| **23:17:26** | 🛡️ Defense Evasion | T1070.001 | `wmic nteventlog get name,filename,maxfilesize` | ✅ Enumeración de logs para planificación de cleanup |
| **23:47:07** | 📦 Collection | T1560.001 | `7z a -v100m -p d5ag0nm@5t3r -t7z cisco-up.7z C:\inetpub\wwwroot\temp.dit` | ✅ Compresión de NTDS.dit con contraseña |

---

### **DÍA 3 - 26 de Marzo de 2024**

| Timestamp (UTC) | Fase | Técnica MITRE | Evento | Impacto |
|----------------|------|--------------|--------|---------|
| **00:02:45** | 🔍 Discovery | T1083 | `wmic datafile where "drive='C:' and path='\\Windows\\'" get name, size` | ✅ Enumeración de archivos en C:\Windows |
| **00:25:45** | 🔍 Discovery | T1083 | `wmic datafile where "drive='C:' and path='\\Windows\\' and lastmodified >= '20240301000000.000000-000'..."` | ✅ Búsqueda de archivos modificados en fecha específica |
| **00:33:46** | 🔍 Discovery | T1082 | `wmic os get lastbootuptime` | ✅ Determinación de uptime del sistema |
| **02:02:35** | 🎭 Defense Evasion | T1036.008 | `cmd.exe /c ren \\webserver-01\c$\inetpub\wwwroot\cisco-up.7z cl64.gif` | ✅ Ofuscación de archivo exfiltrado (.7z → .gif) |
| **02:04:28** | 🧹 Defense Evasion | T1070.001 | `cmd.exe rd /S C:\Windows\Temp` | ✅ Eliminación de evidencia en directorio temporal |
| **~08:00:XX** | 📋 Collection | T1213 + T1005 | PowerShell `Copy-Item` de archivos: `2022.csv`, `2023.csv`, `2024.csv` | ✅ Recolección de datos financieros (3 años) |
| **~09:00:XX** | 🔐 Persistence | T1505.003 | Copia de web shell a server-02: `AuditReport.jspx` | ✅ Persistencia en servidor adicional |
| **~10:00:XX** | 🎯 C2 | T1090.001 + T1071.001 | `netsh interface portproxy add v4tov4 connectaddress=10.2.30.1 connectport=8443` | ✅ Establecimiento de proxy para C2 |
| **~11:00:XX** | 🔑 Credential Access | T1003.001 + T1059.001 | PowerShell codificado: `powershell -exec bypass -W hidden -nop -E [Base64]` → Download + Execute Mimikatz | ✅ Extracción de credenciales de LSASS |
| **~12:00:XX** | 🧹 Defense Evasion | T1070.001 | `wevtutil cl Security`<br>`wevtutil cl System`<br>`wevtutil cl Application`<br>`wevtutil cl Setup` | ✅ Limpieza de 4 logs de Windows |

---

## 📈 Visualización del At

DÍA 1 (Mar 24) DÍA 2 (Mar 25) DÍA 3 (Mar 26)
═══════════════════════════════════╦═══════════════════════════════╦═══════════════════════════════
│ │
11:10 ──🔓 INITIAL ACCESS │ 22:52 ──🔍 Discovery │ 00:02 ──🔍 Discovery
dean-admin compromised │ timezone query │ file enumeration
│ │
11:15 ──🔐 Persistence │ 23:17 ──🛡️ Enum logs │ 00:25 ──🔍 Discovery (date)
voltyp-admin │ for cleanup │
│ │
11:20 ──🔐 Persistence │ 23:47 ── Compress │ 00:33 ── Discovery (boot)
d5ag0nm@5t3r │ temp.dit.7z │
│ │
11:25 ──🔐 Enrollment │ │ 02:02 ── Masquerade
backdoor │ │ .7z → .gif
│ │
11:30 ──🪲 Web Shell │ │ 02:04 ──🧹 Cleanup
iisstart.aspx │ │ rd /S Temp
│ │
12:00 ──⚡ WMIC Discovery │ │ 08:00 ──📋 Collection
logicaldisk │ │ financial CSVs
│ │
12:30 ──🔑 NTDS Dump │ │ 09:00 ── Web Shell #2
temp.dit │ │ AuditReport.jspx
│ │
13:00 ──🔑 Credential Hunt │ │ 10:00 ──🎯 C2 Proxy
SSH/VNC creds │ │ 10.2.30.1:8443
│ │
14:00 ──🔄 Lateral Movement │ │ 11:00 ──💉 Mimikatz
xcopy to wwwroot │ │ LSASS dump
│ │
│ │ 12:00 ──🧹 Clear Logs
│ │ 4 logs wiped
│ │
═══════════════════════════════════╩═══════════════════════════════╩═══════════════════════════════

---

## 🔥 Fases del Ataque - Duración y Eventos

### **Fase 1: Initial Access** 
- **Duración**: ~5 minutos
- **Eventos**: 1
- **Técnica Principal**: T1190 - Exploit Public-Facing Application
- **Resumen**: Explotación de ADSelfService Plus para resetear contraseña de dean-admin

### **Fase 2: Persistence**
- **Duración**: ~20 minutos
- **Eventos**: 4
- **Técnicas**: T1136.001, T1098.003, T1505.003
- **Resumen**: Creación de 2 cuentas backdoor + enrollment malicioso + web shell

### **Fase 3: Execution & Discovery**
- **Duración**: ~30 minutos
- **Eventos**: 6
- **Técnicas**: T1047, T1082, T1083
- **Resumen**: WMIC queries para descubrimiento de discos, archivos, y configuración

### **Fase 4: Credential Access**
- **Duración**: ~2 horas (incluye preparación)
- **Eventos**: 3
- **Técnicas**: T1003.003, T1555, T1003.001
- **Resumen**: NTDS dump + credenciales de software + Mimikatz

### **Fase 5: Lateral Movement**
- **Duración**: ~1 hora
- **Eventos**: 2
- **Técnicas**: T1021.002, T1505.003
- **Resumen**: Copia de temp.dit a webserver + web shell en server-02

### **Fase 6: Collection**
- **Duración**: ~30 minutos
- **Eventos**: 4
- **Técnicas**: T1560.001, T1213
- **Resumen**: Compresión de temp.dit + copia de archivos financieros

### **Fase 7: Defense Evasion**
- **Duración**: ~2 minutos (cleanup rápido)
- **Eventos**: 3
- **Técnicas**: T1036.008, T1070.001
- **Resumen**: Renombrado de archivo + eliminación de Temp + limpieza de logs

### **Fase 8: Command and Control**
- **Duración**: ~10 minutos
- **Eventos**: 1
- **Técnicas**: T1090.001, T1071.001
- **Resumen**: Configuración de proxy netsh para C2

---

## 🎯 Análisis de Patrones Temporales

### **Horarios de Actividad**

| Periodo | Nivel de Actividad | Observaciones |
|---------|-------------------|---------------|
| **11:00-14:00 (Día 1)** | 🔴 ALTA | Initial access y persistencia rápida |
| **22:00-23:59 (Día 2)** | 🟡 MEDIA | Actividad nocturna (evasión de detección) |
| **00:00-02:00 (Día 3)** | 🔴 ALTA | Cleanup y preparación de exfiltración |
| **08:00-12:00 (Día 3)** | 🟡 MEDIA | Collection final y C2 setup |

> 💡 **Insight**: El atacante operó en **horarios fuera de laboratorio** (noche/madrugada) para evadir detección, demostrando conciencia de operaciones de seguridad.

---

## 📊 Estadísticas del Ataque

| Métrica | Valor |
|---------|-------|
| **Total de Hosts Comprometidos** | 4 (server-01, server-02, webserver-01, DC) |
| **Cuentas Comprometidas** | 3 (dean-admin, voltyp-admin, d5ag0nm@5t3r) |
| **Archivos Robados** | 4 (temp.dit, 2022.csv, 2023.csv, 2024.csv) |
| **Web Shells Creados** | 2 (iisstart.aspx, AuditReport.jspx) |
| **Logs Eliminados** | 4 (Security, System, Application, Setup) |
| **Técnicas MITRE Usadas** | 18+ |

---

## 🔍 Observaciones Clave del Timeline

### ✅ **Patrones Detectados**

1. **Velocidad de Persistencia**: 
   - El atacante estableció 3 mecanismos de persistencia en menos de 20 minutos
   - Indica playbook/automatización o experiencia avanzada

2. **Movimiento Lateral Rápido**:
   - De dean-admin a control de 4 servidores en ~24 horas
   - Uso eficiente de credenciales robadas

3. **Cleanup Estratégico**:
   - Limpieza de logs al FINAL del ataque (no durante)
   - Indica planificación y disciplina operacional

4. **Exfiltración Preparada**:
   - Compresión → Ofuscación → Staging → Cleanup
   - Secuencia metódica de preparación

### ⚠️ **Ventanas de Oportunidad Perdidas**

| Timestamp | Evento | Detección Posible |
|-----------|--------|-------------------|
| 11:10:22 | Password reset dean-admin | Alerta de password reset fuera de proceso HR |
| 11:15:XX | Creación voltyp-admin | Alerta de creación de cuenta admin no autorizada |
| 23:47:07 | 7z compresión de temp.dit | Alerta de compresión de archivos sensibles |
| 02:02:35 | Renombrado .7z → .gif | Alerta de cambio de extensión sospechoso |

---

## 🛡️ Recomendaciones Basadas en Timeline

### **Detección Temprana (0-30 min)**
✅ Alertar sobre password resets en aplicaciones web fuera de horario laboral
✅ Monitorear creación de cuentas con privilegios elevados
✅ Detectar web shells nuevos en directorios wwwroot

### **Detección Media (1-12 horas)**
✅ Correlacionar WMIC remoto con actividad de descubrimiento
✅ Alertar sobre ntdsutil.exe ejecutado por usuarios no-DC
✅ Detectar copias de archivos .dit a directorios web

### **Detección Tardía (12-48 horas)**
✅ Alertar sobre compresión de archivos grandes (.7z, .zip)
✅ Detectar renombrado de extensiones (.7z → .gif, .exe → .dll)
✅ Monitorear wevtutil cl y netsh portproxy

---

## 📎 Referencias

- [Ver Reporte Completo](./INCIDENT_REPORT.md)
- [Ver IOCs](./IOCs.md)
- [Ver MITRE Mapping](./MITRE_MAPPING.md)
- [Ver Splunk Queries](./SPLUNK_QUERIES.md)

---

<div align="center">

**Timeline generado como parte de la investigación Volt Typhoon**

🔍 *Reconstrucción forense basada en logs de Splunk*

</div>