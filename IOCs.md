# 🔑 Indicators of Compromise (IOCs): Volt Typhoon

<div align="center">

**Lista Completa de IOCs Identificados Durante la Investigación**

![IOCs](https://img.shields.io/badge/Total%20IOCs-25+-red)
![Last Updated](https://img.shields.io/badge/Updated-2024--03--26-blue)
![Confidence](https://img.shields.io/badge/Confidence-High-green)

[📋 Reporte](./INCIDENT_REPORT.md) | [📅 Timeline](./TIMELINE.md) | [🗺️ MITRE](./MITRE_MAPPING.md)

</div>

---

## ⚠️ Advertencia de Uso

> 🔒 **Estos IOCs son de un ejercicio educativo (TryHackMe)**.  
> 🎯 **Úsalos para**: Aprender, practicar detección, y construir reglas de prueba.  
> ❌ **No los uses para**: Bloquear tráfico real sin validación contextual.  
> ✅ **Adapta siempre**: Los IOCs de APTs reales evolucionan; usa patrones, no solo valores estáticos.

---

## 📊 Resumen Ejecutivo de IOCs

| Categoría | Cantidad | Ejemplo Clave |
|-----------|----------|--------------|
| 👤 Cuentas Comprometidas | 3 | `dean-admin`, `voltyp-admin` |
| 📁 Archivos Maliciosos | 5 | `temp.dit`, `cl64.gif` |
| 💻 Comandos Ofensivos | 8+ | `ntdsutil`, `wevtutil cl` |
| 🌐 Indicadores de Red | 3 | `10.2.30.1:8443` |
| 🔑 Registry Keys | 4+ | `HKLM\...\SystemInformation` |
| 🛠️ Herramientas Usadas | 6 | Mimikatz, 7z, netsh |

---

## 👤 Cuentas Comprometidas

| Cuenta | Tipo | Contexto del Compromiso | Detección Sugerida |
|--------|------|------------------------|-------------------|
| `dean-admin` | Usuario privilegiado | Password reset vía ADSelfService Plus explotado (T1190) | Alertar sobre password resets en apps web fuera de proceso HR |
| `voltyp-admin` | Backdoor local | Creada por atacante con privilegios de administrador (T1136.001) | Alertar sobre creación de cuentas con "admin" no autorizadas |
| `d5ag0nm@5t3r` | Backdoor ofuscada | Nombre en leetspeak para evadir detección (T1036.003) | Detectar cuentas con números/caracteres especiales en nombres |

### 🔍 Query Splunk para detectar cuentas sospechosas:
```splunk
index="main" EventID=4720 OR EventID=4732
| search user="*admin*" OR user="*[0-9]*" OR user="*[@$]*"
```
### 🔍 Query Splunk para detectar archivos sospechosos:
```splunk
index="main" sourcetype="sysmon" EventID=11
| search file_name="*.aspx" OR file_name="*.jspx" OR file_name="*.dit"
| search file_path="*wwwroot*" OR file_path="*Temp*"
```
### 🔍 Query Splunk para detectar comandos sospechosos:
```splunk
index="main" sourcetype="cmd" OR "powershell"
| search "ntdsutil" OR "mimikatz" OR "wevtutil cl" OR "portproxy" OR "Invoke-WebRequest"
```
### 🔍 Query Splunk para detectar tráfico sospechoso:
```splunk
index="main" sourcetype="proxy" OR "firewall"
| search dest_ip="10.2.30.1" OR dest_port="8443" OR uri="*voltyp.com*"
```
### 🔍 Query Splunk para detectar consultas de registro sospechosas:
```splunk
index="main"
| search registry_path="*SystemInformation*" OR registry_path="*OpenSSH*" OR registry_path="*PuTTY*"
```
### 📁 Archivos Maliciosos

- iisstart.aspx
C:\inetpub\wwwroot\
Web Shell (.aspx)
Persistencia y ejecución remota (T1505.003)

- AuditReport.jspx
C:\inetpub\wwwroot\ (server-02)
Web Shell (.jspx)
Persistencia con masquerading (T1036.008)

- temp.dit
C:\Windows\Temp\
NTDS Dump
Extracción de credenciales de dominio (T1003.003)

- cisco-up.7z → cl64.gif
\\webserver-01\c$\inetpub\wwwroot\
Archivo ofuscado
Preparación para exfiltración (T1036.008)

- mimikatz.exe
C:\Temp\db2\
Herramienta ofensiva
Dump de credenciales LSASS (T1003.001)

### 📋 Checklist de Respuesta Rápida
✅ [ ] Rotar credenciales de dean-admin y eliminar cuentas backdoor
✅ [ ] Eliminar web shells: iisstart.aspx, AuditReport.jspx
✅ [ ] Buscar y eliminar temp.dit, cl64.gif, mimikatz.exe en todos los hosts
✅ [ ] Revisar configuraciones de netsh portproxy en todos los servidores
✅ [ ] Restaurar logs desde backups/SIEM para análisis forense completo
✅ [ ] Parchear ADSelfService Plus inmediatamente
✅ [ ] Implementar detección para los queries de Splunk proporcionados
✅ [ ] Auditar todas las cuentas con privilegios elevados

### 🔄 Cómo Actualizar Estos IOCs

- Valida en tu entorno: No bloquees ciegamente; prueba en modo "alert-only" primero
- Contextualiza: Adapta IPs, rutas, y nombres de usuario a tu infraestructura
- Automatiza: Convierte estos IOCs en reglas de SIEM/EDR para detección proactiva
- Comparte: Contribuye a comunidades como MISP, OTX, o GitHub con IOCs anonimizados
- Revisa: Los APTs evolucionan; actualiza tus IOCs trimestralmente o tras nuevos informes
