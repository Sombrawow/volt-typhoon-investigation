# 🎯 Indicadores de compromiso (IOCs)

[⬅️ README](./README.md) · [📅 Timeline](./TIMELINE.md) · [🗺️ MITRE](./MITRE_MAPPING.md)

> ⚠️ **Entorno de laboratorio.** Todos los indicadores proceden de la room "Volt Typhoon" de TryHackMe. Sirven para practicar detección; no deben usarse para bloquear tráfico real. Las IPs `192.168.1.x` son direcciones privadas del laboratorio.

---

## 👤 Cuentas

| Cuenta | Tipo | Evidencia |
|---|---|---|
| `CTRL-ACC\dean-admin` | Cuenta de dominio comprometida | Cambio de contraseña en ADSS (24/03 11:10:22); ejecuta todas las acciones exclusivas del atacante |
| `voltyp-admin` | Cuenta creada por el atacante | `wmic useraccount create` (24/03 11:11:12) + inscripción, contraseña, pregunta de seguridad y MFA en ADSS |

## 🔑 Credenciales expuestas en los comandos

| Valor | Contexto | Acción de respuesta |
|---|---|---|
| `as&9ha2e$#&@n22n(` | Contraseña inicial de `voltyp-admin` | Deshabilitar la cuenta |
| `uNcr4cK4b1e` | Contraseña de `dean-admin` pasada a `wmic /user:` | Rotar; asumir comprometida |
| `d5ag0nm@5t3r` | Contraseña del archivo `cisco-up.7z` | Permite descifrar el archivo para valorar el alcance |

> El repositorio anterior trataba `d5ag0nm@5t3r` como una cuenta de usuario. Es la contraseña del archivo comprimido, no una cuenta.

---

## 📁 Ficheros y rutas

| Artefacto | Ruta / host | Qué es |
|---|---|---|
| `temp.dit` | `C:\Windows\Temp\tmp\` (host según el log: `.153`; el `xcopy` posterior la trata como ruta local de `webserver-01`); copiado a `C:\inetpub\wwwroot\` en `webserver-01` | Destino IFM del volcado del NTDS |
| `cisco-up.7z` / `cisco-up.7z.*` | `C:\inetpub\wwwroot\` en `webserver-01` | `temp.dit` comprimido y cifrado, en volúmenes de 100 MB (`.001`, `.002`…) |
| `cl64.gif` | `C:\inetpub\wwwroot\` en `webserver-01` | `cisco-up.7z` renombrado |
| `ntuser.ini` | `C:\Windows\Temp\` (host no determinado) | Web shell codificado en base64 antes de decodificar |
| `iisstart.aspx` | `C:\Windows\Temp\` (host no determinado) | Web shell decodificado |
| `AuditReport.jspx` | `C:\inetpub\wwwroot\` en `server-02` | El mismo web shell desplegado |
| `mimikatz.exe` | `C:\Temp\db2\` | Herramienta de extracción de credenciales |
| `lsass.dmp` | Desconocida | Volcado de LSASS procesado por mimikatz (creación no observada) |
| `2022.csv`, `2023.csv`, `2024.csv` | `C:\Windows\Temp\faudit\` | Copias de `C:\ProgramData\FinanceBackup\` |

**Directorios de trabajo del atacante** (patrón repetido): `C:\Windows\Temp\tmp`, `C:\Temp\db2`, `C:\Windows\Temp\faudit`.

**Registro**: borrado del valor `MRU0` (ruta oculta tras `$registryPath`; inferida: `HKCU\Software\Microsoft\Terminal Server Client\Default`, ubicación habitual del MRU de RDP); claves de `OpenSSH`, `realvnc` y `putty` consultadas.

---

## 🌐 Red

> Indicadores de red *defanged* (`[.]`, `hxxp`) para evitar que se conviertan en enlaces activos. En los comandos citados en el resto del repositorio se mantienen literales, porque son evidencia.

| Indicador | Tipo | Contexto |
|---|---|---|
| `voltyp[.]com` | Dominio | Descarga de mimikatz |
| `hxxp://voltyp[.]com/3/tlz/mimikatz.exe` | URL | Ídem |
| `10.2.30[.]1:8443` | IP:puerto | Destino del `netsh portproxy` (`connectaddress`/`connectport`) |
| `0.0.0.0:50100` en `server-01` | Puerto en escucha | Lado local del `portproxy` |

`10.2.30[.]1` es una dirección privada (RFC 1918): la acción de respuesta es identificar y aislar ese host, no bloquearlo como IP externa.

### Hosts internos implicados

| Host | Papel |
|---|---|
| `192.168.1.153` | Probable controlador de dominio (ejecuta `ntdsutil ifm` localmente; ver matiz en TIMELINE, Fase 3); origen del movimiento lateral del 25/03 |
| `192.168.1.133` | Host donde se crea `voltyp-admin` |
| `192.168.1.129`, `192.168.1.184` | Origen de comandos `/node:` del 26/03 y 29/03 |
| `webserver-01` | Staging del NTDS |
| `server-01` | Túnel `portproxy` |
| `server-02` | Web shell `AuditReport.jspx` |

### Indicadores descartados

| Indicador | Motivo |
|---|---|
| `192.168.1.134` | Usada también por siete cuentas legítimas en ADSS. No sirve como IOC aislado. |
| `calc.exe`, `notepad.exe` | Ejecutados también por cuentas legítimas. |

---

## 🛠️ Herramientas y LOLBins

`wmic`, `ntdsutil`, `xcopy`, `7z`, `certutil`, `netsh`, `wevtutil`, `reg`, PowerShell (`Invoke-WebRequest`, `Copy-Item`, `Remove-ItemProperty`) y `mimikatz`.

---

## ✅ Checklist de respuesta

- [ ] Deshabilitar `voltyp-admin` y revisar sus registros de MFA y preguntas de seguridad en ADSS.
- [ ] Rotar la contraseña de `dean-admin` y revocar sus factores de autenticación.
- [ ] Tratar el NTDS como comprometido: rotar todas las contraseñas del dominio y `krbtgt` dos veces.
- [ ] Eliminar `AuditReport.jspx`, `iisstart.aspx`, `ntuser.ini`, `cl64.gif`, `cisco-up.7z`, `temp.dit` y `mimikatz.exe`, conservando copia forense.
- [ ] Comprobar `netsh interface portproxy show all` en todos los servidores.
- [ ] Bloquear `voltyp.com`; buscarlo, junto con `10.2.30.1`, en logs de DNS, proxy y firewall, e identificar y aislar el host `10.2.30.1`.
- [ ] Revisar los logs de IIS de `webserver-01` y `server-02` en busca de peticiones a `cl64.gif` y `AuditReport.jspx`.
