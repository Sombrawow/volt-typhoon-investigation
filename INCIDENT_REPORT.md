# 📋 Informe de incidente — Volt Typhoon (TryHackMe)

[⬅️ README](./README.md) · [📅 Timeline](./TIMELINE.md) · [🎯 IOCs](./IOCs.md) · [🗺️ MITRE](./MITRE_MAPPING.md)

| Campo | Valor |
|---|---|
| Analista | Javier García |
| Entorno | Room "Volt Typhoon" de TryHackMe (laboratorio) |
| Herramienta | Splunk (`index=main`; sourcetypes `adss`, `wmic`, `powershell`) |
| Periodo analizado | 22/02/2024 – 30/03/2024 |
| Ventana de los logs | 17/03/2024 07:14:30 – 30/03/2024 (UTC); no hay eventos anteriores |
| Actividad del atacante documentada | 24/03/2024 11:10:22 – 29/03/2024 23:56:30 (posible actividad previa desde el 17/03) |
| Severidad | Crítica: compromiso de credenciales de todo el dominio |
| Estado | Análisis completado; exfiltración no confirmable con los datos disponibles |

---

## 1. Resumen ejecutivo

Un atacante controló la cuenta de administración `dean-admin`. Entre el 24 y el 29 de marzo creó una cuenta propia con persistencia reforzada, volcó la base de datos de Active Directory del probable controlador de dominio y la preparó para su extracción desde un servidor web, ejecutó mimikatz contra un volcado de LSASS ya existente, desplegó un web shell, abrió un túnel hacia `10.2.30.1:8443` y lanzó el borrado de los logs de eventos. Desde el 17/03, primer día con logs, la misma cuenta ya ejecuta un reconocimiento que ninguna otra cuenta realiza.

Todo se hizo con herramientas nativas de Windows (Living off the Land), lo que obligó a distinguir la actividad del atacante del ruido administrativo normal comparando el comportamiento de todas las cuentas.

**Impacto:** las credenciales de todo el dominio deben considerarse comprometidas. También se accedió a copias de datos financieros (`2022.csv`–`2024.csv`).

---

## 2. Cronología resumida

| Fecha | Fase | Hito |
|---|---|---|
| 17/03–23/03 | Reconocimiento (posible) | Desde el primer día de logs, `dean-admin` busca ficheros `%password%` y enumera logs, incluido Directory Service |
| 24/03 11:10 | Persistence | Cambio de contraseña de `dean-admin` en ADSelfService Plus (explotación de ADSS inferida, no observada) |
| 24/03 11:11–11:14 | Persistence | Creación de `voltyp-admin` y alta de contraseña, pregunta de seguridad y MFA |
| 25/03 22:44 | Credential Access | Volcado del NTDS (`temp.dit`) en `.153` |
| 25/03 22:45 – 26/03 02:04 | Collection | Staging en `webserver-01`, cifrado (`cisco-up.7z`), camuflaje (`cl64.gif`), borrado de `Temp` |
| 26/03 21:53 | Credential Access | Mimikatz desde `voltyp.com` sobre `lsass.dmp` |
| 27/03 | Credential Access / Collection | Consultas de credenciales en el registro; copia de datos financieros |
| 28–29/03 | Persistence | Web shell `iisstart.aspx` desplegado como `AuditReport.jspx` en `server-02` |
| 29/03 22:04 | Defense Evasion | Comando de borrado de los logs Application, Security, Setup y System |
| 29/03 23:13–23:56 | Command and Control | Túnel `netsh portproxy` hacia `10.2.30.1:8443` |

Detalle completo: [TIMELINE.md](./TIMELINE.md).

---

## 3. Hallazgos clave

1. **El inicio del compromiso no puede fijarse.** Los logs empiezan el 17/03 y desde ese día `dean-admin` ejecuta comandos que ninguna otra cuenta ejecuta (búsqueda de ficheros `%password%`, enumeración de logs). Si son del atacante, el cambio de contraseña del 24/03 consolida un acceso previo en vez de ser el acceso inicial.
2. **`.153` es probablemente el controlador de dominio.** `ntdsutil ifm create full` se ejecutó sin `/node:`, es decir, localmente, y solo genera un volcado completo en un DC. Matiz: el `xcopy` posterior toma el volcado de una ruta local de `webserver-01`, y los logs no muestran cómo llegó allí.
3. **Persistencia por triple factor.** Al controlar contraseña, pregunta de seguridad y MFA de `voltyp-admin`, revertir uno solo no expulsa al atacante.
4. **Patrón de directorio de trabajo.** `C:\Windows\Temp\tmp`, `C:\Temp\db2` y `C:\Windows\Temp\faudit` se crean inmediatamente o pocos minutos antes de una operación sensible. Es la base de una regla de detección.
5. **El ruido corporativo era la mayor parte del volumen.** Solo los comandos exclusivos de `dean-admin` (creación de cuenta, `/node:`, `ntdsutil`, `netsh`, búsqueda de `%password%`, servicios de acceso remoto) sostienen la atribución.

---

## 4. Atribución

- **Vector inicial.** El aviso conjunto CISA AA23-144A sobre Volt Typhoon incluye CVE-2021-40539 (ManageEngine ADSelfService Plus) entre las vulnerabilidades explotadas por el actor. Microsoft atribuyó en 2021 otra campaña contra el mismo producto a DEV-0322, así que el vector por sí solo no identifica al actor.
- **Comportamiento.** La mayoría de las técnicas observadas figuran como procedimientos de Volt Typhoon (G1017) en ATT&CK: `ntdsutil` IFM, copias del NTDS con extensión `.gif`, 7z con contraseña, `certutil`, copia de web shells entre servidores, comprobación de virtualización, `wevtutil` y `netsh portproxy`.
- **Conclusión.** El caso es muy coherente con los TTPs publicados de Volt Typhoon, pero las técnicas Living off the Land no son exclusivas de un actor y los logs no permiten una atribución independiente.

---

## 5. Limitaciones

| Pregunta | Por qué no se puede responder |
|---|---|
| ¿Salieron los datos de la red? | No hay logs de IIS, proxy ni firewall |
| ¿Cómo se creó `lsass.dmp`? | No hay auditoría de creación de procesos (4688/Sysmon) |
| ¿Cuándo y cómo se obtuvo el control de `dean-admin`? | Los logs empiezan el 17/03 y la explotación de ADSS no aparece en el log de la aplicación |
| ¿Qué es `10.2.30.1`? | Dirección privada fuera de los rangos observados; sin contexto de red |
| ¿Se ejecutó con éxito el borrado de logs o el web shell? | Los logs muestran comandos, no resultados; `wevtutil cl` admite un log por llamada e IIS no ejecuta `.jspx` sin handler |
| ¿Devolvieron credenciales los `reg query`? | Los logs registran el comando, no su salida |

---

## 6. Recomendaciones prioritarias

- [ ] Deshabilitar `voltyp-admin`; rotar `dean-admin` y revocar sus factores.
- [ ] Restablecer todas las contraseñas del dominio y `krbtgt` dos veces.
- [ ] Retirar el web shell y los artefactos de staging, con copia forense.
- [ ] Eliminar el `portproxy`, bloquear `voltyp.com` e identificar y aislar el host `10.2.30.1`.
- [ ] Parchear ADSelfService Plus y sacarlo de Internet.
- [ ] Centralizar logs (IIS, proxy, 4688/Sysmon) con retención fuera del endpoint.

Detalle, reglas Sigma y hardening: [RECOMMENDATIONS.md](./RECOMMENDATIONS.md).
