# 🔍 Volt Typhoon — Investigación de una intrusión con Splunk

<div align="center">

![TryHackMe](https://img.shields.io/badge/TryHackMe-Volt%20Typhoon-green)
![Splunk](https://img.shields.io/badge/SIEM-Splunk-orange)
![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-blue)

**Reconstrucción forense de una intrusión simulada tipo APT a partir de logs de ADSelfService Plus, WMIC y PowerShell**

[📋 Informe](./INCIDENT_REPORT.md) · [📅 Timeline](./TIMELINE.md) · [🎯 IOCs](./IOCs.md) · [🗺️ MITRE](./MITRE_MAPPING.md) · [🔎 Queries](./SPLUNK_QUERIES.md) · [🛡️ Recomendaciones](./RECOMMENDATIONS.md)

</div>

---

## 📌 Resumen

Investigación de la room [Volt Typhoon](https://tryhackme.com/room/volttyphoon) de TryHackMe: un SOC detecta actividad compatible con un actor APT y hay que reconstruir la intrusión a partir de dos semanas de logs en Splunk.

El análisis va más allá de responder las preguntas de la room: separa el ruido operativo de la organización de la actividad realmente atribuible al atacante, documenta las hipótesis descartadas y declara explícitamente qué no puede demostrarse con los logs disponibles.

**Fuentes de datos disponibles** (confirmadas con `index=main | stats count by sourcetype`): `adss` (ADSelfService Plus), `wmic` y `powershell` (Module Logging, Event ID 800). No hay logs de red, proxy, web ni Windows Security.

---

## 📊 Hallazgos principales

| Fase | Hallazgo | Técnica MITRE |
|---|---|---|
| Initial Access | Explotación de ADSelfService Plus: inferida, no observada ([ver matiz](./TIMELINE.md#fase-2--persistence-24-de-marzo)) | T1190 *(inferida)* |
| Persistence | Cambio de contraseña de `dean-admin` (24/03 11:10:22) y cuenta `voltyp-admin` creada por WMIC con contraseña, pregunta de seguridad y MFA propios | T1098, T1136, T1098.005 |
| Credential Access | Volcado del NTDS con `ntdsutil` en el probable controlador de dominio | T1003.003 |
| Credential Access | Mimikatz descargado con PowerShell codificado y ejecutado contra un `lsass.dmp` existente | T1003.001 |
| Credential Access | Búsqueda de credenciales de OpenSSH, RealVNC y PuTTY en el registro | T1552.002 |
| Collection | Staging del NTDS en la raíz web de `webserver-01`, cifrado y camuflado como `cl64.gif` | T1074.002, T1560.001, T1036.008 |
| Persistence | Web shell decodificado con `certutil` y desplegado como `AuditReport.jspx` en `server-02` | T1505.003, T1036.005 |
| Command and Control | Túnel `netsh portproxy` hacia `10.2.30.1:8443` | T1090.001 |
| Defense Evasion | Comando de borrado de los logs Application, Security, Setup y System | T1070.001 |

Listado completo, con evidencia por técnica: [MITRE_MAPPING.md](./MITRE_MAPPING.md).

---

## 🧪 Metodología: lo que diferencia este análisis

1. **Línea base antes de acusar.** El barrido de comandos WMIC parecía reconocimiento del atacante, pero al comparar todas las cuentas (`dc(command)`, `dc(ip_address)` por usuario) resultó ser actividad de fondo compartida por al menos cinco cuentas. Solo un subconjunto de comandos es exclusivo de la cuenta comprometida.
2. **Hipótesis descartadas con datos.** `june-exec` como segunda cuenta comprometida, `192.168.1.134` como IOC exclusivo y `calc.exe` como prueba de ejecución remota se investigaron y se descartaron con evidencia ([detalle](./TIMELINE.md#hipótesis-investigadas-y-descartadas)).
3. **Distinción entre evidencia, inferencia y contexto externo.** La técnica de acceso inicial y la atribución se tratan como inferencias, no como hechos del log ([ver atribución](./INCIDENT_REPORT.md#4-atribución)).
4. **Inicio del dataset ≠ inicio de la intrusión.** El salto de actividad del 17/03 coincide con el primer día de logs de todas las cuentas, así que no se usa como fecha de compromiso.
5. **Límites de visibilidad declarados.** No se confirma la exfiltración ni el origen del volcado de LSASS, porque los logs disponibles no lo permiten.

---

## 📂 Estructura

```
volt-typhoon-investigation/
├── README.md            ← Este archivo
├── INCIDENT_REPORT.md   ← Informe ejecutivo y técnico
├── TIMELINE.md          ← Cronología detallada por fases
├── IOCs.md              ← Indicadores de compromiso
├── MITRE_MAPPING.md     ← Técnicas ATT&CK con su evidencia
├── SPLUNK_QUERIES.md    ← Queries usadas y propuestas de detección
└── RECOMMENDATIONS.md   ← Detección, hardening y respuesta
```

---

## 🛠️ Habilidades demostradas

- Threat hunting en Splunk: descubrimiento de sourcetypes y campos, filtrado temporal, agregaciones, `rex`, `timechart`.
- Análisis de LOLBins: WMIC, ntdsutil, netsh, wevtutil, certutil, PowerShell.
- Decodificación de comandos PowerShell en base64.
- Separación de ruido y señal mediante líneas base por cuenta.
- Mapeo a MITRE ATT&CK verificado contra la definición de cada técnica.
- Redacción de reglas de detección (SPL y Sigma).

---

## 🎓 Lecciones aprendidas

1. Con Living off the Land, el comando no delata al atacante: lo delata el contexto (qué cuenta, contra qué host, en qué secuencia).
2. Una búsqueda sin resultados no demuestra ausencia: primero hay que confirmar qué sourcetypes y campos existen.
3. Un número solo es anómalo comparado con una línea base.
4. Un IOC estático (una IP) se esquiva fácilmente; un patrón de comportamiento (crear un directorio en `Temp` y copiar o volcar datos poco después) es más resistente.
5. Antes de interpretar un cambio brusco en una serie temporal, hay que comprobar si coincide con el inicio de los datos.

---

## 👤 Autor

**Javier García**
🔗 [LinkedIn](https://www.linkedin.com/in/jvrgs) · 📧 jvrgs98@protonmail.com
🎯 Buscando oportunidades como SOC Analyst L1

---

## 📜 Licencia

MIT. Proyecto con fines educativos basado en la room "Volt Typhoon" de TryHackMe. Todos los indicadores proceden de un entorno de laboratorio.
