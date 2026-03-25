# 🔍 Volt Typhoon APT Investigation

<div align="center">

![TryHackMe](https://img.shields.io/badge/TryHackMe-Volt%20Typhoon-green)
![Splunk](https://img.shields.io/badge/Tool-Splunk-orange)
![MITRE%20ATT%26CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-blue)

**Investigación de una campaña APT simulada del grupo Volt Typhoon**

[📋 Reporte Completo](./INCIDENT_REPORT.md) | 
[📅 Timeline](./TIMELINE.md) | 
[🎯 IOCs](./IOCs.md) | 
[🗺️ MITRE Mapping](./MITRE_MAPPING.md)

</div>

---

## 📌 Resumen Ejecutivo

Esta investigación documenta el análisis forense de una intrusión simulada del grupo APT **Volt Typhoon**, utilizando **Splunk SIEM** para threat hunting y respuesta a incidentes.

### 🎯 Objetivos
- [x] Identificar punto de entrada inicial (Initial Access)
- [x] Rastrear movimiento lateral y persistencia
- [x] Detectar técnicas de credential dumping
- [x] Identificar método de exfiltración y C2
- [x] Mapear todas las técnicas a MITRE ATT&CK
- [x] Proponer controles de detección proactiva

### 🛠️ Herramientas Utilizadas
| Herramienta | Propósito |
|------------|-----------|
| Splunk Enterprise | SIEM - Búsqueda y correlación de logs |
| MITRE ATT&CK Framework | Mapeo de TTPs del atacante |
| CyberChef | Decodificación de comandos Base64 |

---

## 📊 Hallazgos Clave

| Fase | Técnica MITRE | Hallazgo |
|------|--------------|----------|
| Initial Access | T1190 | ADSelfService Plus exploit |
| Persistence | T1136.001, T1505.003 | Cuentas backdoor + web shells |
| Execution | T1047, T1059.001 | WMIC + PowerShell ofuscado |
| Credential Access | T1003.001, T1555 | Mimikatz + NTDS dump |
| C2 | T1090.001 | netsh portproxy → 10.2.30.1:8443 |
| Defense Evasion | T1070.001 | wevtutil cl (4 logs limpiados) |

---

## 🚀 Habilidades Demostradas

- ✅ Threat Hunting con Splunk SPL
- ✅ Análisis forense de logs de Windows
- ✅ Detección de LOLBins (WMIC, netsh, wevtutil)
- ✅ Decodificación de comandos ofuscados (Base64)
- ✅ Mapeo completo a MITRE ATT&CK (18+ técnicas)
- ✅ Documentación profesional de Incident Response
- ✅ Propuesta de reglas de detección proactiva

---

## 📂 Estructura del Repositorio
volt-typhoon-investigation/
├── README.md ← Este archivo
├── INCIDENT_REPORT.md ← Reporte completo de IR
├── TIMELINE.md ← Línea de tiempo detallada
├── IOCs.md ← Indicadores de Compromiso
├── MITRE_MAPPING.md ← Mapeo ATT&CK completo
├── SPLUNK_QUERIES.md ← Queries utilizados
└── RECOMMENDATIONS.md ← Hardening y detección


---

## 🎓 Aprendizaje Clave

> *"Esta investigación demostró la importancia del logging centralizado, la detección proactiva de LOLBins, y la correlación de eventos para reconstruir campañas APT completas."*

### Lecciones Aprendidas
1. Los atacantes APT usan técnicas de "Living Off The Land" para evadir detección
2. La limpieza de logs es un indicador de compromiso en sí mismo
3. La centralización de logs (SIEM) es crítica para IR efectivo
4. El mapeo a MITRE ATT&CK estandariza la comunicación de amenazas

---

## 👤 Autor

**Javier García**  
🔗 [LinkedIn](https://www.linkedin.com/in/jvrgs)  
📧 jvrgs98@protonmail.com
🎯 Buscando oportunidades como: SOC Analyst Jr. / Threat Hunter

---

## 📜 Licencia

Este proyecto es con fines educativos. Basado en la room "Volt Typhoon" de TryHackMe.

---

<div align="center">

**¡Gracias por visitar mi portfolio de ciberseguridad!** 🛡️

[⬆️ Volver arriba](#-volt-typhoon-apt-investigation)

</div>