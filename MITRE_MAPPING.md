# 🗺️ MITRE ATT&CK Mapping: Volt Typhoon

## 📊 Resumen Ejecutivo del Mapeo
| Métrica | Valor | 
|Tácticas MITRE Cubiertas| 9 de 14 |
|Técnicas Identificadas|20+|
|Sub-técnicas Específicas|15+|
|LOLBins Detectados|8|
|Nivel de Sofisticación|ALTO (APT State-Sponsored)|

## 🎯 Matriz MITRE ATT&CK - Volt Typhoon
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              MITRE ATT&CK MATRIX - VOLT TYPHOON                         │
├─────────────┬─────────────┬─────────────┬─────────────┬─────────────┬─────────────────┤
│  RECON      │  INITIAL    │  EXECUTION  │  PERSISTENCE│  PRIVILEGE  │  DEFENSE        │
│  (T1592)    │  ACCESS     │             │             │  ESCALATION │  EVASION        │
│             │  T1190      │  T1059.001  │  T1136.001  │             │  T1070.001      │
│             │             │  T1047      │  T1505.003  │             │  T1036.008      │
│             │             │             │  T1098.003  │             │  T1497.001      │
├─────────────┼─────────────┼─────────────┼─────────────┼─────────────┼─────────────────┤
│  CREDENTIAL │  DISCOVERY  │  LATERAL    │  COLLECTION │  C2         │  EXFILTRATION   │
│  ACCESS     │             │  MOVEMENT   │             │             │                 │
│  T1003.003  │  T1082      │  T1021.002  │  T1560.001  │  T1090.001  │  T1567          │
│  T1003.001  │  T1083      │             │  T1213      │  T1071.001  │  T1041          │
│  T1555      │  T1497.001  │             │  T1074.001  │             │                 │
└─────────────┴─────────────┴─────────────┴─────────────┴─────────────┴─────────────────┘

## 📋 Checklist de Hardening Basado en MITRE

✅ [ ] Implementar detección para todas las técnicas T1003.x (Credential Dumping)
✅ [ ] Habilitar PowerShell Script Block Logging y Module Logging
✅ [ ] Configurar alertas para Event ID 1102 (Log Cleared)
✅ [ ] Restringir ejecución de ntdsutil.exe a Domain Controllers
✅ [ ] Monitorear creación de cuentas (Event ID 4720) con nombres sospechosos
✅ [ ] Auditar acceso a administrative shares (C$, ADMIN$)
✅ [ ] Implementar detección para netsh portproxy commands
✅ [ ] Configurar SIEM para correlacionar múltiples técnicas en ventanas cortas
✅ [ ] Parchear aplicaciones web públicas (ADSelfService Plus)
✅ [ ] Implementar LAPS para contraseñas de administrador local

## 🎓 Lecciones Aprendidas del Mapeo

- LOLBins son el mayor desafío: El 100% de herramientas eran legítimas, requiriendo detección basada en comportamiento, no firmas.
- Multi-técnica por fase: Volt Typhoon usó múltiples técnicas por táctica (ej: 3 métodos de credential access), indicando sofisticación y redundancia.
- Defense Evasion al final: La limpieza de logs ocurrió al FINAL del ataque, maximizando el tiempo de operación antes de ser detectado.
- C2 interno: El uso de un proxy interno (10.2.30.1) para C2 hace la detección de tráfico saliente más difícil.
- Mapeo es esencial: Sin MITRE ATT&CK, comunicar estas TTPs a otros equipos sería significativamente más complejo.

<div align="center">

Mapeo MITRE ATT&CK completado como parte de la investigación Volt Typhoon
🗺️ 20+ técnicas mapeadas | 9 tácticas cubiertas | 100% LOLBins
🛡️ Para uso en desarrollo de reglas de detección y mejora de capacidades SOC
</div>
```
