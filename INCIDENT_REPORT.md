# 📋 Incident Response Report: Volt Typhoon

## Información del Incidente

| Campo | Valor |
|-------|-------|
| **Fecha de Investigación** | 25/03/2026 |
| **Analista** | Javier García |
| **Clasificación** | APT - Intrusión Patrocinada por Estado |
| **Severidad** | CRÍTICA |
| **Herramienta Principal** | Splunk Enterprise |

---

## 📅 Timeline del Ataque

| Timestamp | Fase | Técnica MITRE | Descripción |
|-----------|------|--------------|-------------|
| 2024-03-24T11:10:22 | Initial Access | T1190 | Password reset de dean-admin via ADSelfService Plus |
| 2024-03-24T11:XX:XX | Persistence | T1136.001 | Creación de cuenta voltyp-admin |
| 2024-03-24T11:XX:XX | Persistence | T1136.001 | Creación de cuenta d5ag0nm@5t3r (ofuscada) |
| 2024-03-24T11:XX:XX | Persistence | T1098.003 | Malicious Enrollment en ADSelfService |
| 2024-03-25T23:47:07 | Collection | T1560.001 | Compresión de temp.dit con 7z |
| 2024-03-26T02:02:35 | Defense Evasion | T1036.008 | Renombrado cisco-up.7z → cl64.gif |
| 2024-03-26T02:04:28 | Defense Evasion | T1070.001 | Limpieza de C:\Windows\Temp |
| [Fecha] | C2 | T1090.001 | netsh portproxy → 10.2.30.1:8443 |
| [Fecha] | Defense Evasion | T1070.001 | wevtutil cl (4 logs) |

---

## 🔑 Indicadores de Compromiso (IOCs)

### Cuentas Comprometidas

- dean-admin (comprometida)
- voltyp-admin (backdoor)

### Archivos Maliciosos

- AuditReport.jspx (web shell server-02)
- temp.dit (NTDS dump)
- cl64.gif (archivo exfiltrado ofuscado)

### Comandos Ofensivos

- wmic /node:server01,server02 logicaldisk get...
- ntdsutil "ifm create full"
- PowerShell -E [Base64] → Mimikatz
- netsh interface portproxy add v4tov4
- wevtutil cl Security/System/Application/Setup

### Red

- C2: 10.2.30.1:8443
- Descarga: http://voltyp.com/3/tlz/mimikatz.exe

---

## 🛡️ Recomendaciones de Remediación

### Inmediatas (24-48 horas)
- [ ] Parchear ADSelfService Plus
- [ ] Rotar credenciales KRBTGT (2 veces)
- [ ] Eliminar cuentas backdoor
- [ ] Eliminar web shells de wwwroot

### Corto Plazo (1-2 semanas)
- [ ] Implementar detección para WMIC remoto
- [ ] Habilitar logging centralizado (SIEM)
- [ ] Configurar alertas para wevtutil cl
- [ ] Auditar todas las cuentas privilegiadas

### Largo Plazo (1-3 meses)
- [ ] Implementar LAPS para contraseñas locales
- [ ] Deshabilitar PowerShell v2
- [ ] Configurar retención inmutable de logs
- [ ] Realizar threat hunting proactivo mensual

---

## 📎 Anexos

- [Ver Queries de Splunk](./SPLUNK_QUERIES.md)
- [Ver Mapeo MITRE Completo](./MITRE_MAPPING.md)
- [Ver Recomendaciones Detalladas](./RECOMMENDATIONS.md)