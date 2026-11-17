# 🔎 Queries de Splunk

[⬅️ README](./README.md) · [📅 Timeline](./TIMELINE.md) · [🛡️ Recomendaciones](./RECOMMENDATIONS.md)

> **Datos de la room**
> - Índice: `main`. Sourcetypes disponibles: `adss`, `wmic`, `powershell` (no hay Windows Security, Sysmon, red ni proxy).
> - Campos de `adss`: `username`, `action_name`, `ip_address`, `status`, `access_mode`.
> - Campos de `wmic`: `username`, `command`, `ip_address`, `action`, `result`.
> - En `powershell`, el campo `CommandLine` extraído solo contiene el primer token; para buscar dentro del comando hay que buscar en el texto del evento.
> - Las secciones 1 a 4 contienen queries **ejecutadas durante la investigación**. La sección 5 contiene **propuestas de detección** no validadas en un entorno real.
> - Regla de sintaxis aplicada en todas: paréntesis explícitos al combinar `OR` con otras condiciones (`(sourcetype=a OR sourcetype=b)`).

---

## 1. Metodología: descubrimiento y línea base

**1.1 Qué sourcetypes existen** (antes de filtrar por ninguno)
```spl
index=main
| stats count by sourcetype
```

**1.2 En qué sourcetypes aparece una entidad en una ventana**
```spl
earliest="03/28/2024:00:00:00" latest="03/29/2024:00:00:00" index=main "dean-admin"
| stats count by sourcetype
```

**1.3 Dwell time: actividad diaria de una cuenta**
```spl
earliest="02/22/2024:00:00:00" latest="03/23/2024:00:00:00"
index=main sourcetype=wmic username="dean-admin"
| timechart span=1d count
```
> `timechart` en lugar de `stats count by date_mday`: este último mezcla el mismo día de meses distintos.

**1.4 Línea base de actividad WMIC por cuenta**
```spl
index=main sourcetype=wmic
| stats dc(command) as comandos_distintos, dc(ip_address) as hosts_distintos, count by username
```

**1.5 Comandos exclusivos de una cuenta** (normalizados a su verbo base)
```spl
index=main sourcetype=wmic
| rex field=command "^(?<comando_base>wmic\s+(/node:\S+\s+)?(/user:\S+\s+)?(/password:\S+\s+)?\S+\s+\S+)"
| stats values(username) as usuarios by comando_base
| where mvcount(usuarios)=1 AND usuarios="dean-admin"
```
> Limitación: el patrón exige que tras `/node:` no haya espacio, así que `wmic /node: server-01 ...` y `wmic /node:server01, server02 ...` quedan sin normalizar (aparecen como base propia). Versión corregida, no ejecutada en la room:
> ```spl
> | rex field=command "^wmic\s+(?:/\w+:\s*[^\s,]+(?:,\s*[^\s,]+)*\s+)*(?<comando_base>\S+\s+\S+)"
> ```
> Para verbos de acción (`call create`, `call terminate`, `startservice`) la normalización oculta el argumento, que es lo importante. Para esos se compara el comando completo (1.6).

**1.6 Comandos de acción y quién los ejecuta**
```spl
index=main sourcetype=wmic (command="*call create*" OR command="*call terminate*" OR command="*startservice*" OR command="*stopservice*" OR command="* delete*")
| stats values(username) as usuarios by command
```

**1.7 Línea base de desbloqueos en ADSS**
```spl
earliest="03/17/2024:00:00:00" latest="03/31/2024:00:00:00"
index=main sourcetype=adss action_name="Account Unlock"
| stats count by username
| sort -count
```

**1.8 Uso de una IP por cuentas**
```spl
index=main sourcetype=adss ip_address="192.168.1.134"
| table _time, username, action_name
| sort _time
```

---

## 2. Initial Access y Persistence

**2.1 Toma de control de `dean-admin`**
```spl
index=main sourcetype=adss username="dean-admin" action_name="Password Change"
| table _time, username, action_name, ip_address, status
```

**2.2 Actividad de ADSS el día del compromiso**
```spl
earliest="03/24/2024:00:00:00" latest="03/25/2024:00:00:00" index=main sourcetype=adss
| table _time, username, action_name, ip_address
| sort _time
```

**2.3 Creación de la cuenta backdoor**
```spl
earliest="03/24/2024:00:00:00" latest="03/25/2024:00:00:00" index=main "voltyp-admin"
| table _time, sourcetype, username, action_name, command
| sort _time
```

---

## 3. Credential Access, Collection y Defense Evasion

**3.1 Volcado del NTDS**
```spl
index=main sourcetype=wmic command="*ntdsutil*"
| table _time, username, ip_address, command
```

**3.2 Movimiento lateral con `/node:`**
```spl
index=main sourcetype=wmic command="*/node:*"
| table _time, username, ip_address, command
| sort _time
```

**3.3 Localizar un comando codificado (búsqueda por forma, no por palabra)**
```spl
index=main sourcetype=powershell
| eval longitud=len(_raw)
| sort 10 -longitud
| table _time, longitud, _raw
```

**3.4 Consultas de registro**
```spl
index=main sourcetype=powershell "reg query"
| table _time, _raw
| sort _time
```

**3.5 Entorno virtualizado**
```spl
index=main sourcetype=powershell "Get-ItemProperty" "*Virtual*"
| table _time, _raw
```

**3.6 Borrado del MRU de RDP**
```spl
index=main sourcetype=powershell "Remove-ItemProperty" "MRU"
| table _time, _raw
```

**3.7 Enumeración y borrado de logs con wevtutil**
```spl
index=main "wevtutil"
| table _time, EventID, _raw
| sort _time
```

**3.8 Datos financieros y su posible movimiento posterior**
```spl
index=main ("faudit" OR "FinanceBackup" OR "2022.csv" OR "2023.csv" OR "2024.csv")
| table _time, sourcetype, _raw
| sort _time
```

---

## 4. Web shell y C2

**4.1 Decodificación del web shell**
```spl
index=main "certutil" "-decode"
| table _time, sourcetype, _raw
```

**4.2 Despliegue en server-02**
```spl
index=main sourcetype=powershell "Copy-Item" "server-02"
| table _time, _raw
```

**4.3 Proxy con netsh**
```spl
index=main sourcetype=wmic command="*portproxy*"
| table _time, username, ip_address, command
```

---

## 5. Propuestas de detección

> No validadas fuera de la room (5.1 usa una ventana deslizante con `streamstats` para no partir las ráfagas que cruzan el límite de un intervalo fijo). Los nombres de campo corresponden a este dataset; en un entorno real se adaptarían a Sysmon (EventID 1) o Security 4688 con línea de comandos.

**5.1 Ráfaga de acciones de autogestión en ADSS** (la anomalía real del 24/03 no era la IP, sino la densidad)
```spl
index=main sourcetype=adss
| sort 0 _time
| streamstats time_window=10m count, dc(action_name) as acciones_distintas by username
| where count>=4 AND acciones_distintas>=3
| table _time, username, action_name, count, acciones_distintas
```

**5.2 Registro de MFA poco después de una inscripción**
```spl
index=main sourcetype=adss (action_name="Enrollment" OR action_name="Multi-factor Authentication (MFA) Setup")
| transaction username maxspan=15m startswith=eval(action_name="Enrollment") endswith=eval(action_name="Multi-factor Authentication (MFA) Setup")
| table _time, username, duration
```
> Falsos positivos: en ADSS toda inscripción legítima incluye el alta de MFA. Útil solo combinada con otras señales (cuenta recién creada, cambio de contraseña reciente, ráfaga de 5.1).

**5.3 Directorio de trabajo en Temp seguido de copia, descarga o volcado**
```spl
index=main (sourcetype=powershell OR sourcetype=wmic)
    ((("mkdir" OR "New-Item") "\\Temp\\") OR "Copy-Item" OR "xcopy" OR "Invoke-WebRequest" OR "ntdsutil")
| eval es_dir=if(match(_raw,"(?i)(mkdir|New-Item)"),1,0), es_accion=if(match(_raw,"(?i)(Copy-Item|xcopy|Invoke-WebRequest|ntdsutil)"),1,0)
| sort 0 _time
| streamstats time_window=15m sum(es_dir) as dirs_previos
| where es_accion=1 AND dirs_previos>0
| table _time, sourcetype, _raw
```
> En la room los eventos de PowerShell no tienen un campo de usuario ni de host fiable, así que la ventana es global. En producción se añadiría `by host` (o por usuario) al `streamstats`.

**5.4 LOLBins de alto riesgo**
```spl
index=main (sourcetype=wmic OR sourcetype=powershell) ("ntdsutil" OR "portproxy" OR "wevtutil cl" OR "certutil -decode" OR "sekurlsa")
| table _time, sourcetype, username, _raw
```
> `sekurlsa` solo aparece en texto claro si el comando no va codificado o con Script Block Logging (Event ID 4104). Para comandos codificados, usar la búsqueda por longitud (3.3) o buscar el parámetro `-E` / `-enc`.

**5.5 WMIC remoto con credenciales en claro**
```spl
index=main sourcetype=wmic command="*/node:*" command="*/password*"
| table _time, username, ip_address, command
```
