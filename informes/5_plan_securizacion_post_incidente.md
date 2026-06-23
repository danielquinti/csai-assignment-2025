# Plan de Securización Post-Incidente

**Caso:** Remediación y hardening reactivo del servidor WIN-VNQSUL89MUA  
**Máquina afectada:** Windows Server 2025 — `192.168.56.10`  
**Autor:** Blue Team — Agente de Remediación Post-Incidente  
**Fecha:** 23 de junio de 2026  
**Clasificación:** CONFIDENCIAL  

**Referencias analizadas:**

- [3_informe_forense.md](3_informe_forense.md) — RCA del compromiso del 25/03/2026  
- [2_red_team_audit_report.md](2_red_team_audit_report.md) — Exfiltración JWT vía memoria hypervisor y bypass rate limiting  
- [1_blue_team_instrucciones.txt](1_blue_team_instrucciones.txt) — Hardening previo (`nuke.ps1`, `WinNetSvc`, LOLBins)  
- [3_Restauracion_SSH_MCP_Report.md](3_Restauracion_SSH_MCP_Report.md) — Canal de gestión MCP/SSH restaurado  

> **Nota:** Este documento sustituye al borrador [4_plan_remediacion.md](4_plan_remediacion.md) como plan oficial de securización post-incidente.

---

## 1. Resumen Ejecutivo

El servidor **WIN-VNQSUL89MUA** fue comprometido a través de dos vectores independientes:

1. **Vector físico (25/03/2026):** Acceso interactivo a la consola VirtualBox con credenciales comprometidas del usuario `user2` (LogonType 2). El Red Team desactivó el Firewall de Windows y BitLocker, creó la cuenta backdoor `yishiego` con privilegios de Administrador y forzó un apagado inmediato para destruir evidencia volátil. La configuración Sysmon (`WinNetSvc.xml`) no capturó ningún evento ProcessCreate (ID 1) durante la sesión, exponiendo un punto ciego crítico en la telemetría de consola interactiva.

2. **Vector hypervisor (Red Team Audit):** Extracción del volcado de memoria de la VM mediante `VBoxManage debugvm dumpvmcore` desde el host, análisis con Volatility, recuperación del `SecretKey` JWT en claro y falsificación de token administrativo. Adicionalmente, se detectó bypass del rate limiter de la aplicación mediante cabeceras `X-Forwarded-For` falsificadas.

El hardening perimetral previo (`nuke.ps1`: solo HTTP/HTTPS, SSH eliminado, firewall restrictivo, LOLBins neutralizados) **no mitigó el acceso físico a la consola** ni el vector hypervisor.

Este plan define **15 medidas de hardening avanzado** (MED-01 a MED-15), organizadas en 7 bloques por vector de ataque, con métodos de aplicación nativos de Windows Server 2025. La ausencia de SIEM centralizado (Wazuh) se compensa con un **bucle de autorremediación agéntica vía MCP** (MED-15).

---

## 2. Análisis de Causa Raíz (RCA)

| ID | Debilidad explotada | Evidencia | Técnica MITRE |
|----|---------------------|-----------|---------------|
| INC-01 | Acceso consola VM con credenciales válidas de `user2` | Event ID 4624, LogonType 2, origen `127.0.0.1`, 25/03/2026 | T1078 — Valid Accounts |
| INC-02 | Creación cuenta backdoor `yishiego` + elevación a Administradores | Event 4720 (creación) + 4732 (grupo), 25/03/2026 13:43 | T1136 — Create Account |
| INC-03 | Firewall desactivado con `netsh advfirewall set allprofiles state off` | Historial `ConsoleHost_history.txt`; firewall inactivo hasta recuperación (13 días) | T1562.004 — Disable Firewall |
| INC-04 | BitLocker desactivado con `manage-bde -off C:` | Historial PowerShell | T1486 — Data Encrypted for Impact |
| INC-05 | Punto ciego Sysmon: 0 eventos ProcessCreate (ID 1) en sesión de consola | 2.607 eventos Sysmon el 25/03, ninguno de tipo ID 1 | T1562.001 — Impair Defenses |
| INC-06 | Apagado forzado `shutdown /s /t 0` para destruir evidencia volátil | Event 1100 (log service stopped), 4647 (logout) | T1529 — System Shutdown/Reboot |
| INC-07 | Reversión de LOLBins renombrados a `.bak` para instalar Python fileless | `curl.exe.bak` → `curl.exe`; `tar.exe.bak` → `tar.exe` | T1218 — System Binary Proxy Execution |
| INC-08 | Historial PowerShell en texto claro con contraseña `EstuveAqui.1234` expuesta | `C:\Users\Administrador\...\ConsoleHost_history.txt` (6.496 bytes) | T1059 — Command and Scripting Interpreter |
| INC-09 | Extracción `SecretKey` JWT desde RAM del VM via `VBoxManage debugvm dumpvmcore` + Volatility | Red Team Audit Report — `strings memdump.elf \| grep -i jwt` | T1003.001 — LSASS Memory (análogo) |
| INC-10 | Bypass de rate limiting mediante cabecera `X-Forwarded-For` falsificada | 7 peticiones con IPs distintas sin activar `RATE_LIMIT_EXCEEDED` | T1110.003 — Password Spraying |

---

## 3. Fase 0 — Saneamiento Inmediato (Prerrequisito)

> **IMPORTANTE:** Ejecutar esta fase **antes** de aplicar las medidas MED-01 a MED-15. Preservar el canal de gestión MCP/SSH (puertos 22 y 8000) restringido a la IP del host analista (`192.168.56.1`).

### 3.1 Eliminación de persistencia

```powershell
# Verificar existencia de la cuenta backdoor
Get-LocalUser -Name "yishiego" -ErrorAction SilentlyContinue

# Eliminar cuenta de persistencia
net user yishiego /delete

# Confirmar que no queda en el grupo Administradores
Get-LocalGroupMember -Group "Administradores"
```

### 3.2 Rotación de credenciales comprometidas

```powershell
# Generar contraseña robusta (20 caracteres, complejidad alta)
$nuevaPass = -join ((33..126) | Get-Random -Count 20 | ForEach-Object { [char]$_ })
net user user2 $nuevaPass
Write-Host "[!] Guardar contraseña en gestor seguro fuera de la VM: $nuevaPass" -ForegroundColor Yellow
```

### 3.3 Restauración del Firewall de Windows

```powershell
# 1. Habilitar todos los perfiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# 2. Política restrictiva por defecto
Set-NetFirewallProfile -Profile Domain,Public,Private `
    -DefaultInboundAction Block -DefaultOutboundAction Block

# 3. Reglas explícitas — servicio web + canal de gestión agéntica
New-NetFirewallRule -DisplayName "Allow_HTTP_In"  -Direction Inbound -Protocol TCP -LocalPort 80   -Action Allow -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "Allow_HTTPS_In" -Direction Inbound -Protocol TCP -LocalPort 443  -Action Allow -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "Allow_SSH_MCP"  -Direction Inbound -Protocol TCP -LocalPort 22   -Action Allow -RemoteAddress 192.168.56.1 -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "Allow_MCP_SSE"  -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow -RemoteAddress 192.168.56.1 -ErrorAction SilentlyContinue

# 4. Verificación
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
```

### 3.4 Reactivación de BitLocker

```powershell
# Verificar estado actual
manage-bde -status C:

# Activar cifrado con protector TPM + clave de recuperación (guardar offline)
Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -TpmProtector -UsedSpaceOnly -ErrorAction SilentlyContinue
$recovery = Add-BitLockerKeyProtector -MountPoint "C:" -RecoveryPasswordProtector
Write-Host "[!] Clave de recuperación (guardar fuera de la VM):" -ForegroundColor Yellow
$recovery.KeyProtector.RecoveryPassword

# Verificar progreso
Get-BitLockerVolume -MountPoint "C:" | Select-Object MountPoint, VolumeStatus, EncryptionPercentage, ProtectionStatus
```

### 3.5 Saneamiento de claves SSH autorizadas

```powershell
# Aplicar permisos estrictos OpenSSH (solo Administradores + SYSTEM)
icacls "C:\ProgramData\ssh\administrators_authorized_keys" /inheritance:r /grant "*S-1-5-32-544:F" "SYSTEM:F"
icacls "C:\ProgramData\ssh\administrators_authorized_keys" /setowner "*S-1-5-32-544"

# Calcular hash SHA-256 de referencia (documentar para MED-15)
Get-FileHash "C:\ProgramData\ssh\administrators_authorized_keys" -Algorithm SHA256
```

---

## 4. Matriz de Medidas de Hardening

### Bloque A — Acceso local y credenciales

---

#### MED-01

| Campo | Detalle |
|-------|---------|
| **ID Incidente** | INC-01 |
| **Vector de ataque** | Acceso consola VirtualBox con credenciales válidas de `user2` (LogonType 2) — T1078 |
| **Nueva medida de seguridad** | Política de bloqueo de cuenta agresiva (5 intentos / 30 min), contraseña mínimo 16 caracteres, ocultar el último usuario en la pantalla de logon y exigir Ctrl+Alt+Supr para iniciar sesión |
| **Justificación técnica** | El Red Team accedió directamente a la consola VM, evadiendo el firewall perimetral y SSH eliminado. Reducir el umbral de bloqueo a 5 intentos y no exponer nombres de cuenta dificultan la reutilización de credenciales filtradas o ataques de fuerza bruta en acceso físico |
| **Método de aplicación** | `net accounts` + Registro de Windows |

```powershell
# Política de contraseñas y bloqueo
net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:15
net accounts /minpwlen:16 /maxpwage:90 /minpwage:1

# No revelar el último usuario en la pantalla de logon
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v dontdisplaylastusername /t REG_DWORD /d 1 /f

# Exigir Ctrl+Alt+Supr antes de iniciar sesión (desactiva bypass de pantalla de bloqueo)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DisableCAD /t REG_DWORD /d 0 /f

# Mensaje legal disuasorio en pantalla de logon
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v legalnoticecaption /t REG_SZ /d "ACCESO RESTRINGIDO" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v legalnoticetext /t REG_SZ /d "Sistema de uso exclusivo para personal autorizado. Toda actividad es monitorizada y registrada." /f
```

---

#### MED-02

| Campo | Detalle |
|-------|---------|
| **ID Incidente** | INC-02 |
| **Vector de ataque** | Creación de cuenta backdoor `yishiego` y elevación directa al grupo Administradores — T1136 |
| **Nueva medida de seguridad** | Auditoría avanzada de gestión de cuentas y grupos de seguridad; script de whitelist de administradores locales con alerta en Event Log |
| **Justificación técnica** | `net user` y `net localgroup` generan eventos Security 4720, 4722 y 4732 independientemente de Sysmon. Habilitarlos explícitamente con `auditpol` garantiza telemetría incluso si Sysmon falla, y el script de whitelist permite detección automática de cuentas no autorizadas |
| **Método de aplicación** | `auditpol` (Advanced Audit Policy) + PowerShell |

```powershell
# Habilitar subcategorías de auditoría críticas
auditpol /set /subcategory:"User Account Management"   /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Logon"                     /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon"             /success:enable /failure:enable

# Verificar configuración
auditpol /get /subcategory:"User Account Management"

# Script de whitelist — ejecutar como tarea programada (ver Sección 6)
$allowedAdmins = @("WIN-VNQSUL89MUA\user2")
$currentAdmins = Get-LocalGroupMember -Group "Administradores" |
    Where-Object { $_.ObjectClass -eq "User" } |
    Select-Object -ExpandProperty Name

$rogue = $currentAdmins | Where-Object { $_ -notin $allowedAdmins }
if ($rogue) {
    $msg = "ALERTA: Cuenta(s) no autorizada(s) en Administradores: $($rogue -join ', ')"
    Write-EventLog -LogName Application -Source "SecurityAudit" -EventId 5010 -EntryType Error -Message $msg
    Write-Warning $msg
}
```

---

#### MED-03

| Campo | Detalle |
|-------|---------|
| **ID Incidente** | INC-01 |
| **Vector de ataque** | Credenciales de `user2` conocidas por el Red Team; extracción de secretos LSA desde memoria — T1078 / T1003 |
| **Nueva medida de seguridad** | LSA Protection (RunAsPPL) + Virtualization-Based Security (VBS) con Credential Guard |
| **Justificación técnica** | `RunAsPPL` convierte al proceso `lsass.exe` en Protected Process Light, impidiendo que procesos sin firma Microsoft lean su memoria. Credential Guard aisla las credenciales en una instancia de Hyper-V separada (VSM), inaccesible incluso con privilegios SYSTEM. Ambos controles elevan el coste de extracción de credenciales en el vector hypervisor (INC-09) |
| **Método de aplicación** | Registro de Windows (requiere reinicio) |

```powershell
# LSA Protected Process Light
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f

# Virtualization-Based Security
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity     /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v RequirePlatformSecurityFeatures       /t REG_DWORD /d 1 /f

# Credential Guard
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard" /v Enabled /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard" /v Locked  /t REG_DWORD /d 0 /f

# Verificar tras reinicio:
# Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
Restart-Computer -Confirm
```

---

### Bloque B — Anti-manipulación de controles defensivos

---

#### MED-04

| Campo | Detalle |
|-------|---------|
| **ID Incidente** | INC-03 |
| **Vector de ataque** | Desactivación completa del Firewall de Windows con un único comando `netsh advfirewall set allprofiles state off` — T1562.004 |
| **Nueva medida de seguridad** | Firewall restrictivo con política de denegación por defecto, reglas mínimas explícitas y tarea programada SYSTEM de autorremediación cada 5 minutos |
| **Justificación técnica** | El Red Team desactivó el firewall en la sesión del 25/03 y este permaneció inactivo hasta la recuperación el 07/04 (13 días). La tarea de enforcement como `NT AUTHORITY\SYSTEM` detecta perfiles deshabilitados y los restaura automáticamente, reduciendo el MTTR por debajo de 5 minutos sin necesidad de SIEM |
| **Método de aplicación** | PowerShell + Tarea Programada |

```powershell
# Aplicar política restrictiva
Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block
New-NetFirewallRule -DisplayName "Allow_HTTP_In"  -Direction Inbound -Protocol TCP -LocalPort 80   -Action Allow -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "Allow_HTTPS_In" -Direction Inbound -Protocol TCP -LocalPort 443  -Action Allow -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "Allow_SSH_MCP"  -Direction Inbound -Protocol TCP -LocalPort 22   -Action Allow -RemoteAddress 192.168.56.1 -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "Allow_MCP_SSE"  -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow -RemoteAddress 192.168.56.1 -ErrorAction SilentlyContinue

# Crear script de enforcement
$scriptBlock = @'
$disabled = Get-NetFirewallProfile | Where-Object { $_.Enabled -eq $false }
if ($disabled) {
    Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block
    New-EventLog -LogName Application -Source "Enforce_Firewall" -ErrorAction SilentlyContinue
    Write-EventLog -LogName Application -Source "Enforce_Firewall" -EventId 5001 -EntryType Warning `
        -Message "ALERTA: Firewall reactivado automaticamente. Perfiles deshabilitados: $($disabled.Name -join ', ')"
}
'@
$scriptPath = "C:\Windows\System32\Drivers\en-US\NetworkData\Enforce_Firewall.ps1"
$scriptBlock | Out-File -FilePath $scriptPath -Encoding ASCII -Force

# Registrar tarea programada
$action    = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
$trigger   = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration ([TimeSpan]::MaxValue)
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest
Register-ScheduledTask -TaskName "Enforce_Firewall" -Action $action -Trigger $trigger -Principal $principal -Force
```

---

#### MED-05

| Campo | Detalle |
|-------|---------|
| **ID Incidente** | INC-04 |
| **Vector de ataque** | Desactivación de BitLocker con `manage-bde -off C:`, exponiendo datos del VDI a extracción offline — T1486 |
| **Nueva medida de seguridad** | Re-cifrado BitLocker AES-256 con protector TPM + clave de recuperación offline; ACL restrictiva sobre `manage-bde.exe`; tarea de verificación periódica del estado de cifrado |
| **Justificación técnica** | El Red Team desactivó el cifrado facilitando el acceso posterior al archivo VDI desde el host (`VBoxManage debugvm dumpvmcore`). La ACL impide que sesiones interactivas sin privilegios explícitos ejecuten `manage-bde`; la tarea de verificación detecta desactivaciones no autorizadas |
| **Método de aplicación** | PowerShell + `icacls` + Tarea Programada |

```powershell
# Re-cifrar disco
Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -TpmProtector -UsedSpaceOnly
$rec = Add-BitLockerKeyProtector -MountPoint "C:" -RecoveryPasswordProtector
Write-Host "[!] GUARDAR OFFLINE — Clave de recuperacion: $($rec.KeyProtector.RecoveryPassword)" -ForegroundColor Yellow

# Restringir acceso al binario manage-bde
icacls "C:\Windows\System32\manage-bde.exe" /inheritance:r /grant "SYSTEM:(F)" "BUILTIN\Administrators:(RX)"

# Script de verificación periódica
$blScript = @'
$vol = Get-BitLockerVolume -MountPoint "C:"
if ($vol.ProtectionStatus -ne "On" -or $vol.VolumeStatus -ne "FullyEncrypted") {
    New-EventLog -LogName Application -Source "Enforce_BitLocker" -ErrorAction SilentlyContinue
    Write-EventLog -LogName Application -Source "Enforce_BitLocker" -EventId 5002 -EntryType Warning `
        -Message "ALERTA: BitLocker no activo. Estado: $($vol.ProtectionStatus) / $($vol.VolumeStatus)"
    Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -TpmProtector -UsedSpaceOnly -ErrorAction SilentlyContinue
}
'@
$blScript | Out-File "C:\Windows\System32\Drivers\en-US\NetworkData\Enforce_BitLocker.ps1" -Encoding ASCII -Force

$blAction  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\Windows\System32\Drivers\en-US\NetworkData\Enforce_BitLocker.ps1"
$blTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 15) -RepetitionDuration ([TimeSpan]::MaxValue)
Register-ScheduledTask -TaskName "Enforce_BitLocker" -Action $blAction -Trigger $blTrigger -User "SYSTEM" -RunLevel Highest -Force
```

---

#### MED-06

| Campo | Detalle |
|-------|---------|
| **ID Incidente** | INC-05 |
| **Vector de ataque** | Punto ciego Sysmon: configuración `WinNetSvc.xml` solo monitorizaba hijos de `w3wp.exe` (IIS), generando 0 eventos ProcessCreate (ID 1) durante la sesión de consola del 25/03/2026 |
| **Nueva medida de seguridad** | Ampliación de `WinNetSvc.xml` con reglas ProcessCreate para shells interactivas, herramientas de gestión críticas y detección de comandos de degradación de defensas |
| **Justificación técnica** | El Red Team ejecutó `netsh`, `manage-bde`, `net user`, `net localgroup` y `shutdown` sin generar un solo evento de proceso. Las nuevas reglas capturan cualquier ejecución de estas herramientas independientemente del proceso padre, cerrando el punto ciego de consola interactiva |
| **Método de aplicación** | XML Sysmon + PowerShell (ver Sección 5 para el XML completo) |

```powershell
# Recargar Sysmon con la nueva configuración (ver Sección 5)
$xmlPath = "C:\Windows\System32\Drivers\en-US\NetworkData\WinNetSvc.xml"
C:\Windows\WinNetSvc.exe -c $xmlPath
Write-Host "[+] Sysmon recargado con reglas de consola interactiva" -ForegroundColor Green

# Validar: lanzar un comando y verificar que genera evento ID 1
cmd /c whoami
Start-Sleep -Seconds 2
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 |
    Where-Object { $_.Id -eq 1 } |
    Select-Object TimeCreated, Message
```

---

### Bloque C — Contención de herramientas nativas (LOLBins)

---

#### MED-07

| Campo | Detalle |
|-------|---------|
| **ID Incidente** | INC-07 |
| **Vector de ataque** | Reversión de LOLBins renombrados a `.bak` (`curl.exe.bak`, `tar.exe.bak`) para descargar e instalar Python 3.12 fileless, evadiendo la táctica "tierra quemada" — T1218 |
| **Nueva medida de seguridad** | Permisos NTFS de solo lectura sobre archivos `.bak` en System32; AppLocker con reglas de denegación para `net.exe`, `netsh.exe`, `reg.exe` y `manage-bde.exe` para usuarios interactivos |
| **Justificación técnica** | El Red Team copió binarios desde `.bak` al directorio `%TEMP%` para evadir el renombrado. La ACL de solo lectura impide la copia sin privilegios SYSTEM; AppLocker bloquea la ejecución de las herramientas de administración más peligrosas desde sesiones interactivas |
| **Método de aplicación** | `icacls` + AppLocker (GPO local) |

```powershell
# ACL restrictiva sobre archivos .bak en System32
Get-ChildItem "C:\Windows\System32\*.bak" -ErrorAction SilentlyContinue | ForEach-Object {
    icacls $_.FullName /inheritance:r /grant "SYSTEM:(F)" "BUILTIN\Administrators:(R)"
    Write-Host "[+] ACL aplicada: $($_.Name)" -ForegroundColor Green
}

# Habilitar servicio AppLocker
Set-Service AppIDSvc -StartupType Automatic
Start-Service AppIDSvc -ErrorAction SilentlyContinue

# Crear directorio de políticas AppLocker y aplicar política XML completa
$applockerDir = "$env:SystemRoot\System32\AppLocker"
New-Item -ItemType Directory -Path $applockerDir -Force | Out-Null

$applockerXml = @"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="11111111-0000-0000-0000-000000000001" Name="Allow Administrators" Description="" UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions><FilePathCondition Path="*"/></Conditions>
    </FilePathRule>
    <FilePathRule Id="11111111-0000-0000-0000-000000000002" Name="Allow SYSTEM" Description="" UserOrGroupSid="S-1-5-18" Action="Allow">
      <Conditions><FilePathCondition Path="*"/></Conditions>
    </FilePathRule>
    <FilePathRule Id="99999999-0001-0001-0001-000000000001" Name="Deny net.exe - Everyone" Description="Bloquear creacion de cuentas" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions><FilePathCondition Path="%SYSTEM32%\net.exe"/></Conditions>
    </FilePathRule>
    <FilePathRule Id="99999999-0001-0001-0001-000000000002" Name="Deny netsh.exe - Everyone" Description="Bloquear modificacion firewall" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions><FilePathCondition Path="%SYSTEM32%\netsh.exe"/></Conditions>
    </FilePathRule>
    <FilePathRule Id="99999999-0001-0001-0001-000000000003" Name="Deny manage-bde.exe - Everyone" Description="Bloquear gestion BitLocker" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions><FilePathCondition Path="%SYSTEM32%\manage-bde.exe"/></Conditions>
    </FilePathRule>
    <FilePathRule Id="99999999-0001-0001-0001-000000000004" Name="Deny reg.exe - Everyone" Description="Bloquear edicion registro" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions><FilePathCondition Path="%SYSTEM32%\reg.exe"/></Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
"@
$applockerXml | Out-File "$applockerDir\Policy.xml" -Encoding Unicode -Force
Set-AppLockerPolicy -XmlPolicy "$applockerDir\Policy.xml" -ErrorAction SilentlyContinue
gpupdate /force
```

---

#### MED-08

| Campo | Detalle |
|-------|---------|
| **ID Incidente** | INC-08 |
| **Vector de ataque** | Historial PowerShell (`ConsoleHost_history.txt`) almacenado en texto claro expuso la contraseña de la cuenta backdoor `yishiego` (`EstuveAqui.1234`) — T1059 |
| **Nueva medida de seguridad** | Deshabilitar la persistencia de historial PSReadLine; habilitar Script Block Logging y Module Logging a nivel de máquina como telemetría forense alternativa |
| **Justificación técnica** | El historial de texto plano es un artefacto forense bidireccional: beneficia al defensor pero también expone operaciones del atacante si este no lo limpia. Script Block Logging captura comandos ejecutados en el Event Log (Microsoft-Windows-PowerShell/Operational, ID 4104), que es más difícil de eliminar silenciosamente que un archivo de perfil |
| **Método de aplicación** | Registro de Windows (equivalente a GPO) |

```powershell
# Deshabilitar persistencia de historial PSReadLine (perfil de máquina)
if (-not (Test-Path $PROFILE.AllUsersAllHosts)) {
    New-Item -Path $PROFILE.AllUsersAllHosts -ItemType File -Force | Out-Null
}
Add-Content -Path $PROFILE.AllUsersAllHosts -Value "`nSet-PSReadLineOption -HistorySaveStyle SaveNothing"

# Script Block Logging (captura todo el código PowerShell ejecutado — Event ID 4104)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging           /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockInvocationLogging /t REG_DWORD /d 1 /f

# Module Logging (registra todos los módulos y cmdlets usados — Event ID 4103)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" /v * /t REG_SZ /d * /f

# Eliminar historial existente de todos los perfiles de usuario
Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -ErrorAction SilentlyContinue |
    Remove-Item -Force -ErrorAction SilentlyContinue
Write-Host "[+] Historial PowerShell eliminado y logging habilitado" -ForegroundColor Green
```

---

### Bloque D — Evasión forense y disponibilidad

---

#### MED-09

| Campo | Detalle |
|-------|---------|
| **ID Incidente** | INC-06 |
| **Vector de ataque** | Apagado inmediato del sistema con `shutdown /s /t 0` para destruir evidencia volátil (RAM, conexiones de red, procesos) — T1529 |
| **Nueva medida de seguridad** | Auditoría de eventos de apagado; restricción de `SeShutdownPrivilege`; tarea de monitorización post-arranque para correlacionar reinicios con sesiones interactivas recientes |
| **Justificación técnica** | Los eventos 1074/6006/6008 registran apagados con causa y usuario responsable. Restringir `SeShutdownPrivilege` a cuentas de servicio del sistema (no a cuentas interactivas) añade una capa de control; la tarea `BootMonitor` correlaciona reinicios inesperados con logons LogonType 2 previos y genera alerta en Application Log |
| **Método de aplicación** | `auditpol` + `secedit` + Tarea Programada |

```powershell
# Auditoría de apagados
auditpol /set /subcategory:"System Shutdown"    /success:enable /failure:enable
auditpol /set /subcategory:"Other System Events" /success:enable /failure:enable

# Exportar política de derechos de usuario y verificar SeShutdownPrivilege
secedit /export /cfg C:\sec_shutdown.cfg
# La línea debe quedar: SeShutdownPrivilege = *S-1-5-32-544 (solo grupo Administradores)
# Ajustar manualmente si hay cuentas individuales adicionales y reimportar:
# secedit /configure /db C:\secedit.sdb /cfg C:\sec_shutdown.cfg /areas USER_RIGHTS
Remove-Item C:\sec_shutdown.cfg -Force -ErrorAction SilentlyContinue

# Tarea de monitorización post-arranque
$bootScript = @'
Start-Sleep -Seconds 30
$lastBoot     = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$recentLogons = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=$lastBoot.AddMinutes(-20)} -ErrorAction SilentlyContinue |
    Where-Object { $_.Properties[8].Value -eq 2 }
if ($recentLogons) {
    New-EventLog -LogName Application -Source "BootMonitor" -ErrorAction SilentlyContinue
    Write-EventLog -LogName Application -Source "BootMonitor" -EventId 5003 -EntryType Warning `
        -Message "ALERTA: Sistema reiniciado tras sesion interactiva reciente (LogonType 2). Posible anti-forensics."
}
'@
$bootScript | Out-File "C:\Windows\System32\Drivers\en-US\NetworkData\BootMonitor.ps1" -Encoding ASCII -Force
Register-ScheduledTask -TaskName "BootMonitor" `
    -Action    (New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\Windows\System32\Drivers\en-US\NetworkData\BootMonitor.ps1") `
    -Trigger   (New-ScheduledTaskTrigger -AtStartup) `
    -User      "SYSTEM" `
    -RunLevel  Highest `
    -Force
```

---

### Bloque E — Capa hypervisor y host

---

#### MED-10

| Campo | Detalle |
|-------|---------|
| **ID Incidente** | INC-09 |
| **Vector de ataque** | Extracción del volcado completo de memoria de la VM mediante `VBoxManage debugvm WIN-VNQSUL89MUA dumpvmcore --filename memdump.elf` desde el host — T1003.001 |
| **Nueva medida de seguridad** | Deshabilitar clipboard y Drag-and-Drop bidireccional en VirtualBox; restringir ACL del binario `VBoxManage.exe` a Administradores del host; habilitar VBS/HVCI en el host Windows |
| **Justificación técnica** | El TCB (Trusted Computing Base) incluye el hypervisor: todo el hardening del guest es ineficaz si el host puede volcar la RAM del VM. Restringir `VBoxManage.exe` impide que usuarios sin privilegios generen volcados; VBS/HVCI en el host eleva el coste de compromiso del hypervisor |
| **Método de aplicación** | `VBoxManage` (host) + `icacls` (host) + Registro (host) |

```powershell
# Ejecutar en el HOST Windows (no en la VM)

# Deshabilitar canales de comunicación VM-Host
$vbox   = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
$vmName = "WIN-VNQSUL89MUA"  # Ajustar al nombre exacto en VirtualBox
& $vbox modifyvm $vmName --clipboard-mode  disabled
& $vbox modifyvm $vmName --draganddrop     disabled
& $vbox modifyvm $vmName --vrde            off

# Restringir ejecución de VBoxManage a Administradores del host
icacls $vbox /inheritance:r /grant "BUILTIN\Administrators:(RX)" "SYSTEM:(F)"
icacls $vbox /deny "BUILTIN\Users:(X)"

# Habilitar VBS/HVCI en el host (requiere reinicio del host)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 1 /f
```

---

#### MED-11

| Campo | Detalle |
|-------|---------|
| **ID Incidente** | INC-09 |
| **Vector de ataque** | Secreto JWT (`SecretKey`) residente en memoria del worker IIS (`w3wp.exe`) y extraíble con Volatility desde el volcado de RAM — T1552 |
| **Nueva medida de seguridad** | Rotación inmediata del `SecretKey` JWT con entropía de 256 bits; almacenamiento protegido mediante DPAPI (scope `LocalMachine`); reinicio del Application Pool para invalidar todos los tokens forjados |
| **Justificación técnica** | Volatility localizó el `SecretKey` como cadena de texto plano en el heap del proceso. DPAPI ata el secreto al contexto criptográfico de la máquina, por lo que la **clave de larga duración** en disco queda cifrada e inusable desde otro sistema aunque se extraiga el VDI |
| **Método de aplicación** | PowerShell (guest — VM) |

```powershell
# Generar nuevo SecretKey de 256 bits de entropía
Add-Type -AssemblyName System.Security
$bytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$plainSecret = [Convert]::ToBase64String($bytes)

# Cifrar con DPAPI (LocalMachine scope — no portable entre máquinas)
$protected = [Security.Cryptography.ProtectedData]::Protect(
    [Text.Encoding]::UTF8.GetBytes($plainSecret),
    $null,
    [Security.Cryptography.DataProtectionScope]::LocalMachine
)

# Persistir el secreto como variable de entorno de máquina
[Environment]::SetEnvironmentVariable("Jwt__SecretKey", $plainSecret, "Machine")
Write-Host "[!] SecretKey rotado. Todos los JWT anteriores quedan INVALIDADOS." -ForegroundColor Yellow

# Reiniciar AppPool para recargar la variable de entorno
Import-Module WebAdministration
Restart-WebAppPool -Name "SecureCatalogPool"
Write-Host "[+] AppPool SecureCatalogPool reiniciado" -ForegroundColor Green
```

---

### Bloque F — Capa aplicación web

---

#### MED-12

| Campo | Detalle |
|-------|---------|
| **ID Incidente** | INC-10 |
| **Vector de ataque** | Bypass del rate limiter de la aplicación falsificando la cabecera `X-Forwarded-For` con IPs distintas por petición — T1110.003 |
| **Nueva medida de seguridad** | Reconfigurar el rate limiter de ASP.NET Core para particionar exclusivamente por `HttpContext.Connection.RemoteIpAddress`; eliminar toda confianza en `X-Forwarded-For` al no existir proxy reverso de confianza |
| **Justificación técnica** | El Red Team envió 7 peticiones con IPs falsificadas en `X-Forwarded-For` sin activar `RATE_LIMIT_EXCEEDED`. En este despliegue IIS directamente expuesto (sin NGINX/HAProxy delante), la IP de conexión TCP real (`RemoteIpAddress`) es el único identificador de cliente verificable e inmanipulable desde el exterior |
| **Método de aplicación** | Código C# — `Program.cs` de SecureCatalog |

```csharp
// En Program.cs — reemplazar la configuración del rate limiter:

// INCORRECTO (vulnerable a X-Forwarded-For spoofing):
// var clientIp = context.Request.Headers["X-Forwarded-For"].FirstOrDefault()
//     ?? context.Connection.RemoteIpAddress?.ToString();

// CORRECTO — usar SOLO la IP de la conexión TCP subyacente:
builder.Services.AddRateLimiter(options =>
{
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
    {
        // RemoteIpAddress es la IP de la conexión TCP real, inmanipulable desde cabeceras HTTP
        var remoteIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        return RateLimitPartition.GetFixedWindowLimiter(remoteIp, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit    = 10,
            Window         = TimeSpan.FromMinutes(5),
            QueueLimit     = 0,
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst
        });
    });
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
});

// NO añadir app.UseForwardedHeaders() sin configurar KnownProxies explícitamente.
```

---

#### MED-13

| Campo | Detalle |
|-------|---------|
| **ID Incidente** | (Hardening proactivo — superficie criptográfica) |
| **Vector de ataque** | TLS 1.0 y TLS 1.1 potencialmente habilitados en SCHANNEL, exponiendo la única superficie de red visible (puerto 443) a ataques POODLE y BEAST — T1557 |
| **Nueva medida de seguridad** | Deshabilitar TLS 1.0 y TLS 1.1 en SCHANNEL; forzar exclusivamente TLS 1.2 y TLS 1.3 |
| **Justificación técnica** | Reduce la superficie criptográfica débil en el único servicio expuesto en red. TLS 1.3 elimina la negociación de cipher suites débiles y proporciona Perfect Forward Secrecy obligatorio |
| **Método de aplicación** | Registro de Windows |

```powershell
# Deshabilitar protocolos legacy
foreach ($ver in @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")) {
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$ver\Server"
    New-Item -Path $path -Force | Out-Null
    New-ItemProperty -Path $path -Name "Enabled"           -Value 0 -PropertyType DWord -Force
    New-ItemProperty -Path $path -Name "DisabledByDefault"  -Value 1 -PropertyType DWord -Force
}

# Habilitar protocolos modernos
foreach ($ver in @("TLS 1.2", "TLS 1.3")) {
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$ver\Server"
    New-Item -Path $path -Force | Out-Null
    New-ItemProperty -Path $path -Name "Enabled"           -Value 1 -PropertyType DWord -Force
    New-ItemProperty -Path $path -Name "DisabledByDefault"  -Value 0 -PropertyType DWord -Force
}

# Aplicar cambios (requiere reinicio de IIS)
iisreset /restart
Write-Host "[+] SCHANNEL configurado: solo TLS 1.2 y TLS 1.3" -ForegroundColor Green
```

---

### Bloque G — Canal de gestión MCP/SSH

---

#### MED-14

| Campo | Detalle |
|-------|---------|
| **ID Incidente** | INC-11 (post-restauración) |
| **Vector de ataque** | Canal SSH restaurado con autenticación por contraseña habilitada; puerto 8000 abierto sin restricción de IP; credenciales de `user2` conocidas por el Red Team |
| **Nueva medida de seguridad** | SSH solo por clave pública (`PasswordAuthentication no`); shell `cmd.exe` como shell por defecto de SSH para transporte MCP sin BOM; reglas de firewall SSH y MCP restringidas exclusivamente a `192.168.56.1` |
| **Justificación técnica** | El informe de restauración documenta que el Red Team cambió la contraseña de `user2` y configura claves autorizadas. Deshabilitar la autenticación por contraseña elimina la reutilización de credenciales filtradas; `cmd.exe` como shell evita que PowerShell inyecte marcas BOM en el stream stdio del protocolo MCP JSON-RPC |
| **Método de aplicación** | Registro de Windows + edición de `sshd_config` + PowerShell |

```powershell
# Shell limpia para transporte MCP (cmd.exe no inyecta BOM en stdio)
reg add "HKLM\SOFTWARE\OpenSSH" /v DefaultShell /d "C:\Windows\System32\cmd.exe" /f

# Deshabilitar autenticación por contraseña en sshd_config
$cfg = "C:\ProgramData\ssh\sshd_config"
$content = Get-Content $cfg
$content = $content -replace '^#?PasswordAuthentication.*',   'PasswordAuthentication no'
$content = $content -replace '^#?PubkeyAuthentication.*',     'PubkeyAuthentication yes'
$content = $content -replace '^#?PermitEmptyPasswords.*',     'PermitEmptyPasswords no'
$content = $content -replace '^#?PermitRootLogin.*',          'PermitRootLogin no'
$content | Set-Content $cfg -Encoding UTF8

# Asegurar que el bloque Match Group administrators está descomentado
if ($content -notmatch '^Match Group administrators') {
    Add-Content $cfg "`nMatch Group administrators`n    AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys"
}

# Permisos NTFS estrictos sobre authorized_keys (requisito OpenSSH)
icacls "C:\ProgramData\ssh\administrators_authorized_keys" /inheritance:r /grant "*S-1-5-32-544:F" "SYSTEM:F"
icacls "C:\ProgramData\ssh\administrators_authorized_keys" /setowner "*S-1-5-32-544"

# Restringir reglas de firewall a IP del host analista
Set-NetFirewallRule -DisplayName "Allow_SSH_MCP" -RemoteAddress 192.168.56.1 -ErrorAction SilentlyContinue
Set-NetFirewallRule -DisplayName "Allow_MCP_SSE" -RemoteAddress 192.168.56.1 -ErrorAction SilentlyContinue

# Reiniciar servicio SSH
Restart-Service sshd
Write-Host "[+] SSH configurado: solo clave publica, restringido a 192.168.56.1" -ForegroundColor Green
```

---

#### MED-15

| Campo | Detalle |
|-------|---------|
| **ID Incidente** | INC-12 (ausencia de SIEM centralizado) |
| **Vector de ataque** | Degradación silenciosa de controles defensivos sin mecanismo de alerta centralizado (Wazuh no disponible) |
| **Nueva medida de seguridad** | Bucle cerrado de autorremediación agéntica vía MCP: servidor Python con 4 herramientas de auditoría y corrección automática |
| **Justificación técnica** | Sin SIEM, las alteraciones de controles (firewall desactivado, cuenta nueva en Administradores) pueden pasar desapercibidas días o semanas. El servidor MCP expone herramientas atómicas que el agente IA consume para detectar desviaciones del baseline y revertirlas en caliente, reduciendo el MTTR objetivo por debajo de 5 minutos |
| **Método de aplicación** | Servidor MCP Python (`C:\Python312\mcp_server.py`) + Tarea programada (ver Sección 6) |

---

## 5. Configuración Sysmon — Reglas de Consola Interactiva (MED-06)

Integrar el siguiente bloque **dentro** de `<EventFiltering>` en `C:\Windows\System32\Drivers\en-US\NetworkData\WinNetSvc.xml`, antes del cierre `</EventFiltering>`:

```xml
<!--
  ===================================================================
    RULE GROUP: CONSOLA INTERACTIVA (Post-Incidente MED-06)
    Cierra el punto ciego: ProcessCreate en sesiones LogonType 2.
    Binarios exactos usados por el Red Team el 25/03/2026.
  ===================================================================
-->
<RuleGroup name="ConsolaInteractiva" groupRelation="or">
  <ProcessCreate onmatch="include">

    <!-- Shells como proceso lanzado o como proceso padre -->
    <Image condition="image">powershell.exe</Image>
    <Image condition="image">cmd.exe</Image>
    <Image condition="image">pwsh.exe</Image>
    <ParentImage condition="image">powershell.exe</ParentImage>
    <ParentImage condition="image">cmd.exe</ParentImage>
    <ParentImage condition="image">pwsh.exe</ParentImage>

    <!-- Motores de script Windows -->
    <Image condition="image">wscript.exe</Image>
    <Image condition="image">cscript.exe</Image>

    <!-- Herramientas usadas en el ataque confirmado -->
    <Image condition="image">net.exe</Image>
    <Image condition="image">net1.exe</Image>
    <Image condition="image">netsh.exe</Image>
    <OriginalFileName condition="is">manage-bde.exe</OriginalFileName>
    <OriginalFileName condition="is">shutdown.exe</OriginalFileName>
    <OriginalFileName condition="is">reg.exe</OriginalFileName>
    <OriginalFileName condition="is">sc.exe</OriginalFileName>
    <OriginalFileName condition="is">whoami.exe</OriginalFileName>

  </ProcessCreate>
</RuleGroup>

<!--
  ===================================================================
    RULE GROUP: MANIPULACION DE DEFENSAS (Post-Incidente MED-06)
    Detectar comandos de degradación de controles de seguridad
    independientemente del proceso que los lanza.
  ===================================================================
-->
<RuleGroup name="DefensaDegradada" groupRelation="or">
  <ProcessCreate onmatch="include">
    <CommandLine condition="contains">advfirewall set</CommandLine>
    <CommandLine condition="contains">firewall set rule</CommandLine>
    <CommandLine condition="contains">manage-bde -off</CommandLine>
    <CommandLine condition="contains">manage-bde -pause</CommandLine>
    <CommandLine condition="contains">manage-bde -disable</CommandLine>
    <CommandLine condition="contains">net user</CommandLine>
    <CommandLine condition="contains">net localgroup</CommandLine>
    <CommandLine condition="contains">shutdown /s</CommandLine>
    <CommandLine condition="contains">wevtutil cl</CommandLine>
    <CommandLine condition="contains">wevtutil clear-log</CommandLine>
    <CommandLine condition="contains">auditpol /clear</CommandLine>
  </ProcessCreate>
</RuleGroup>
```

**Aplicar y validar:**

```powershell
$xmlPath = "C:\Windows\System32\Drivers\en-US\NetworkData\WinNetSvc.xml"
C:\Windows\WinNetSvc.exe -c $xmlPath

# Test: ejecutar net.exe sin argumentos y verificar que genera ID 1
net.exe 2>$null
Start-Sleep -Seconds 2
$testEvent = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -eq 1 -and $_.TimeCreated -gt (Get-Date).AddSeconds(-10) }

if ($testEvent) {
    Write-Host "[+] VALIDADO: Sysmon captura ProcessCreate en consola" -ForegroundColor Green
} else {
    Write-Warning "[!] No se detectaron eventos ID 1. Revisar WinNetSvc.xml"
}
```

---

## 6. Playbook MCP de Autorremediación (MED-15)

### 6.1 Arquitectura del bucle cerrado

```
  [ Agente IA Defensivo (Host Cursor) ]
                  │
        JSON-RPC / SSH (puerto 22)
        o SSE (puerto 8000, contingencia)
                  ▼
        [ Servidor MCP — C:\Python312\mcp_server.py ]
                  │
    ┌─────────────┼─────────────┬─────────────┐
    ▼             ▼             ▼             ▼
check_local   enforce_     enforce_      audit_ssh
  _users      firewall     bitlocker        _keys
```

> **Preservación del canal:** Nunca bloquear los puertos 22/8000 desde la IP `192.168.56.1` ni vaciar `administrators_authorized_keys` sin mantener la clave del agente MCP.

### 6.2 Implementación del servidor MCP ampliado

Desplegar en `C:\Python312\mcp_server.py`:

```python
import hashlib
import subprocess
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("WindowsCommander")

# --- Configuración de referencia (ajustar tras Fase 0) ---
ALLOWED_ADMINS = {"WIN-VNQSUL89MUA\\user2"}
AUTHORIZED_KEYS_PATH = r"C:\ProgramData\ssh\administrators_authorized_keys"
AUTHORIZED_KEYS_SHA256 = "REEMPLAZAR_CON_HASH_FASE_0"  # Get-FileHash -Algorithm SHA256
HOST_ANALYST_IP = "192.168.56.1"


def _run_ps(cmd: str) -> str:
    r = subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd],
        capture_output=True, text=True,
    )
    return r.stdout + r.stderr


@mcp.tool()
def check_local_users() -> str:
    """Audita miembros del grupo Administradores contra whitelist. Elimina cuentas no autorizadas."""
    members = _run_ps(
        "Get-LocalGroupMember -Group 'Administradores' | Select-Object -ExpandProperty Name"
    ).strip().splitlines()
    rogue = [m for m in members if m.strip() not in ALLOWED_ADMINS]
    removed = []
    for user in rogue:
        _run_ps(f'Remove-LocalGroupMember -Group "Administradores" -Member "{user}" -ErrorAction SilentlyContinue')
        _run_ps(f'Remove-LocalUser -Name "{user}" -ErrorAction SilentlyContinue')
        removed.append(user)
    if removed:
        return f"ALERTA: Eliminadas cuentas no autorizadas: {', '.join(removed)}"
    return f"OK: Administradores conformes: {', '.join(members)}"


@mcp.tool()
def enforce_firewall() -> str:
    """Verifica y reactiva el firewall si está deshabilitado. Restaura reglas base."""
    status = _run_ps("Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json")
    if "false" in status.lower():
        _run_ps("Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block")
        _run_ps('New-NetFirewallRule -DisplayName "Allow_HTTP_In"  -Direction Inbound -Protocol TCP -LocalPort 80  -Action Allow -ErrorAction SilentlyContinue')
        _run_ps('New-NetFirewallRule -DisplayName "Allow_HTTPS_In" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow -ErrorAction SilentlyContinue')
        _run_ps(f'New-NetFirewallRule -DisplayName "Allow_SSH_MCP" -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow -RemoteAddress {HOST_ANALYST_IP} -ErrorAction SilentlyContinue')
        _run_ps(f'New-NetFirewallRule -DisplayName "Allow_MCP_SSE" -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow -RemoteAddress {HOST_ANALYST_IP} -ErrorAction SilentlyContinue')
        return "REMEDIADO: Firewall reactivado y reglas restauradas"
    return "OK: Firewall activo en todos los perfiles"


@mcp.tool()
def enforce_bitlocker() -> str:
    """Audita BitLocker en C: y reinicia cifrado si está desactivado o pausado."""
    status = _run_ps("(Get-BitLockerVolume -MountPoint 'C:').ProtectionStatus")
    if "On" not in status:
        _run_ps("Enable-BitLocker -MountPoint 'C:' -EncryptionMethod Aes256 -TpmProtector -UsedSpaceOnly -ErrorAction SilentlyContinue")
        return "REMEDIADO: BitLocker reactivado en C:"
    return "OK: BitLocker ProtectionStatus = On"


@mcp.tool()
def audit_ssh_keys() -> str:
    """Compara SHA-256 de administrators_authorized_keys con el valor de referencia."""
    try:
        with open(AUTHORIZED_KEYS_PATH, "rb") as f:
            current = hashlib.sha256(f.read()).hexdigest()
        if current != AUTHORIZED_KEYS_SHA256:
            return f"ALERTA: Hash de claves SSH alterado. Actual: {current}"
        return f"OK: Hash SSH conforme ({current[:16]}...)"
    except FileNotFoundError:
        return "ALERTA: administrators_authorized_keys no encontrado"


@mcp.tool()
def ejecutar_comando_powershell(comando: str) -> str:
    """Ejecuta un comando PowerShell y devuelve el resultado (uso operativo del agente)."""
    return _run_ps(comando)


if __name__ == "__main__":
    mcp.run(transport="stdio")
```

### 6.3 Tabla de herramientas y lógica de autorremediación

| Herramienta MCP | Acción del agente | Lógica de autorremediación | Frecuencia |
|-----------------|-------------------|----------------------------|------------|
| `check_local_users` | Compara administradores locales con whitelist `{user2}` | Elimina cuentas fuera de lista (ej. `yishiego`) | Diaria + tras evento 4720 |
| `enforce_firewall` | Verifica `Enabled` en los 3 perfiles | Reactiva firewall y restaura reglas HTTP/HTTPS/SSH/MCP | Cada 5 min (tarea) + bajo demanda |
| `enforce_bitlocker` | Audita `ProtectionStatus` de `C:` | Reinicia cifrado si está Off o pausado | Cada 15 min (tarea) + bajo demanda |
| `audit_ssh_keys` | Calcula SHA-256 de `administrators_authorized_keys` | Alerta si el hash difiere del valor de referencia de Fase 0 | Diaria |

### 6.4 Tarea programada de auditoría agéntica

```powershell
# Script de auditoría local (complementa el bucle MCP remoto)
$auditScript = @'
$log = "C:\Windows\System32\Config\TxR\Diagnostics\mcp_audit.log"
$ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Disparar verificación tras logon interactivo (4624 LogonType 2)
$recentLogon = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddMinutes(-5)} -ErrorAction SilentlyContinue |
    Where-Object { $_.Properties[8].Value -eq 2 }
if ($recentLogon) {
    "[$ts] ALERTA: Logon interactivo detectado — requiere auditoría MCP" | Out-File $log -Append -Encoding ASCII
}

# Verificación local de controles críticos (sin MCP)
$fw = (Get-NetFirewallProfile | Where-Object { $_.Enabled -eq $false }).Count
$bl = (Get-BitLockerVolume -MountPoint "C:").ProtectionStatus
"[$ts] Firewall_disabled_profiles=$fw BitLocker=$bl" | Out-File $log -Append -Encoding ASCII
'@
$auditScript | Out-File "C:\Windows\System32\Drivers\en-US\NetworkData\MCP_AuditTrigger.ps1" -Encoding ASCII -Force

Register-ScheduledTask -TaskName "MCP_AuditTrigger" `
    -Action  (New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -File C:\Windows\System32\Drivers\en-US\NetworkData\MCP_AuditTrigger.ps1") `
    -Trigger (New-ScheduledTaskTrigger -Daily -At "00:00" -RepetitionInterval (New-TimeSpan -Hours 1)) `
    -User    "SYSTEM" -RunLevel Highest -Force
```

### 6.5 Configuración del cliente MCP en el host (Cursor)

```json
{
  "mcpServers": {
    "windows-vm-remediation": {
      "command": "C:\\Windows\\System32\\OpenSSH\\ssh.exe",
      "args": [
        "-i", "C:\\Users\\<usuario>\\.ssh\\id_ed25519",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        "user2@192.168.56.10",
        "C:\\Python312\\python.exe",
        "C:\\Python312\\mcp_server.py"
      ]
    }
  }
}
```

---

## 7. Orden de Implementación

| Fase | Día | Medidas | Acciones |
|------|-----|---------|----------|
| **0** | Día 0 (inmediato) | Fase 0 | Eliminar `yishiego`, rotar `user2`, restaurar firewall y BitLocker |
| **1** | Día 0 | MED-01, MED-02, MED-04, MED-05 | Postura mínima operativa |
| **2** | Día 1 | MED-06, MED-08, MED-09 | Telemetría y anti-forensics |
| **3** | Día 2 | MED-03, MED-07, MED-14 | Reinicio requerido (Credential Guard, AppLocker) |
| **4** | Día 3 | MED-10, MED-11, MED-12, MED-13 | Capa host + aplicación |
| **5** | Continuo | MED-15 | Bucle agéntico MCP |

---

## 8. KPIs de Validación Post-Implementación

| KPI | Indicador | Fórmula / Criterio | Frecuencia | Objetivo | Comando de verificación |
|-----|-----------|-------------------|------------|----------|-------------------------|
| **MTTR-A** | Tiempo medio de contención agéntica | Tiempo desde alteración de control hasta restauración por MCP | Por incidente | < 5 min | Revisar `mcp_audit.log` |
| **TCH** | Tasa de cumplimiento de hardening | Controles conformes / Total controles × 100 | Semanal | 100 % | Ejecutar las 4 herramientas MCP |
| **CECI** | Cobertura eventos consola interactiva | Procesos LogonType 2 logueados por Sysmon ID 1 | Mensual | 100 % | `cmd /c whoami` → verificar ID 1 |
| **FCMCP** | Fiabilidad del canal MCP | Sesiones MCP exitosas / Total sesiones × 100 | Semanal | > 99 % | Test JSON-RPC `initialize` vía SSH |
| **FAA** | Frecuencia de auditoría agéntica | Ejecuciones programadas + reactivas tras 4624 | Diaria | ≥ 1/día | `Get-ScheduledTask -TaskName "MCP_AuditTrigger"` |

### 8.1 Checklist de verificación rápida

```powershell
# 1. Sin cuentas backdoor en Administradores
Get-LocalGroupMember -Group "Administradores"

# 2. Firewall activo en los 3 perfiles
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction

# 3. BitLocker operativo
manage-bde -status C:

# 4. Sysmon ProcessCreate en consola
cmd /c echo test_sysmon
Start-Sleep 2
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 | Where-Object Id -eq 1

# 5. SSH sin autenticación por contraseña
Select-String -Path "C:\ProgramData\ssh\sshd_config" -Pattern "PasswordAuthentication"

# 6. Auditoría de cuentas habilitada
auditpol /get /subcategory:"User Account Management"

# 7. PowerShell Script Block Logging
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"

# 8. TLS 1.0/1.1 deshabilitado
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"
```

### 8.2 Criterios de aceptación

| Control | Estado esperado |
|---------|-----------------|
| Cuenta `yishiego` | **Ausente** |
| Firewall (Domain, Public, Private) | **Enabled = True**, DefaultInbound = Block |
| BitLocker `C:` | **ProtectionStatus = On**, VolumeStatus = FullyEncrypted |
| Sysmon consola | **≥ 1 evento ID 1** tras ejecutar comando en cmd |
| SSH | **PasswordAuthentication no** |
| Administradores locales | Solo `user2` en whitelist |
| Hash `administrators_authorized_keys` | Coincide con valor anotado en Fase 0 |

---

## 9. Resumen de Medidas

| ID | Incidente | Vector MITRE | Medida | Método |
|----|-----------|--------------|--------|--------|
| MED-01 | INC-01 | T1078 | Bloqueo de cuenta + política de contraseña + mensaje legal | `net accounts` / Registro |
| MED-02 | INC-02 | T1136 | Auditoría avanzada cuentas/grupos + whitelist | `auditpol` |
| MED-03 | INC-01 | T1078/T1003 | Credential Guard + LSA Protection (RunAsPPL) | Registro |
| MED-04 | INC-03 | T1562.004 | Firewall restrictivo + tarea enforcement 5 min | PowerShell |
| MED-05 | INC-04 | T1486 | BitLocker + ACL manage-bde + tarea 15 min | PowerShell / `icacls` |
| MED-06 | INC-05 | T1562.001 | Sysmon ProcessCreate consola + DetecciónDefensas | XML Sysmon |
| MED-07 | INC-07 | T1218 | AppLocker completo (Allow+Deny) + protección .bak | GPO AppLocker |
| MED-08 | INC-08 | T1059 | PSReadLine off + Script Block Logging | Registro |
| MED-09 | INC-06 | T1529 | Auditoría apagados + BootMonitor arranque | `secedit` / tarea |
| MED-10 | INC-09 | T1003.001 | Hardening VirtualBox host + VBS/HVCI | `VBoxManage` / Registro |
| MED-11 | INC-09 | T1552 | Rotación JWT 256 bits + DPAPI + reinicio AppPool | PowerShell |
| MED-12 | INC-10 | T1110.003 | Rate limit por IP TCP real (ignorar X-Forwarded-For) | Código C# |
| MED-13 | Proactivo | T1557 | TLS 1.2/1.3 únicamente (SSL2/3 + TLS1.0/1.1 off) | Registro SCHANNEL |
| MED-14 | INC-11 | — | SSH clave pública + cmd.exe shell + restricción IP | `sshd_config` / Registro |
| MED-15 | INC-12 | — | Bucle autorremediación MCP (4 herramientas) | Python MCP + tarea |

---

*Fin del Plan de Securización Post-Incidente — WIN-VNQSUL89MUA*  
*Generado conforme a MITRE ATT&CK, CIS Benchmarks Windows Server 2025 y NIST SP 800-61.*
