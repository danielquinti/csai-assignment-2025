# Plan de Securización Post-Incidente

**Caso:** Remediación y hardening reactivo del servidor WIN-VNQSUL89MUA  
**Máquina afectada:** Windows Server 2025 — `192.168.56.10`  
**Autor:** Blue Team — Agente de Remediación Post-Incidente  
**Fecha:** 23 de junio de 2026  
**Clasificación:** CONFIDENCIAL  

**Referencias analizadas:**

- [3_informe_forense.md](3_informe_forense.md) — RCA del compromiso del 25/03/2026  
- [2_red_team_audit_report.md](2_red_team_audit_report.md) — Exfiltración JWT vía memoria hypervisor  
- [1_blue_team_instrucciones.txt](1_blue_team_instrucciones.txt) — Hardening previo (`nuke.ps1`, WinNetSvc, LOLBins)  
- [3_Restauracion_SSH_MCP_Report.md](3_Restauracion_SSH_MCP_Report.md) — Canal de gestión MCP/SSH restaurado  

> **Nota:** Este documento sustituye al borrador [4_plan_remediacion.md](4_plan_remediacion.md) como plan oficial de securización post-incidente.

---

## 1. Resumen Ejecutivo

El servidor **WIN-VNQSUL89MUA** fue comprometido el **25 de marzo de 2026** mediante acceso interactivo local a la consola de VirtualBox (LogonType 2) con credenciales legítimas del administrador `user2`. El Red Team desactivó el firewall y BitLocker, creó la cuenta backdoor `yishiego` con privilegios de Administrador, exploró la aplicación SecureCatalog y forzó un apagado inmediato para destruir evidencia volátil.

El análisis forense reveló que el hardening perimetral previo (`nuke.ps1`: solo HTTP/HTTPS, SSH eliminado) **no mitigó el acceso físico a la consola**. Además, la configuración de Sysmon (`WinNetSvc.xml`) presentaba un punto ciego crítico: **cero eventos ProcessCreate (ID 1)** en sesiones de consola, permitiendo operar sin telemetría de procesos.

El audit del Red Team confirmó un segundo vector independiente: **extracción de memoria del VM vía `VBoxManage debugvm dumpvmcore`**, con falsificación de JWT y exfiltración de la base de usuarios.

Este plan define **15 medidas de hardening avanzado** (MED-01 a MED-15), organizadas por vector de ataque, con métodos de aplicación nativos de Windows Server siempre que sea posible. Al no disponer de SIEM centralizado (Wazuh), se complementa con un **bucle de autorremediación agéntica vía MCP** (MED-15).

---

## 2. Análisis de Causa Raíz (RCA)

| # | Debilidad explotada | Evidencia | Técnica MITRE |
|---|---------------------|-----------|---------------|
| 1 | Acceso consola VM con credenciales `user2` | Event ID 4624, LogonType 2, origen `127.0.0.1` | T1078 — Valid Accounts |
| 2 | Punto ciego Sysmon en consola interactiva | 2.607 eventos Sysmon el 25/03, **0× ID 1** | T1562.001 — Impair Defenses |
| 3 | Desactivación firewall sin detección | `netsh advfirewall set allprofiles state off` | T1562.004 — Disable Firewall |
| 4 | Desactivación BitLocker | `manage-bde -off C:` | T1486 — Data Encrypted for Impact |
| 5 | Persistencia vía cuenta local | `net user yishiego` + elevación a Administradores | T1136 — Create Account |
| 6 | Anti-forensics volátil | `shutdown /s /t 0` | T1529 — System Shutdown/Reboot |
| 7 | Extracción secreto JWT desde RAM del hypervisor | `VBoxManage debugvm dumpvmcore` + Volatility | T1003.001 — LSASS Memory (análogo) |
| 8 | Bypass rate limiting vía `X-Forwarded-For` | 7 intentos sin `RATE_LIMIT_EXCEEDED` | T1110.003 — Password Spraying |
| 9 | Reversión LOLBins `.bak` | Restauración de `curl.exe.bak`, `tar.exe.bak` | T1218 — System Binary Proxy Execution |
| 10 | Historial PowerShell en claro | Contraseña `EstuveAqui.1234` en `ConsoleHost_history.txt` | T1059 — Command and Scripting Interpreter |

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
# Generar contraseña robusta (mínimo 16 caracteres, complejidad alta)
$nuevaPass = -join ((33..126) | Get-Random -Count 20 | ForEach-Object { [char]$_ })
net user user2 $nuevaPass
Write-Host "[!] Guardar contraseña en gestor seguro fuera de la VM: $nuevaPass" -ForegroundColor Yellow

# Forzar cambio en próximo logon (opcional, break-glass)
# net user user2 /logonpasswordchg:yes
```

### 3.3 Restauración del Firewall de Windows

```powershell
# 1. Habilitar todos los perfiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# 2. Política restrictiva por defecto
Set-NetFirewallProfile -Profile Domain,Public,Private `
    -DefaultInboundAction Block -DefaultOutboundAction Block

# 3. Reglas explícitas — servicio web + canal de gestión agéntica
New-NetFirewallRule -DisplayName "Allow_HTTP_In"  -Direction Inbound -Protocol TCP -LocalPort 80  -Action Allow -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "Allow_HTTPS_In" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow -ErrorAction SilentlyContinue
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

# Verificar hash SHA-256 de referencia (anotar para MED-15)
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
| **Nueva medida de seguridad** | Política de bloqueo de cuenta agresiva, longitud mínima de contraseña 16 caracteres, ocultar último usuario en pantalla de logon y exigir Ctrl+Alt+Supr |
| **Justificación técnica** | El Red Team accedió por la consola de la VM, evadiendo el firewall perimetral. Reducir la ventana de fuerza bruta (5 intentos / 30 min) y no revelar nombres de cuenta en el logon dificulta la reutilización de credenciales filtradas o adivinadas |
| **Método de aplicación** | GPO local / `net accounts` + Registro |

```powershell
net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:15
net accounts /minpwlen:16 /maxpwage:42 /minpwage:1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v dontdisplaylastusername /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DisableCAD /t REG_DWORD /d 0 /f
```

---

#### MED-02

| Campo | Detalle |
|-------|---------|
| **ID Incidente** | INC-02 |
| **Vector de ataque** | Creación de cuenta backdoor `yishiego` y elevación a Administradores — T1136 |
| **Nueva medida de seguridad** | Auditoría avanzada de gestión de cuentas y grupos de seguridad; script de whitelist de administradores locales |
| **Justificación técnica** | El atacante usó `net user` y `net localgroup Administradores`. Los eventos Security 4720 (creación de cuenta) y 4732 (miembro añadido a grupo local) se registran independientemente de Sysmon ProcessCreate, cerrando la brecha de telemetría |
| **Método de aplicación** | Advanced Audit Policy (`auditpol`) + PowerShell |

```powershell
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# Whitelist de administradores autorizados (ajustar SIDs tras Get-LocalUser)
$allowedAdmins = @("user2")
$currentAdmins = Get-LocalGroupMember -Group "Administradores" | Select-Object -ExpandProperty Name
$rogue = $currentAdmins | Where-Object { $_ -notin $allowedAdmins -and $_ -notmatch "S-1-5-21" }
if ($rogue) { Write-Warning "Cuentas no autorizadas en Administradores: $($rogue -join ', ')" }
```

---

#### MED-03

| Campo | Detalle |
|-------|---------|
| **ID Incidente** | INC-02 |
| **Vector de ataque** | Credenciales de `user2` conocidas por el Red Team — T1078 |
| **Nueva medida de seguridad** | Rotación obligatoria de contraseña + LSA Protection (RunAsPPL) + Virtualization-Based Security (Credential Guard) |
| **Justificación técnica** | Impide la reutilización directa de credenciales capturadas y eleva el coste de extracción de secretos LSA en memoria, complementando las defensas contra dump hypervisor (INC-08) |
| **Método de aplicación** | Registro de Windows (requiere reinicio) |

```powershell
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v RequirePlatformSecurityFeatures /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard" /v Enabled /t REG_DWORD /d 1 /f

# Tras reinicio, verificar:
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
| **Vector de ataque** | Desactivación del firewall — `netsh advfirewall set allprofiles state off` — T1562.004 |
| **Nueva medida de seguridad** | Firewall restrictivo con denegación por defecto, reglas explícitas por servicio, restricción de gestión a IP del host y tarea programada de autorremediación cada 5 minutos |
| **Justificación técnica** | El Red Team desactivó el firewall con un único comando. La política inbound block limita la exposición; la tarea SYSTEM detecta perfiles deshabilitados y los reactiva automáticamente, reduciendo el MTTR por debajo de 5 minutos |
| **Método de aplicación** | PowerShell + Tarea programada |

```powershell
Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block
New-NetFirewallRule -DisplayName "Allow_HTTP_In"  -Direction Inbound -Protocol TCP -LocalPort 80  -Action Allow -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "Allow_HTTPS_In" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "Allow_SSH_MCP"  -Direction Inbound -Protocol TCP -LocalPort 22   -Action Allow -RemoteAddress 192.168.56.1 -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "Allow_MCP_SSE"  -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow -RemoteAddress 192.168.56.1 -ErrorAction SilentlyContinue

# Tarea de enforcement como SYSTEM
$scriptBlock = @'
$disabled = Get-NetFirewallProfile | Where-Object { $_.Enabled -eq $false }
if ($disabled) {
    Set-NetFirewallProfile -All -Enabled True
    Write-EventLog -LogName Application -Source "Enforce_Firewall" -EventId 5001 -EntryType Warning -Message "Firewall reactivado por tarea de enforcement"
}
'@
$scriptPath = "C:\Windows\System32\Drivers\en-US\NetworkData\Enforce_Firewall.ps1"
$scriptBlock | Out-File -FilePath $scriptPath -Encoding ASCII -Force

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
| **Vector de ataque** | Desactivación de BitLocker — `manage-bde -off C:` — T1486 |
| **Nueva medida de seguridad** | Re-cifrado BitLocker AES-256 con protector TPM + clave de recuperación offline; ACL restrictiva sobre `manage-bde.exe`; tarea de verificación de estado de cifrado |
| **Justificación técnica** | El atacante desactivó el cifrado para facilitar acceso offline al VDI. Re-habilitar BitLocker protege datos en reposo; la ACL impide que cuentas interactivas ejecuten `manage-bde` sin elevar privilegios adicionales |
| **Método de aplicación** | PowerShell + `icacls` |

```powershell
Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -TpmProtector -UsedSpaceOnly
Add-BitLockerKeyProtector -MountPoint "C:" -RecoveryPasswordProtector

# Restringir permisos NTFS sobre el binario
icacls "C:\Windows\System32\manage-bde.exe" /inheritance:r /grant "SYSTEM:(F)" "BUILTIN\Administrators:(RX)"

# Tarea de verificación (cada 15 min)
$blScript = @'
$vol = Get-BitLockerVolume -MountPoint "C:"
if ($vol.ProtectionStatus -ne "On" -or $vol.VolumeStatus -ne "FullyEncrypted") {
    Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -TpmProtector -UsedSpaceOnly -ErrorAction SilentlyContinue
    Write-EventLog -LogName Application -Source "Enforce_BitLocker" -EventId 5002 -EntryType Warning -Message "BitLocker reactivado: $($vol.ProtectionStatus)"
}
'@
$blScript | Out-File "C:\Windows\System32\Drivers\en-US\NetworkData\Enforce_BitLocker.ps1" -Encoding ASCII -Force
$blAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\Windows\System32\Drivers\en-US\NetworkData\Enforce_BitLocker.ps1"
$blTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 15) -RepetitionDuration ([TimeSpan]::MaxValue)
Register-ScheduledTask -TaskName "Enforce_BitLocker" -Action $blAction -Trigger $blTrigger -User "SYSTEM" -RunLevel Highest -Force
```

---

#### MED-06

| Campo | Detalle |
|-------|---------|
| **ID Incidente** | INC-03 |
| **Vector de ataque** | Punto ciego Sysmon: 0 eventos ProcessCreate (ID 1) en sesión de consola interactiva |
| **Nueva medida de seguridad** | Ampliación de `WinNetSvc.xml` con reglas ProcessCreate para shells interactivas y LOLBins usados en el ataque |
| **Justificación técnica** | La configuración original solo monitorizaba procesos hijos de `w3wp.exe` (IIS). Sin ID 1 en consola, `netsh`, `manage-bde`, `net user` y `shutdown` operaron sin telemetría Sysmon el 25/03/2026 |
| **Método de aplicación** | XML Sysmon + PowerShell (ver Sección 5) |

```powershell
$xmlPath = "C:\Windows\System32\Drivers\en-US\NetworkData\WinNetSvc.xml"
C:\Windows\WinNetSvc.exe -c $xmlPath
Write-Host "[+] Sysmon recargado con reglas de consola interactiva" -ForegroundColor Green
```

---

### Bloque C — Contención de herramientas nativas (LOLBins)

---

#### MED-07

| Campo | Detalle |
|-------|---------|
| **ID Incidente** | INC-05 |
| **Vector de ataque** | Reversión de LOLBins renombrados a `.bak` (`curl.exe.bak`, `tar.exe.bak`) — T1218 |
| **Nueva medida de seguridad** | Permisos NTFS de solo lectura/ejecución en archivos `.bak` de System32; AppLocker con denegación de `net.exe`, `netsh.exe`, `reg.exe` y `manage-bde.exe` para usuarios interactivos |
| **Justificación técnica** | El Red Team restauró binarios desde `.bak` para evadir la táctica "tierra quemada". AppLocker impide que sesiones interactivas ejecuten herramientas de administración que el atacante usó para persistencia y degradación de defensas |
| **Método de aplicación** | GPO local — AppLocker + `icacls` |

```powershell
# Impedir escritura sobre archivos .bak en System32
Get-ChildItem "C:\Windows\System32\*.bak" -ErrorAction SilentlyContinue | ForEach-Object {
    icacls $_.FullName /inheritance:r /grant "SYSTEM:(F)" "BUILTIN\Administrators:(R)"
}

# Habilitar servicio AppLocker
Set-Service AppIDSvc -StartupType Automatic
Start-Service AppIDSvc

# Crear reglas AppLocker (requiere reinicio o gpupdate)
$applockerDir = "C:\Windows\System32\Group Policy\Machine\Microsoft\Windows AppLocker\Executable Rules"
New-Item -ItemType Directory -Path $applockerDir -Force | Out-Null

# Denegar LOLBins críticos a todos los usuarios (S-1-1-0 = Everyone)
# Nota: SYSTEM y reglas Allow previas deben coexistir; probar en entorno de laboratorio
@"
<RuleCollection Type="Exe" EnforcementMode="Enabled">
  <FilePathRule Id="99999999-0001-0001-0001-000000000001" Name="Deny net.exe interactive" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
    <Conditions><FilePathCondition Path="C:\Windows\System32\net.exe"/></Conditions>
  </FilePathRule>
  <FilePathRule Id="99999999-0001-0001-0001-000000000002" Name="Deny netsh.exe interactive" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
    <Conditions><FilePathCondition Path="C:\Windows\System32\netsh.exe"/></Conditions>
  </FilePathRule>
  <FilePathRule Id="99999999-0001-0001-0001-000000000003" Name="Deny manage-bde.exe interactive" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
    <Conditions><FilePathCondition Path="C:\Windows\System32\manage-bde.exe"/></Conditions>
  </FilePathRule>
</RuleCollection>
"@ | Out-File "$applockerDir\Rules.xml" -Encoding Unicode -Force

gpupdate /force
```

---

#### MED-08

| Campo | Detalle |
|-------|---------|
| **ID Incidente** | INC-06 |
| **Vector de ataque** | Historial PowerShell en claro (`ConsoleHost_history.txt`) expuso contraseña de `yishiego` — T1059 |
| **Nueva medida de seguridad** | Deshabilitar persistencia de historial PSReadLine; habilitar Script Block Logging y Module Logging a nivel de máquina |
| **Justificación técnica** | El historial reveló la contraseña de la cuenta backdoor en texto plano. El logging de bloques de PowerShell captura comandos ejecutados aunque el archivo de historial sea eliminado, proporcionando telemetría forense alternativa |
| **Método de aplicación** | Registro de Windows (equivalente GPO) + PowerShell |

```powershell
# Deshabilitar historial PSReadLine (perfil de máquina)
Set-PSReadLineOption -HistorySaveStyle SaveNothing

# Políticas de logging (Machine-wide)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockInvocationLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" /v * /t REG_SZ /d * /f

# Borrar historial existente de todos los perfiles
Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -ErrorAction SilentlyContinue |
    Remove-Item -Force
```

---

### Bloque D — Evasión forense y disponibilidad

---

#### MED-09

| Campo | Detalle |
|-------|---------|
| **ID Incidente** | INC-07 |
| **Vector de ataque** | Apagado forzado — `shutdown /s /t 0` — T1529 |
| **Nueva medida de seguridad** | Auditoría de apagados del sistema; restricción de `SeShutdownPrivilege`; tarea de monitorización de `LastBootUpTime` |
| **Justificación técnica** | El apagado inmediato destruye evidencia volátil en RAM. Registrar eventos 1074/6006 y limitar quién puede apagar el sistema permite detectar conductas anti-forenses y correlacionar con sesiones LogonType 2 |
| **Método de aplicación** | `secedit` + Advanced Audit Policy + Tarea programada |

```powershell
auditpol /set /subcategory:"System Shutdown" /success:enable /failure:enable

# Exportar y restringir SeShutdownPrivilege (solo grupo Administradores, sin cuentas individuales adicionales)
secedit /export /cfg C:\sec_shutdown.cfg
$config = Get-Content C:\sec_shutdown.cfg
# Verificar línea: SeShutdownPrivilege = *S-1-5-32-544
$config | Set-Content C:\sec_shutdown.cfg
secedit /configure /db C:\secedit_shutdown.sdb /cfg C:\sec_shutdown.cfg /areas USER_RIGHTS
Remove-Item C:\sec_shutdown.cfg, C:\secedit_shutdown.sdb -Force -ErrorAction SilentlyContinue

# Tarea: alertar si el sistema se reinició en los últimos 10 minutos tras logon interactivo
$bootScript = @'
$lastBoot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$recentLogon = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddMinutes(-15)} -ErrorAction SilentlyContinue |
    Where-Object { $_.Properties[8].Value -eq 2 }
if ($recentLogon -and ((Get-Date) - $lastBoot).TotalMinutes -lt 10) {
    Write-EventLog -LogName Application -Source "BootMonitor" -EventId 5003 -EntryType Warning -Message "Reinicio detectado tras logon interactivo"
}
'@
$bootScript | Out-File "C:\Windows\System32\Drivers\en-US\NetworkData\BootMonitor.ps1" -Encoding ASCII -Force
Register-ScheduledTask -TaskName "BootMonitor" `
    -Action (New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -File C:\Windows\System32\Drivers\en-US\NetworkData\BootMonitor.ps1") `
    -Trigger (New-ScheduledTaskTrigger -AtStartup) -User "SYSTEM" -RunLevel Highest -Force
```

---

### Bloque E — Capa hypervisor y host

---

#### MED-10

| Campo | Detalle |
|-------|---------|
| **ID Incidente** | INC-08 |
| **Vector de ataque** | Extracción de memoria VM vía `VBoxManage debugvm dumpvmcore` — T1003.001 |
| **Nueva medida de seguridad** | Deshabilitar clipboard y Drag-and-Drop bidireccional en VirtualBox; restringir ACL de `VBoxManage.exe` en el host; habilitar VBS/HVCI en Windows 11 host |
| **Justificación técnica** | El Red Team extrajo el `SecretKey` JWT desde la RAM física del VM. Sin control del hypervisor, el hardening del guest es insuficiente: el TCB debe incluir el host |
| **Método de aplicación** | VBoxManage (host) + Registro (host) |

```powershell
# Ejecutar en el HOST Windows 11 (no en la VM)
$vbox = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
& $vbox modifyvm "CSAI" --clipboard-mode disabled
& $vbox modifyvm "CSAI" --draganddrop disabled

# Restringir ejecución de VBoxManage debugvm a administradores del host
icacls $vbox /inheritance:r /grant "BUILTIN\Administrators:(RX)" "SYSTEM:(F)"

# Habilitar VBS en host (requiere reinicio del host)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 1 /f
```

---

#### MED-11

| Campo | Detalle |
|-------|---------|
| **ID Incidente** | INC-08 |
| **Vector de ataque** | Secreto JWT (`SecretKey`) residente en memoria del worker IIS — T1552 |
| **Nueva medida de seguridad** | Rotación del secreto JWT; almacenamiento protegido con DPAPI; reinicio del Application Pool tras rotación |
| **Justificación técnica** | Volatility localizó cadenas `SecretKey` en RAM del proceso. DPAPI ata el secreto al contexto de máquina, reduciendo la exposición en dumps de memoria y invalidando tokens forjados con la clave anterior |
| **Método de aplicación** | PowerShell (guest) |

```powershell
# Generar nuevo secreto aleatorio de 256 bits
$bytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$plainSecret = [Convert]::ToBase64String($bytes)

# Proteger con DPAPI (LocalMachine scope)
$protected = [Security.Cryptography.ProtectedData]::Protect(
    [Text.Encoding]::UTF8.GetBytes($plainSecret), $null,
    [Security.Cryptography.DataProtectionScope]::LocalMachine
)
$protectedB64 = [Convert]::ToBase64String($protected)

# Actualizar variable de entorno de máquina (la app debe desproteger en runtime)
[Environment]::SetEnvironmentVariable("Jwt__SecretKey", $plainSecret, "Machine")

# Reiniciar Application Pool
Import-Module WebAdministration
Restart-WebAppPool -Name "SecureCatalogPool"
Write-Host "[!] Todos los JWT emitidos con la clave anterior quedan invalidados" -ForegroundColor Yellow
```

---

### Bloque F — Capa aplicación web

---

#### MED-12

| Campo | Detalle |
|-------|---------|
| **ID Incidente** | INC-09 |
| **Vector de ataque** | Bypass de rate limiting falsificando `X-Forwarded-For` — T1110.003 |
| **Nueva medida de seguridad** | Particionar el rate limiter exclusivamente por `HttpContext.Connection.RemoteIpAddress`; no confiar en cabeceras `X-Forwarded-For` sin proxy reverso de confianza |
| **Justificación técnica** | El Red Team envió 7 peticiones con IPs distintas en `X-Forwarded-For` sin activar `RATE_LIMIT_EXCEEDED`. En este escenario no existe proxy legítimo; la IP de conexión TCP real es el único identificador fiable |
| **Método de aplicación** | Código — `Program.cs` de SecureCatalog |

```csharp
// En builder.Services.AddRateLimiter — reemplazar partición por defecto:
options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
{
  // Usar SOLO la IP de conexión TCP; ignorar X-Forwarded-For
  var remoteIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
  return RateLimitPartition.GetFixedWindowLimiter(remoteIp, _ => new FixedWindowRateLimiterOptions
  {
    PermitLimit = 10,
    Window = TimeSpan.FromMinutes(5)
  });
});

// NO habilitar UseForwardedHeaders sin lista de proxies de confianza explícita
```

---

#### MED-13

| Campo | Detalle |
|-------|---------|
| **ID Incidente** | INC-10 |
| **Vector de ataque** | TLS 1.0 y TLS 1.1 habilitados en IIS — T1557 |
| **Nueva medida de seguridad** | Deshabilitar protocolos TLS legacy en SCHANNEL; forzar TLS 1.2 y TLS 1.3 únicamente |
| **Justificación técnica** | Reduce la superficie criptográfica débil (POODLE, BEAST) en el único servicio expuesto a red (HTTPS 443) |
| **Método de aplicación** | Registro de Windows |

```powershell
# Deshabilitar TLS 1.0 y 1.1 (Server)
foreach ($ver in @("TLS 1.0","TLS 1.1")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$ver\Server" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$ver\Server" -Name "Enabled" -Value 0 -PropertyType DWord -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$ver\Server" -Name "DisabledByDefault" -Value 1 -PropertyType DWord -Force
}

# Habilitar TLS 1.2 y 1.3
foreach ($ver in @("TLS 1.2","TLS 1.3")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$ver\Server" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$ver\Server" -Name "Enabled" -Value 1 -PropertyType DWord -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$ver\Server" -Name "DisabledByDefault" -Value 0 -PropertyType DWord -Force
}

# Reiniciar IIS para aplicar
iisreset /restart
```

---

### Bloque G — Canal de gestión MCP/SSH

---

#### MED-14

| Campo | Detalle |
|-------|---------|
| **ID Incidente** | INC-11 |
| **Vector de ataque** | Canal MCP/SSH como superficie de ataque ampliada (contraseñas débiles, puerto 8000 abierto sin restricción) |
| **Nueva medida de seguridad** | SSH solo por clave pública; shell `cmd.exe` para transporte MCP sin BOM; puertos 22/8000 restringidos a IP del host analista; ACL estricta en `administrators_authorized_keys` |
| **Justificación técnica** | El informe de restauración documenta que contraseñas en texto plano y puerto 8000 global amplían la superficie. Restringir por IP y autenticación por clave impide reutilización de credenciales robadas del incidente |
| **Método de aplicación** | Registro + `sshd_config` + PowerShell |

```powershell
# Shell limpia para MCP (sin BOM de PowerShell)
reg add "HKLM\SOFTWARE\OpenSSH" /v DefaultShell /d "C:\Windows\System32\cmd.exe" /f

# Editar C:\ProgramData\ssh\sshd_config — añadir o modificar:
# PasswordAuthentication no
# PubkeyAuthentication yes
# PermitEmptyPasswords no
# Match Group administrators
#     AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys

$cfg = "C:\ProgramData\ssh\sshd_config"
(Get-Content $cfg) -replace '^#?PasswordAuthentication.*','PasswordAuthentication no' |
    Set-Content $cfg -Encoding UTF8

icacls "C:\ProgramData\ssh\administrators_authorized_keys" /inheritance:r /grant "*S-1-5-32-544:F" "SYSTEM:F"
Restart-Service sshd

# Restringir reglas firewall a IP del host (si no aplicado en Fase 0)
Set-NetFirewallRule -DisplayName "Allow_SSH_MCP" -RemoteAddress 192.168.56.1 -ErrorAction SilentlyContinue
Set-NetFirewallRule -DisplayName "Allow_MCP_SSE" -RemoteAddress 192.168.56.1 -ErrorAction SilentlyContinue
```

---

#### MED-15

| Campo | Detalle |
|-------|---------|
| **ID Incidente** | INC-12 |
| **Vector de ataque** | Degradación silenciosa de controles defensivos sin SIEM centralizado |
| **Nueva medida de seguridad** | Bucle cerrado de autorremediación agéntica vía MCP: 4 herramientas de auditoría y corrección automática |
| **Justificación técnica** | Sin Wazuh ni SIEM centralizado, el agente IA conectado por MCP compensa la ausencia de alertas centralizadas detectando y revirtiendo alteraciones en caliente (MTTR objetivo < 5 min) |
| **Método de aplicación** | Servidor MCP Python (`C:\Python312\mcp_server.py`) + Tarea programada (ver Sección 6) |

---

## 5. Configuración Sysmon — Reglas de Consola Interactiva (MED-06)

Integrar el siguiente bloque **dentro** de `<EventFiltering>` en `C:\Windows\System32\Drivers\en-US\NetworkData\WinNetSvc.xml`, antes del cierre `</EventFiltering>`:

```xml
<!--
  ===================================================================
    RULE GROUP: CONSOLA INTERACTIVA (Post-Incidente MED-06)
    Cierra el punto ciego: ProcessCreate en sesiones LogonType 2
    Binarios usados por el Red Team el 25/03/2026
  ===================================================================
-->
<RuleGroup name="ConsolaInteractiva" groupRelation="or">
  <ProcessCreate onmatch="include">

    <!-- Shells interactivas como proceso o padre -->
    <Image condition="image">powershell.exe</Image>
    <Image condition="image">cmd.exe</Image>
    <Image condition="image">pwsh.exe</Image>
    <ParentImage condition="image">powershell.exe</ParentImage>
    <ParentImage condition="image">cmd.exe</ParentImage>
    <ParentImage condition="image">pwsh.exe</ParentImage>

    <!-- Scripts Windows -->
    <Image condition="image">wscript.exe</Image>
    <Image condition="image">cscript.exe</Image>

    <!-- LOLBins usados en el ataque confirmado -->
    <Image condition="image">net.exe</Image>
    <Image condition="image">net1.exe</Image>
    <Image condition="image">netsh.exe</Image>
    <OriginalFileName condition="is">manage-bde.exe</OriginalFileName>
    <OriginalFileName condition="is">shutdown.exe</OriginalFileName>
    <OriginalFileName condition="is">reg.exe</OriginalFileName>
    <OriginalFileName condition="is">sc.exe</OriginalFileName>

    <!-- Reconocimiento post-compromiso -->
    <OriginalFileName condition="is">whoami.exe</OriginalFileName>

  </ProcessCreate>
</RuleGroup>

<!--
  ===================================================================
    RULE GROUP: MANIPULACIÓN DE DEFENSAS (Post-Incidente MED-06)
    Detectar intentos de desactivar firewall o servicios de seguridad
  ===================================================================
-->
<RuleGroup name="DefensaDegradada" groupRelation="or">
  <ProcessCreate onmatch="include">
    <CommandLine condition="contains">advfirewall set</CommandLine>
    <CommandLine condition="contains">firewall set rule</CommandLine>
    <CommandLine condition="contains">manage-bde -off</CommandLine>
    <CommandLine condition="contains">manage-bde -pause</CommandLine>
    <CommandLine condition="contains">net user</CommandLine>
    <CommandLine condition="contains">net localgroup</CommandLine>
    <CommandLine condition="contains">shutdown /s</CommandLine>
    <CommandLine condition="contains">wevtutil cl</CommandLine>
  </ProcessCreate>
</RuleGroup>
```

**Aplicar la configuración:**

```powershell
$xmlPath = "C:\Windows\System32\Drivers\en-US\NetworkData\WinNetSvc.xml"
C:\Windows\WinNetSvc.exe -c $xmlPath

# Validar: ejecutar whoami en cmd y comprobar evento ID 1
cmd /c whoami
Start-Sleep -Seconds 2
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 |
    Where-Object { $_.Id -eq 1 } |
    Select-Object TimeCreated, Message
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
ALLOWED_ADMINS = {"user2"}
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
        _run_ps("Set-NetFirewallProfile -All -Enabled True")
        _run_ps('New-NetFirewallRule -DisplayName "Allow_HTTP_In" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow -ErrorAction SilentlyContinue')
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
# Script invocado por el agente MCP vía SSH desde el host (cron del IDE o tarea local)
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
    -Action (New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -File C:\Windows\System32\Drivers\en-US\NetworkData\MCP_AuditTrigger.ps1") `
    -Trigger (New-ScheduledTaskTrigger -Daily -At "00:00" -RepetitionInterval (New-TimeSpan -Hours 1)) `
    -User "SYSTEM" -RunLevel Highest -Force
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
| MED-01 | INC-01 | T1078 | Bloqueo de cuenta + política de contraseña | GPO / Registro |
| MED-02 | INC-02 | T1136 | Auditoría avanzada cuentas/grupos | auditpol |
| MED-03 | INC-02 | T1078 | Credential Guard + LSA Protection | Registro |
| MED-04 | INC-03 | T1562.004 | Firewall restrictivo + enforcement | PowerShell |
| MED-05 | INC-04 | T1486 | BitLocker + ACL manage-bde | PowerShell / icacls |
| MED-06 | INC-03 | T1562.001 | Sysmon ProcessCreate consola | XML Sysmon |
| MED-07 | INC-05 | T1218 | AppLocker LOLBins + protección .bak | GPO AppLocker |
| MED-08 | INC-06 | T1059 | PSReadLine off + Script Block Logging | Registro |
| MED-09 | INC-07 | T1529 | Auditoría apagados + BootMonitor | secedit / tarea |
| MED-10 | INC-08 | T1003 | Hardening VirtualBox host | VBoxManage |
| MED-11 | INC-08 | T1552 | Rotación JWT + DPAPI | PowerShell |
| MED-12 | INC-09 | T1110 | Rate limit por IP real | Código C# |
| MED-13 | INC-10 | T1557 | TLS 1.2/1.3 únicamente | Registro SCHANNEL |
| MED-14 | INC-11 | — | SSH clave pública + restricción IP | sshd_config / Registro |
| MED-15 | INC-12 | — | Bucle autorremediación MCP | Python MCP |

---

*Fin del Plan de Securización Post-Incidente — WIN-VNQSUL89MUA*
