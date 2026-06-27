# Comandos MCP ejecutados — Securización WIN-VNQSUL89MUA

**VM:** WIN-VNQSUL89MUA (`192.168.56.10`)  
**VirtualBox:** `entregablefinal_2`  
**Canal:** MCP `windows-vm` → herramienta `ejecutar_comando_powershell` → SSH (puerto 22) → PowerShell elevado como `user2`  
**Ejecución de referencia:** 2026-06-26 18:55 – 2026-06-27 05:44 UTC+2  
**Playbook:** `5_2_instrucciones_agente_securicacion.md`  
**Resultado completo:** `5_4_resultado_securizacion.md`

> **Uso previsto:** Este documento recoge los comandos PowerShell **ejecutados con éxito** vía MCP durante la securización post-incidente. Está pensado para que un agente redacte la memoria LaTeX e inserte bloques `\begin{lstlisting}` con comandos reales y contexto.
>
> **Credenciales:** Las contraseñas se generaron en el agente Cursor (no en la VM) antes de F00. En los bloques se usan `$plainUser2` y `$plainUser1`; los valores de la corrida de referencia están en `5_4` (sección CREDENCIALES GENERADAS).
>
> **Nota sobre reintentos:** Varias fases requirieron reintentos (F02 BitLocker, F10 creación de `user1`, F20 tarea programada, WDAC XML manual). Aquí solo figuran las **versiones finales exitosas**. Los intentos fallidos (p. ej. `CiTool` sobre XML manual → `0x80070216`, `[TimeSpan]::MaxValue` en tareas) se omiten.

---

## Índice de fases

| Fase | Referencia | Estado |
|------|------------|--------|
| P0 | Preflight | PASS |
| F00 | §1.1 Backdoor + rotación `user2` | PASS |
| F01 | §1.2 Firewall operativo | PASS |
| F02 | §1.3 BitLocker | PASS |
| F03 | §1.4 VirtualBox NAT + resellado BitLocker | PASS parcial |
| F10 | MS-01 variante agente | PASS |
| F11 | MS-02 Pantalla logon | PASS |
| F12 | MS-08 Lockout/contraseñas | PASS |
| F20 | MS-03 Enforce-Firewall + tarea SYSTEM | PASS |
| F21 | MS-04 BitLocker GPO | PASS |
| F22 | MS-05 AdminGuard + tarea SYSTEM | PASS |
| F30 | MS-06 Sysmon consola | PASS |
| F31 | MS-07 Historial PS + transcripción | PASS |
| F32 | MS-09 Prevención apagado | PASS |
| F40 | MS-10 ACLs + SQL | PASS |
| F50 | Reinicio WDAC | PASS |
| F60 | §3.2 Despliegue `Cierre-Operativo.ps1` | PASS |
| F70 | Verificación §5.1 | PASS |
| F-WDAC | Remediación WDAC LOLBins | PASS |
| I-05 | Fix WHfB `user1` consola | RESUELTO |
| I-06 | Desbloqueo `user1` (lockout) | RESUELTO |
| F-CIERRE | §3.3 Ejecución cierre operativo | PASS |

---

## P0 — Preflight

**Objetivo de la fase:** Comprobar que la VM está en modo gestión (no entrega), SSH activo, sesión elevada y canal MCP operativo antes de modificar nada.

**Contexto:** El agente verificó que `.modo_entrega` no existía, `sshd` estaba en ejecución y la sesión MCP corría con privilegios de administrador (`IsAdmin: True`).

### Comando 1 — Controles P0.1 a P0.5

**Objetivo:** Ejecutar en un solo bloque todos los checks de preflight del playbook.

```powershell
# P0 Preflight completo
Write-Host '=== P0.1 Marcador entrega ===' -ForegroundColor Cyan
Test-Path 'C:\Windows\System32\Config\TxR\Diagnostics\.modo_entrega'

Write-Host '=== P0.2 SSH activo ===' -ForegroundColor Cyan
Get-Service sshd | Select-Object Name, Status, StartType

Write-Host '=== P0.3 Sesion elevada ===' -ForegroundColor Cyan
whoami /groups | Select-String 'S-1-5-32-544'

Write-Host '=== P0.4 Firewall reglas gestion ===' -ForegroundColor Cyan
Get-NetFirewallRule -DisplayName 'Allow_SSH_MCP','Allow_MCP_SSE' -ErrorAction SilentlyContinue |
    Select-Object DisplayName, Enabled

Write-Host '=== P0.5 Info sistema ===' -ForegroundColor Cyan
hostname
whoami
```

| Check | Comando clave | Esperado |
|-------|---------------|----------|
| P0.1 | `Test-Path ...\.modo_entrega` | `False` |
| P0.2 | `Get-Service sshd` | `Running`, `Automatic` |
| P0.3 | `whoami /groups` + `IsInRole('Administrator')` | Administradores |
| P0.4 | `Get-NetFirewallRule` SSH/MCP | Habilitadas o pendientes (F01) |
| P0.5 | `hostname` / `whoami` | `WIN-VNQSUL89MUA`, `user2` |

### Comando 2 — Verificación explícita de elevación

**Objetivo:** Confirmar privilegios admin cuando `whoami /groups` no mostró el SID en el primer intento.

```powershell
$isAdmin = ([Security.Principal.WindowsPrincipal]
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "IsAdmin: $isAdmin"
```

---

## F00 — §1.1 Eliminación backdoor y rotación `user2`

**Objetivo de la fase:** Eliminar la cuenta backdoor `yishiego`, dejar solo `user2` en Administradores y rotar la contraseña de `user2`.

**Contexto:** Primera acción ofensiva de contención tras el preflight. La rotación de contraseña no cortó la sesión MCP porque SSH usa clave pública.

### Comando 1 — Saneamiento y rotación

**Objetivo:** Eliminar persistencia de cuenta, limpiar grupo Administradores y aplicar nueva contraseña.

```powershell
# F00 - Eliminar backdoor yishiego
if (Get-LocalUser -Name 'yishiego' -ErrorAction SilentlyContinue) {
    Remove-LocalUser -Name 'yishiego'
    Write-Host '[+] Cuenta yishiego eliminada.' -ForegroundColor Green
}

# Sanear grupo Administradores (whitelist: solo user2)
$whitelist = @('user2')
Get-LocalGroupMember -Group 'Administradores' |
    Where-Object { $_.ObjectClass -eq 'User' -and $_.Name -notmatch 'Administrator$' } |
    ForEach-Object {
        $shortName = ($_.Name -split '\\')[-1]
        if ($whitelist -notcontains $shortName) {
            Remove-LocalGroupMember -Group 'Administradores' -Member $_.Name -ErrorAction SilentlyContinue
            Disable-LocalUser -Name $shortName -ErrorAction SilentlyContinue
        }
    }

# Rotar contrasena user2 (sin imprimir el valor en salida MCP)
$User2Password = ConvertTo-SecureString $plainUser2 -AsPlainText -Force
Set-LocalUser -Name 'user2' -Password $User2Password
Write-Host '[+] Contrasena de user2 rotada.' -ForegroundColor Green
```

### Comando 2 — Verificación

**Objetivo:** Confirmar ausencia de `yishiego` y composición del grupo Administradores.

```powershell
$yish = Get-LocalUser -Name 'yishiego' -ErrorAction SilentlyContinue
if ($yish) { Write-Host '[FAIL] yishiego aun existe' } else { Write-Host '[PASS] yishiego eliminado' }
Get-LocalGroupMember -Group 'Administradores' | Select-Object Name, ObjectClass
```

---

## F01 — §1.2 Firewall modo operativo Blue Team

**Objetivo de la fase:** Activar firewall en los tres perfiles con deny-by-default y abrir solo 80, 443, 22 (SSH) y 8000 (MCP).

**Contexto:** Restaura el perímetro de red mínimo para servicios web y gestión remota del agente.

### Comando 1 — Configuración firewall

**Objetivo:** Habilitar perfiles, bloquear tráfico por defecto y crear/habilitar reglas operativas.

```powershell
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True `
    -DefaultInboundAction Block -DefaultOutboundAction Block

$operationalRules = @(
    @{ Name = 'Allow_HTTP_In';    Port = 80  },
    @{ Name = 'Allow_HTTPS_In';   Port = 443 },
    @{ Name = 'Allow_SSH_MCP';    Port = 22  },
    @{ Name = 'Allow_MCP_SSE';    Port = 8000 }
)
foreach ($r in $operationalRules) {
    if (-not (Get-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $r.Name -Direction Inbound `
            -Protocol TCP -LocalPort $r.Port -Action Allow | Out-Null
    } else {
        Enable-NetFirewallRule -DisplayName $r.Name
    }
}

# Refuerzo GPO local firewall
$fwPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall'
@('DomainProfile', 'StandardProfile', 'PublicProfile') | ForEach-Object {
    $p = Join-Path $fwPolicy $_
    if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
    Set-ItemProperty -Path $p -Name 'EnableFirewall' -Value 1 -Type DWord
}
```

### Comando 2 — Verificación

**Objetivo:** Confirmar que todos los perfiles están habilitados y las reglas SSH/MCP activas.

```powershell
$disabled = (Get-NetFirewallProfile | Where-Object { -not $_.Enabled }).Count
if ($disabled -eq 0) { Write-Host '[PASS] Todos los perfiles FW habilitados' }
Get-NetFirewallRule -DisplayName 'Allow_SSH_MCP','Allow_MCP_SSE' | Select-Object DisplayName, Enabled
```

---

## F02 — §1.3 Reactivación BitLocker

**Objetivo de la fase:** Cifrar volumen `C:` con BitLocker TPM-only, protectores TPM + recuperación.

**Contexto:** BitLocker estaba `Off` / `FullyDecrypted`. Se verificó vTPM de VirtualBox disponible. Tras varios intentos con `Enable-BitLocker`, el cifrado se completó con `manage-bde -on C:`.

### Comando 1 — Comprobar TPM

**Objetivo:** Verificar que el entorno VirtualBox dispone de vTPM antes de activar BitLocker.

```powershell
$tpm = Get-Tpm
Write-Host "TPM presente: $($tpm.TpmPresent), listo: $($tpm.TpmReady)"
```

### Comando 2 — Agregar protectores y activar cifrado

**Objetivo:** Configurar protector TPM, generar clave de recuperación (guardar en `5_4`) e iniciar cifrado AES-256.

```powershell
$blv = Get-BitLockerVolume -MountPoint 'C:'

if (-not ($blv.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'Tpm' })) {
    Add-BitLockerKeyProtector -MountPoint 'C:' -TpmProtector | Out-Null
}
if (-not ($blv.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' })) {
    $recoveryResult = Add-BitLockerKeyProtector -MountPoint 'C:' -RecoveryPasswordProtector
    # Guardar recovery key en 5_4 — no imprimir en logs operativos
}

Enable-BitLocker -MountPoint 'C:' -EncryptionMethod Aes256 -TpmProtector -UsedSpaceOnly
```

### Comando 3 — Alternativa exitosa (`manage-bde`)

**Objetivo:** Forzar inicio de cifrado cuando `Enable-BitLocker` no avanzaba al 100 %.

```powershell
manage-bde -on C: -skiphardwaretest -UsedSpaceOnly
Start-Sleep -Seconds 3
Get-BitLockerVolume -MountPoint 'C:' |
    Select-Object VolumeStatus, ProtectionStatus, EncryptionPercentage
```

### Comando 4 — Verificación final

**Objetivo:** Confirmar `FullyEncrypted` y protectores TPM + RecoveryPassword.

```powershell
$blv = Get-BitLockerVolume -MountPoint 'C:'
Write-Host "VolumeStatus: $($blv.VolumeStatus), ProtectionStatus: $($blv.ProtectionStatus)"
Write-Host "KeyProtectors: $($blv.KeyProtector.KeyProtectorType -join ', ')"
```

**Resultado:** `ProtectionStatus: On`, `VolumeStatus: FullyEncrypted`, `EncryptionPercentage: 100%`.

---

## F03 — §1.4 VirtualBox NAT + resellado BitLocker

**Objetivo de la fase:** Eliminar adaptador NAT (NIC1) en el host y resellar BitLocker con los nuevos PCR del vTPM.

**Contexto:** El cambio de hardware en VirtualBox sin suspender BitLocker provocó incidencia I-04 (recovery key). El procedimiento correcto se aplicó después: `Suspend-BitLocker` → apagado → cambio hardware (host) → arranque → `Resume-BitLocker`.

> **Nota:** La eliminación de NAT (`VBoxManage modifyvm --nic1 none`) se ejecutó en el **host**, no vía MCP. Las CPUs no se modificaron (quedaron en 4 lógicas).

### Comando 1 — Suspender BitLocker (guest, vía MCP)

**Objetivo:** Desactivar verificación TPM para el próximo arranque antes de cambiar hardware.

```powershell
Suspend-BitLocker -MountPoint 'C:'
Get-BitLockerVolume -MountPoint 'C:' | Select-Object ProtectionStatus
# Esperado: Suspended u Off temporal
```

### Comando 2 — Apagado limpio

**Objetivo:** Apagar la VM de forma controlada antes del cambio de hardware en VirtualBox.

```powershell
Stop-Computer -Force
```

### Comando 3 — Resellar BitLocker tras cambio hardware

**Objetivo:** Reactivar protección BitLocker con las nuevas mediciones PCR (sin NAT).

```powershell
Resume-BitLocker -MountPoint 'C:'
Get-BitLockerVolume -MountPoint 'C:' | Select-Object ProtectionStatus, VolumeStatus
# Esperado: ProtectionStatus = On, FullyEncrypted
```

### Comando 4 — Verificación de red

**Objetivo:** Confirmar que solo queda la IP Host-Only (`192.168.56.10`), sin rango NAT `10.0.2.x`.

```powershell
ipconfig | Select-String 'IPv4'
```

---

## F10 — MS-01 variante agente

**Objetivo de la fase:** Crear cuenta operativa `user1` (sin admin), restringir logon interactivo de `user2`, habilitar WHfB sin bloquear SSH.

**Contexto:** Se omitió `SeDenyNetworkLogonRight` para `user2` (preserva MCP/SSH). `New-LocalUser` falló con `-PasswordNeverExpires $false`; la versión exitosa omite ese parámetro.

### Comando 1 — Crear `user1`

**Objetivo:** Alta de cuenta operativa sin privilegios de administrador.

```powershell
$User1Password = ConvertTo-SecureString $plainUser1 -AsPlainText -Force
New-LocalUser -Name 'user1' -Password $User1Password `
    -Description 'Cuenta operativa sin privilegios'
Add-LocalGroupMember -Group 'Usuarios' -Member 'user1'
```

### Comando 2 — Derechos de logon (`secedit`)

**Objetivo:** Permitir logon interactivo solo a `user1`; denegar consola a `user2` sin tocar logon de red.

```powershell
secedit /export /cfg C:\Windows\Temp\sec_logon.cfg /quiet
$cfg = Get-Content C:\Windows\Temp\sec_logon.cfg
$cfg = $cfg -replace '^SeInteractiveLogonRight\s*=.*', 'SeInteractiveLogonRight = user1'
$cfg = $cfg -replace '^SeDenyInteractiveLogonRight\s*=.*', 'SeDenyInteractiveLogonRight = user2,DefaultAccount,WDAGUtilityAccount'
# NO modificar SeDenyNetworkLogonRight — preserva SSH de user2
$cfg | Set-Content C:\Windows\Temp\sec_logon.cfg -Encoding Unicode
secedit /configure /db $env:windir\security\local.sdb /cfg C:\Windows\Temp\sec_logon.cfg /areas USER_RIGHTS /quiet
Remove-Item C:\Windows\Temp\sec_logon.cfg -Force
gpupdate /force /quiet
```

### Comando 3 — Windows Hello for Business

**Objetivo:** Habilitar WHfB en política (inicialmente con `RequireSecurityDevice=1`; corregido en I-05).

```powershell
$whfb = 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork'
if (-not (Test-Path $whfb)) { New-Item -Path $whfb -Force | Out-Null }
Set-ItemProperty -Path $whfb -Name 'Enabled' -Value 1 -Type DWord
Set-ItemProperty -Path $whfb -Name 'RequireSecurityDevice' -Value 1 -Type DWord
```

### Comando 4 — Verificación

**Objetivo:** Confirmar existencia de `user1`, ausencia en Administradores y `sshd` activo.

```powershell
Get-LocalUser 'user1' | Select-Object Name, Enabled
Get-LocalGroupMember 'Administradores' | Where-Object { $_.Name -match 'user1$' }
Get-Service sshd | Select-Object Status
```

---

## F11 — MS-02 Ocultación pantalla de logon

**Objetivo de la fase:** Ocultar último usuario y cambio rápido de usuario en LogonUI.

### Comando 1 — Registro de políticas

**Objetivo:** Establecer `dontdisplaylastusername` y `HideFastUserSwitching` en el registro.

```powershell
$path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
@('dontdisplaylastusername', 'DontDisplayLastUserName', 'HideFastUserSwitching') |
    ForEach-Object { Set-ItemProperty -Path $path -Name $_ -Value 1 -Type DWord -Force }
gpupdate /force
```

---

## F12 — MS-08 Lockout y política de contraseñas

**Objetivo de la fase:** Aplicar umbral de bloqueo (3 intentos), longitud mínima 16 y complejidad.

### Comando 1 — Política de cuentas y contraseñas

**Objetivo:** Configurar lockout y requisitos de contraseña vía `net accounts` y `secedit`.

```powershell
net accounts /lockoutthreshold:3
net accounts /lockoutduration:30
net accounts /lockoutwindow:15
net accounts /minpwlen:16
net accounts /maxpwage:90
net accounts /uniquepw:24

secedit /export /cfg C:\Windows\Temp\sec_pw.cfg /quiet
(Get-Content C:\Windows\Temp\sec_pw.cfg) -replace 'PasswordComplexity = 0', 'PasswordComplexity = 1' |
    Set-Content C:\Windows\Temp\sec_pw.cfg
secedit /configure /db $env:windir\security\local.sdb /cfg C:\Windows\Temp\sec_pw.cfg /areas SECURITYPOLICY /quiet
Remove-Item C:\Windows\Temp\sec_pw.cfg -Force
```

---

## F20 — MS-03 Enforce-Firewall + tarea SYSTEM

**Objetivo de la fase:** Desplegar script de refuerzo de firewall y tarea SYSTEM cada 5 minutos que restaura reglas SSH/MCP si el Red Team las elimina.

**Contexto:** El intento inicial con `[TimeSpan]::MaxValue` falló; la versión exitosa usa `(New-TimeSpan -Days 3650)`. Los XML WDAC manuales (`Deny-Netsh.xml`) se crearon pero `CiTool` falló (ver F-WDAC).

### Comando 1 — Desplegar `Enforce-Firewall.ps1`

**Objetivo:** Escribir script que reactiva firewall y reglas operativas salvo si existe `.modo_entrega`.

```powershell
$scriptPath = 'C:\Windows\System32\Drivers\en-US\NetworkData\Enforce-Firewall.ps1'
@'
$marker = 'C:\Windows\System32\Config\TxR\Diagnostics\.modo_entrega'
if (Test-Path $marker) { return }
foreach ($p in Get-NetFirewallProfile) {
    if (-not $p.Enabled) {
        Set-NetFirewallProfile -Name $p.Name -Enabled True `
            -DefaultInboundAction Block -DefaultOutboundAction Block
        "$((Get-Date).ToString('o')) FIREWALL_RESTORED Profile=$($p.Name)" |
            Out-File 'C:\Windows\System32\Config\TxR\Diagnostics\fw_enforce.log' -Append
    }
}
$required = @(
    @{ Name = 'Allow_HTTP_In';  Port = 80  },
    @{ Name = 'Allow_HTTPS_In'; Port = 443 },
    @{ Name = 'Allow_SSH_MCP';  Port = 22  },
    @{ Name = 'Allow_MCP_SSE';  Port = 8000 }
)
foreach ($r in $required) {
    if (-not (Get-NetFirewallRule -DisplayName $r.Name -EA SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $r.Name -Direction Inbound -Protocol TCP `
            -LocalPort $r.Port -Action Allow | Out-Null
    } else {
        Enable-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue
    }
}
'@ | Set-Content $scriptPath -Encoding UTF8
```

### Comando 2 — Registrar tarea `BlueTeam_FirewallEnforce`

**Objetivo:** Ejecutar el script cada 5 minutos como `NT AUTHORITY\SYSTEM`.

```powershell
$scriptPath = 'C:\Windows\System32\Drivers\en-US\NetworkData\Enforce-Firewall.ps1'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 5) `
    -RepetitionDuration (New-TimeSpan -Days 3650)
$principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' `
    -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'BlueTeam_FirewallEnforce' -Action $action `
    -Trigger $trigger -Principal $principal -Force | Out-Null
Get-ScheduledTask -TaskName 'BlueTeam_FirewallEnforce' | Select-Object TaskName, State
```

---

## F21 — MS-04 BitLocker GPO

**Objetivo de la fase:** Reforzar política FVE: solo TPM (sin PIN), denegar escritura en unidades extraíbles.

### Comando 1 — Políticas FVE en registro

**Objetivo:** Impedir BitLocker sin TPM y sin PIN de arranque.

```powershell
$fvePath = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
if (-not (Test-Path $fvePath)) { New-Item -Path $fvePath -Force | Out-Null }
Set-ItemProperty -Path $fvePath -Name 'EnableBDEWithNoTPM' -Value 0 -Type DWord
Set-ItemProperty -Path $fvePath -Name 'UseTPMPIN'          -Value 0 -Type DWord
Set-ItemProperty -Path $fvePath -Name 'RDVDenyWriteAccess' -Value 1 -Type DWord
```

> El bloqueo WDAC de `manage-bde.exe` se completó en **F-WDAC** (no en el XML manual `Deny-ManageBde.xml`).

---

## F22 — MS-05 AdminGuard + tarea SYSTEM

**Objetivo de la fase:** Vigilar el grupo Administradores y eliminar cuentas no autorizadas; bloquear `net.exe` vía WDAC (completado en F-WDAC).

### Comando 1 — Desplegar `AdminGuard.ps1`

**Objetivo:** Script que elimina de Administradores cualquier cuenta fuera de la whitelist (`user2`).

```powershell
$scriptPath = 'C:\Windows\System32\Drivers\en-US\NetworkData\AdminGuard.ps1'
@'
param([string[]]$AllowList = @('user2'))
Get-LocalGroupMember -Group 'Administradores' | ForEach-Object {
    $shortName = ($_.Name -split '\\')[-1]
    if ($shortName -notin $AllowList) {
        Remove-LocalGroupMember -Group 'Administradores' -Member $_.Name -ErrorAction SilentlyContinue
        Disable-LocalUser -Name $shortName -ErrorAction SilentlyContinue
        "MS-05: Cuenta '$shortName' eliminada de Administradores." |
            Out-File 'C:\Windows\System32\Config\TxR\Diagnostics\admin_enforce.log' -Append
    }
}
'@ | Set-Content $scriptPath -Encoding UTF8
```

### Comando 2 — Registrar tarea `BlueTeam_AdminGuard`

**Objetivo:** Ejecutar AdminGuard cada 5 minutos como SYSTEM (tarea oculta).

```powershell
$scriptPath = 'C:\Windows\System32\Drivers\en-US\NetworkData\AdminGuard.ps1'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`" -AllowList user2"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 5) `
    -RepetitionDuration (New-TimeSpan -Days 3650)
$principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' `
    -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'BlueTeam_AdminGuard' -Action $action `
    -Trigger $trigger -Principal $principal `
    -Settings (New-ScheduledTaskSettingsSet -Hidden) -Force | Out-Null
```

### Comando 3 — Auditoría de gestión de cuentas

**Objetivo:** Habilitar eventos de auditoría para cambios en cuentas y grupos.

```powershell
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
```

---

## F30 — MS-06 Sysmon consola interactiva

**Objetivo de la fase:** Recargar Sysmon con reglas `HardeningConsolaInteractiva` para auditar actividad en consola.

### Comando 1 — Recargar configuración Sysmon

**Objetivo:** Aplicar `WinNetSvc.xml` con reglas de ProcessCreate para shells y LOLBins.

```powershell
$sysmonExe = 'C:\Windows\System32\Drivers\en-US\NetworkData\WinNetSvc.exe'
$xmlPath   = 'C:\Windows\System32\Drivers\en-US\NetworkData\WinNetSvc.xml'
# El XML incluye RuleGroup HardeningConsolaInteractiva (ver 5_2 F30)
& $sysmonExe -c $xmlPath
```

---

## F31 — MS-07 Historial PowerShell y transcripción

**Objetivo de la fase:** Desactivar historial interactivo PSReadLine y habilitar transcripción centralizada.

### Comando 1 — Desactivar historial y habilitar logging

**Objetivo:** `SaveNothing` en profile global; transcripciones en `PSTranscripts` con ACL restrictiva.

```powershell
$profilePath = 'C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1'
Add-Content -Path $profilePath -Value @'
if (Get-Module PSReadLine -EA SilentlyContinue) {
    Set-PSReadLineOption -HistorySaveStyle SaveNothing
}
'@

Get-ChildItem 'C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt' `
    -ErrorAction SilentlyContinue | Remove-Item -Force

$transcriptDir = 'C:\Windows\System32\Config\TxR\PSTranscripts'
New-Item -ItemType Directory -Force -Path $transcriptDir | Out-Null

$trans = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
$sbLog = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
@($trans, $sbLog) | ForEach-Object { if (-not (Test-Path $_)) { New-Item -Path $_ -Force | Out-Null } }
Set-ItemProperty -Path $trans -Name 'EnableTranscripting' -Value 1 -Type DWord
Set-ItemProperty -Path $trans -Name 'OutputDirectory' -Value $transcriptDir -Type String
Set-ItemProperty -Path $sbLog -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord
```

---

## F32 — MS-09 Prevención apagado anti-forense

**Objetivo de la fase:** Vaciar `SeShutdownPrivilege` y prohibir apagado sin logon.

### Comando 1 — Restricción de apagado

**Objetivo:** Impedir que cuentas locales apaguen el sistema sin sesión autenticada.

```powershell
secedit /export /cfg C:\Windows\Temp\sec_shutdown.cfg /quiet
(Get-Content C:\Windows\Temp\sec_shutdown.cfg) | ForEach-Object {
    if ($_ -match '^SeShutdownPrivilege\s*=') { 'SeShutdownPrivilege = ' } else { $_ }
} | Set-Content C:\Windows\Temp\sec_shutdown.cfg -Encoding Unicode
secedit /configure /db $env:windir\security\local.sdb /cfg C:\Windows\Temp\sec_shutdown.cfg /areas USER_RIGHTS /quiet
Remove-Item C:\Windows\Temp\sec_shutdown.cfg -Force

Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name 'ShutdownWithoutLogon' -Value 0 -Type DWord
```

---

## F40 — MS-10 ACLs SecureCatalog y SQL least privilege

**Objetivo de la fase:** Endurecer permisos NTFS de la aplicación web y reducir privilegios SQL del AppPool.

### Comando 1 — ACLs NTFS

**Objetivo:** Denegar lectura/ejecución a `user1` y `user2` sobre `C:\inetpub\wwwroot\SecureCatalog`.

```powershell
$appPath = 'C:\inetpub\wwwroot\SecureCatalog'
icacls $appPath /inheritance:r /T /C /Q
icacls $appPath /grant "IIS AppPool\SecureCatalogPool:(OI)(CI)RX" /T
icacls $appPath /grant "IUSR:(OI)(CI)RX" /T
icacls $appPath /grant "SYSTEM:(OI)(CI)F" /T
icacls $appPath /grant "BUILTIN\Administradores:(OI)(CI)F" /T
@('user1','user2') | ForEach-Object { icacls $appPath /deny "${_}:(OI)(CI)RX" /T }
```

### Comando 2 — SQL least privilege

**Objetivo:** Quitar `db_owner` al AppPool; asignar solo `db_datareader` y `db_datawriter`.

```powershell
Invoke-Sqlcmd -ServerInstance 'localhost\SQLEXPRESS' -Query @"
USE SecureCatalogDb;
IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'IIS AppPool\SecureCatalogPool')
BEGIN
    ALTER ROLE db_owner DROP MEMBER [IIS AppPool\SecureCatalogPool];
    ALTER ROLE db_datareader ADD MEMBER [IIS AppPool\SecureCatalogPool];
    ALTER ROLE db_datawriter ADD MEMBER [IIS AppPool\SecureCatalogPool];
END
"@
```

---

## F50 — Reinicio para activación WDAC

**Objetivo de la fase:** Reiniciar la VM para que las políticas WDAC y cambios de kernel surtan efecto.

### Comando 1 — Pre-reinicio (verificación estado)

**Objetivo:** Comprobar servicios críticos antes de reiniciar.

```powershell
Get-Service sshd | Select-Object Status, StartType
Get-BitLockerVolume 'C:' | Select-Object ProtectionStatus, VolumeStatus
CiTool.exe --list-policies
```

### Comando 2 — Reinicio

**Objetivo:** Forzar reinicio; MCP se reconecta automáticamente tras ~3–5 minutos.

```powershell
Restart-Computer -Force
```

### Comando 3 — Post-reinicio

**Objetivo:** Verificar reconexión MCP, SSH, firewall y BitLocker tras el arranque.

```powershell
hostname
whoami
Get-Service sshd | Select-Object Status
Get-NetFirewallRule -DisplayName 'Allow_SSH_MCP','Allow_MCP_SSE' | Select-Object DisplayName, Enabled
Get-BitLockerVolume 'C:' | Select-Object ProtectionStatus
```

---

## F60 — §3.2 Despliegue `Cierre-Operativo.ps1`

**Objetivo de la fase:** Escribir en disco el script de pechado **sin ejecutarlo** (línea roja del playbook durante securización).

### Comando 1 — Desplegar script

**Objetivo:** Crear `Cierre-Operativo.ps1` en ruta camuflada de `NetworkData`.

```powershell
$cierrePath = 'C:\Windows\System32\Drivers\en-US\NetworkData\Cierre-Operativo.ps1'
# Contenido completo del script: ver 5_2 F60 o 5_5 F60
# Acciones: .modo_entrega, desregistrar BlueTeam_FirewallEnforce,
#           firewall solo 80/443, detener MCP, desinstalar OpenSSH, limpiar historial
$cierreScript | Set-Content -Path $cierrePath -Encoding UTF8 -Force
Test-Path $cierrePath  # Esperado: True
```

> El script completo (~100 líneas) está en `5_2_instrucciones_agente_securicacion.md` (sección F60). No se ejecutó en esta fase.

---

## F70 — Verificación final

**Objetivo de la fase:** Ejecutar checklist automatizado §5.1 antes del cierre operativo.

**Contexto:** Se corrigió el script original del playbook: `Get-NetFirewallRule` debe usar `-DisplayName` (no `-Name` posicional).

### Comando 1 — `Test-AgentHardening` (versión corregida)

**Objetivo:** Verificar 10+ controles automáticos en un solo bloque.

```powershell
function Test-AgentHardening {
    $r = @()
    $r += [PSCustomObject]@{ Control='Backdoor eliminado'; Pass=-not (Get-LocalUser 'yishiego' -EA SilentlyContinue) }
    $r += [PSCustomObject]@{ Control='Firewall habilitado'; Pass=(Get-NetFirewallProfile|Where-Object{-not $_.Enabled}).Count -eq 0 }
    $r += [PSCustomObject]@{ Control='SSH regla activa'; Pass=[bool](Get-NetFirewallRule -DisplayName 'Allow_SSH_MCP' -EA SilentlyContinue | Where-Object {$_.Enabled -eq 'True'}) }
    $r += [PSCustomObject]@{ Control='MCP regla activa'; Pass=[bool](Get-NetFirewallRule -DisplayName 'Allow_MCP_SSE' -EA SilentlyContinue | Where-Object {$_.Enabled -eq 'True'}) }
    $r += [PSCustomObject]@{ Control='BitLocker activo'; Pass=(Get-BitLockerVolume 'C:').ProtectionStatus -eq 'On' }
    $r += [PSCustomObject]@{ Control='user1 existe'; Pass=[bool](Get-LocalUser 'user1' -EA SilentlyContinue) }
    $r += [PSCustomObject]@{ Control='dontdisplaylastusername'; Pass=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name dontdisplaylastusername -EA SilentlyContinue).dontdisplaylastusername -eq 1 }
    $r += [PSCustomObject]@{ Control='sshd Running'; Pass=(Get-Service sshd -EA SilentlyContinue).Status -eq 'Running' }
    $r += [PSCustomObject]@{ Control='Cierre-Operativo desplegado'; Pass=Test-Path 'C:\Windows\System32\Drivers\en-US\NetworkData\Cierre-Operativo.ps1' }
    $r += [PSCustomObject]@{ Control='Sin modo entrega'; Pass=-not (Test-Path 'C:\Windows\System32\Config\TxR\Diagnostics\.modo_entrega') }
    $r | Format-Table -AutoSize
    return ($r | Where-Object { -not $_.Pass }).Count -eq 0
}
Test-AgentHardening
```

**Resultado pre-cierre:** 10/10 controles automáticos PASS.

---

## F-WDAC — Remediación WDAC LOLBins

**Objetivo de la fase:** Bloquear `netsh.exe`, `manage-bde.exe`, `net.exe` y `net1.exe` mediante App Control for Business.

**Contexto (I-01):** Los XML manuales del playbook (`Deny-Netsh.xml`, etc.) fallaron con `CiTool` error `0x80070216`. La solución fue generar política **base** con `Merge-CIPolicy` + `AllowAll.xml`, convertir a `.cip` con `ConvertFrom-CIPolicy` y aplicar en Audit → Enforce con dos reinicios.

### Comando 1 — Generar política `BlueTeam-Deny-LOLBins`

**Objetivo:** Crear reglas Deny FilePublisher para los cuatro binarios y fusionarlas en política base.

```powershell
Import-Module ConfigCI
$outDir = 'C:\Windows\System32\Drivers\en-US\NetworkData'
$tempDir = 'C:\Windows\Temp\wdac_work'
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

$allowAllCopy = Join-Path $tempDir 'AllowAll.xml'
Copy-Item (Join-Path $env:windir 'schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml') $allowAllCopy -Force

$binaries = @(
    "$env:windir\System32\netsh.exe",
    "$env:windir\System32\manage-bde.exe",
    "$env:windir\System32\net.exe",
    "$env:windir\System32\net1.exe"
)
$denyRules = foreach ($b in $binaries) {
    New-CIPolicyRule -Level FilePublisher -DriverFilePath $b `
        -Fallback SignedVersion,Publisher,Hash -Deny
}

$merged = Join-Path $outDir 'BlueTeam-Deny-LOLBins.xml'
Merge-CIPolicy -PolicyPaths $allowAllCopy -OutputFilePath $merged -Rules $denyRules
Set-CiPolicyIdInfo -FilePath $merged -PolicyName 'BlueTeam_Deny_LOLBins' -ResetPolicyID
```

### Comando 2 — Aplicar en Audit Mode

**Objetivo:** Activar modo auditoría (opción 3) y desplegar política binaria antes del primer reinicio.

```powershell
Set-RuleOption -FilePath $merged -Option 3
$cipAudit = Join-Path $tempDir 'BlueTeam-Deny-LOLBins-audit.cip'
ConvertFrom-CIPolicy -XmlFilePath $merged -BinaryFilePath $cipAudit
CiTool.exe --update-policy $cipAudit
# → Restart-Computer -Force
```

### Comando 3 — Pasar a Enforce Mode

**Objetivo:** Eliminar Audit Mode, regenerar `.cip` y aplicar política en modo bloqueo.

```powershell
$p = 'C:\Windows\System32\Drivers\en-US\NetworkData\BlueTeam-Deny-LOLBins.xml'
$cip = 'C:\Windows\Temp\wdac_work\BlueTeam-Deny-LOLBins-enforce.cip'

Set-RuleOption -FilePath $p -Option 3 -Delete
ConvertFrom-CIPolicy -XmlFilePath $p -BinaryFilePath $cip
CiTool.exe --update-policy $cip
# → Restart-Computer -Force
```

### Comando 4 — Verificación Enforce

**Objetivo:** Confirmar bloqueo de LOLBins y que PowerShell/SSH siguen operativos.

```powershell
CiTool.exe --list-policies
# Esperado: BlueTeam_Deny_LOLBins activa

netsh advfirewall show allprofiles state   # Bloqueado por App Control
manage-bde -status C:                       # Bloqueado
net user                                    # Bloqueado
powershell -NoProfile -Command 'Write-Host OK'  # OK
Get-Service sshd                            # Running
```

**Policy ID aplicada:** `{65511DF1-8D54-431B-A929-A4CBDADE5EC2}`

---

## I-05 — Fix WHfB bloqueo logon `user1` en consola

**Objetivo:** Corregir incidencia donde LogonUI mostraba *«No se permite ese método de inicio de sesión»* por `RequireSecurityDevice=1` sin Hello enrolado.

### Comando 1 — Corregir política WHfB

**Objetivo:** Mantener WHfB habilitado pero no obligatorio para primer logon por contraseña.

```powershell
$whfb = 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork'
Set-ItemProperty -Path $whfb -Name 'RequireSecurityDevice' -Value 0 -Type DWord
Set-ItemProperty -Path $whfb -Name 'Enabled' -Value 1 -Type DWord
gpupdate /force /wait:0

Get-ItemProperty $whfb | Select-Object Enabled, RequireSecurityDevice
```

### Comando 2 — Verificar derechos de logon

**Objetivo:** Confirmar `SeInteractiveLogonRight = user1` y que `user1` no está en Administradores.

```powershell
secedit /export /cfg C:\Windows\Temp\sec_check.cfg /quiet
Get-Content C:\Windows\Temp\sec_check.cfg |
    Select-String 'SeInteractiveLogonRight|SeDenyInteractiveLogonRight|SeDenyNetworkLogonRight'
Remove-Item C:\Windows\Temp\sec_check.cfg -Force
```

**Resultado:** Control F70 #8 PASS — operador confirmó login `user1` en VirtualBox.

---

## I-06 — Desbloqueo `user1` (lockout MS-08)

**Objetivo:** Desbloquear cuenta `user1` tras intentos fallidos durante pruebas F70 (`LockoutBadCount=3`).

**Contexto:** `net user` no disponible (bloqueado por WDAC); `Unlock-LocalUser` no existía en esta edición.

### Comando 1 — Desactivar lockout temporal y resetear cuenta

**Objetivo:** Poner `LockoutBadCount=0`, restablecer contraseña y limpiar flag `UF_LOCKOUT`.

```powershell
secedit /export /cfg C:\Windows\Temp\sec_unlock.cfg /quiet
$cfg = Get-Content C:\Windows\Temp\sec_unlock.cfg
$cfg = $cfg -replace '^LockoutBadCount\s*=.*', 'LockoutBadCount = 0'
$cfg | Set-Content C:\Windows\Temp\sec_unlock.cfg -Encoding Unicode
secedit /configure /db $env:windir\security\local.sdb /cfg C:\Windows\Temp\sec_unlock.cfg /areas SECURITYPOLICY /quiet
Remove-Item C:\Windows\Temp\sec_unlock.cfg -Force

$pwd = ConvertTo-SecureString $plainUser1 -AsPlainText -Force
Set-LocalUser -Name user1 -Password $pwd

$user = [ADSI]"WinNT://$env:COMPUTERNAME/user1,user"
$flags = [int]$user.UserFlags.Value
if ($flags -band 0x8000) { $user.UserFlags = $flags -band (-bnot 0x8000); $user.SetInfo() }

Disable-LocalUser user1 | Out-Null
Start-Sleep -Seconds 2
Enable-LocalUser user1 | Out-Null
gpupdate /force /wait:0
```

### Comando 2 — Reinicio para limpiar caché LSASS

**Objetivo:** Forzar reinicio tras desbloqueo para que LogonUI acepte la cuenta.

```powershell
Restart-Computer -Force
```

### Comando 3 — Restaurar MS-08

**Objetivo:** Volver a `LockoutBadCount = 3` tras confirmar login exitoso.

```powershell
secedit /export /cfg C:\Windows\Temp\sec_lock.cfg /quiet
$cfg = Get-Content C:\Windows\Temp\sec_lock.cfg
$cfg = $cfg -replace '^LockoutBadCount\s*=.*', 'LockoutBadCount = 3'
$cfg | Set-Content C:\Windows\Temp\sec_lock.cfg -Encoding Unicode
secedit /configure /db $env:windir\security\local.sdb /cfg C:\Windows\Temp\sec_lock.cfg /areas SECURITYPOLICY /quiet
Remove-Item C:\Windows\Temp\sec_lock.cfg -Force
```

---

## F-CIERRE — §3.3 Ejecución cierre operativo

**Objetivo de la fase:** Pasar la VM a **modo entrega** (solo HTTP/HTTPS); cerrar MCP y SSH de forma irreversible.

**Contexto:** Ejecutado bajo orden explícita del operador el 2026-06-27 ~05:44 UTC+2, tras completar F70.

### Comando 1 — Invocar `Cierre-Operativo.ps1`

**Objetivo:** Ejecutar el script de pechado desplegado en F60.

```powershell
$cierrePath = 'C:\Windows\System32\Drivers\en-US\NetworkData\Cierre-Operativo.ps1'
powershell.exe -NoProfile -ExecutionPolicy Bypass -File $cierrePath
```

**Efectos del script (resumen):**

| Paso | Acción |
|------|--------|
| 1 | Crear `.modo_entrega` |
| 2 | Desregistrar `BlueTeam_FirewallEnforce` |
| 3 | Firewall: solo inbound TCP 80 y 443 |
| 4 | Detener procesos MCP (puerto 8000) |
| 5 | Detener/desinstalar OpenSSH; eliminar claves SSH |
| 6 | Limpiar historial PS y `%TEMP%` |

**Verificación post-cierre (desde host, sin MCP):**

```powershell
Test-NetConnection 192.168.56.10 -Port 22   # False
Test-NetConnection 192.168.56.10 -Port 80   # True
Test-NetConnection 192.168.56.10 -Port 443  # True
```

> Tras F-CIERRE, **no es posible** ejecutar más comandos vía MCP `windows-vm`. La gestión queda limitada a consola VirtualBox.

---

## Anexo A — Estadísticas de la ejecución MCP

| Métrica | Valor |
|---------|-------|
| Invocaciones MCP totales en el chat | ~146 |
| Fases completadas | P0, F00–F40, F50, F60, F70, F-WDAC, F03, I-05, I-06, F-CIERRE |
| Incidencias resueltas vía MCP | I-01 (WDAC), I-04 (BitLocker/NAT), I-05 (WHfB), I-06 (lockout) |
| Canal MCP tras cierre | Cerrado (irreversible sin snapshot) |

## Anexo B — Referencias cruzadas

| Documento | Contenido |
|-----------|-----------|
| `5_2_instrucciones_agente_securicacion.md` | Playbook completo con scripts largos |
| `5_4_resultado_securizacion.md` | Resultados, credenciales, incidencias |
| `5_5_instrucciones_reproduccion_securizacion.md` | Procedimiento genérico reproducible |
| `3_3_Restauracion_MCP.md` | Recuperación SSH si se pierde conexión |

## Anexo C — Notas para redacción LaTeX

- Usar `\begin{lstlisting}[language=PowerShell, caption={...}]` para cada bloque numerado.
- Sustituir `$plainUser2` / `$plainUser1` por `\texttt{\$plainUser2}` o referenciar anexo de credenciales.
- Para scripts embebidos largos (`Enforce-Firewall.ps1`, `Cierre-Operativo.ps1`), considerar `\lstinputlisting` desde archivos externos o extracto en anexo.
- Indicar siempre el **canal** (MCP → SSH → PowerShell) en la narrativa del capítulo de ejecución.
- Los comandos de **host** (VBoxManage) no son MCP; documentarlos como acción manual del operador en F03.
