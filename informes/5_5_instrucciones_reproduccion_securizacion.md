# Instrucciones de reproducción — Securización post-incidente WIN-VNQSUL89MUA

**Autor:** Agente LLM Blue Team (ejecución de referencia: 2026-06-26)  
**Basado en:** `5_2_instrucciones_agente_securicacion.md`  
**Resultado de la ejecución de referencia:** `5_4_resultado_securizacion.md`

> **IMPORTANTE:** Cada ejecución genera contraseñas y claves BitLocker nuevas. Las credenciales de este documento son genéricas. Consultar el `5_4` de la corrida específica para los valores reales.

---

## Prerrequisitos

### En el host (`alvar@MSI`)

| Componente | Requisito |
|-----------|-----------|
| VirtualBox | VM `entregablefinal_2` corriendo |
| PuTTY/plink | `C:\Program Files\PuTTY\plink.exe` disponible |
| SSH key | `C:\Users\alvar\.ssh\id_ed25519` registrada en VM |
| MCP Cursor | `%APPDATA%\Cursor\User\mcp.json` apuntando a `windows-vm` |
| Cursor / Agente LLM | MCP `windows-vm` conectado y herramienta `ejecutar_comando_powershell` disponible |

### En la VM (`WIN-VNQSUL89MUA`)

| Componente | Estado esperado |
|-----------|----------------|
| OpenSSH sshd | Running, Automatic, puerto 22 |
| Python 3.12 | `C:\Python312\python.exe` |
| MCP server | `C:\Python312\mcp_server.py` (WindowsCommander) |
| DefaultShell SSH | `C:\Windows\System32\cmd.exe` |
| user2 | En grupo Administradores |

### Verificar MCP antes de empezar

```powershell
# Desde el agente LLM vía MCP:
hostname
whoami
[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrator')
# Esperado: WIN-VNQSUL89MUA, user2, True
```

---

## Líneas rojas (invariantes)

| Prohibido | Motivo |
|-----------|--------|
| Ejecutar `Cierre-Operativo.ps1` | Corta SSH/MCP irreversiblemente |
| Ejecutar `nuke.ps1` | Mismo efecto |
| Cerrar puertos 22 u 8000 en firewall | Pierde canal de gestión |
| Crear `.modo_entrega` | Desactiva `BlueTeam_FirewallEnforce` |
| Aplicar `SeDenyNetworkLogonRight` a `user2` | Rompe SSH/MCP |

---

## Paso 0: Generar contraseñas (antes de F00)

Las contraseñas se generan en el agente, **no en la VM**. Usar esta función o equivalente:

```powershell
# Ejecutar LOCALMENTE en el agente (no vía MCP):
function New-SecureCatalogPassword {
    param([int]$Length = 24)
    Add-Type -AssemblyName 'System.Web' -ErrorAction SilentlyContinue
    do {
        $plain = [System.Web.Security.Membership]::GeneratePassword($Length, 6)
    } while ($plain.Length -lt 16 -or $plain -notmatch '[A-Z]' -or $plain -notmatch '[a-z]' `
             -or $plain -notmatch '\d' -or $plain -notmatch '[^a-zA-Z0-9]')
    return $plain
}

$plainUser2 = New-SecureCatalogPassword  # Para F00: rotar user2
$plainUser1 = New-SecureCatalogPassword  # Para F10: crear user1
```

> **Nota:** Si el sistema no tiene `System.Web`, generar manualmente cadenas de 24 chars con ≥6 mayúsculas, ≥6 minúsculas, ≥6 dígitos, ≥6 especiales.

**Reglas:**
- NO imprimir contraseñas en salida MCP de la VM
- SÍ incluirlas en `5_4_resultado_securizacion.md` (sección CREDENCIALES GENERADAS)

---

## Paso 1: P0 Preflight

```powershell
# P0.1 — Marcador entrega (debe ser False)
Test-Path 'C:\Windows\System32\Config\TxR\Diagnostics\.modo_entrega'

# P0.2 — SSH activo
Get-Service sshd | Select-Object Name, Status, StartType

# P0.3 — Sesión elevada
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "IsAdmin: $isAdmin"

# P0.4 — Firewall reglas gestión (pueden no existir aún)
Get-NetFirewallRule -DisplayName 'Allow_SSH_MCP','Allow_MCP_SSE' -ErrorAction SilentlyContinue | Select-Object DisplayName, Enabled
```

**Si algún control falla, no avanzar.**

---

## Paso 2: Fases de securización (F00 → F70)

### F00 — §1.1 Backdoor + rotación user2

```powershell
# Eliminar backdoor
if (Get-LocalUser -Name 'yishiego' -ErrorAction SilentlyContinue) {
    Remove-LocalUser -Name 'yishiego'
}

# Sanear Administradores (solo user2)
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

# Rotar contraseña user2 (usar $plainUser2 generado en Paso 0)
$User2Password = ConvertTo-SecureString $plainUser2 -AsPlainText -Force
Set-LocalUser -Name 'user2' -Password $User2Password
```

**Verificación PASS:** `Get-LocalUser 'yishiego'` sin resultado; solo user2 en Administradores.

---

### F01 — §1.2 Firewall

```powershell
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True `
    -DefaultInboundAction Block -DefaultOutboundAction Block

$rules = @(
    @{ Name = 'Allow_HTTP_In';    Port = 80   },
    @{ Name = 'Allow_HTTPS_In';   Port = 443  },
    @{ Name = 'Allow_SSH_MCP';    Port = 22   },
    @{ Name = 'Allow_MCP_SSE';    Port = 8000 }
)
foreach ($r in $rules) {
    if (-not (Get-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $r.Name -Direction Inbound `
            -Protocol TCP -LocalPort $r.Port -Action Allow | Out-Null
    } else {
        Enable-NetFirewallRule -DisplayName $r.Name
    }
}
```

**Verificación PASS:** Todos los perfiles Enabled=True, reglas 22 y 8000 Enabled=True.

---

### F02 — §1.3 BitLocker

```powershell
$blv = Get-BitLockerVolume -MountPoint 'C:'
if ($blv.ProtectionStatus -ne 'On') {
    Add-BitLockerKeyProtector -MountPoint 'C:' -TpmProtector | Out-Null
    $recovery = Add-BitLockerKeyProtector -MountPoint 'C:' -RecoveryPasswordProtector
    # GUARDAR recovery.KeyProtector.RecoveryPassword en 5_4 sección CREDENCIALES
    manage-bde -on C: -skiphardwaretest -UsedSpaceOnly
}
```

> **Nota:** En VirtualBox con vTPM, la clave se recupera si el TPM no coincide al arrancar.

**Verificación PASS:** `ProtectionStatus = On` o `VolumeStatus = EncryptionInProgress`.

---

### F03 — §1.4 VirtualBox: Eliminar NAT (MANUAL con protocolo BitLocker)

> **ADVERTENCIA:** Cambiar hardware del VirtualBox con BitLocker activo **SIN suspenderlo primero** provoca que la VM arranque en modo recuperación (solicita recovery key). El procedimiento correcto es el siguiente.

#### Procedimiento completo (referencia: 2026-06-27)

**Paso 1 — Suspender BitLocker vía MCP (con VM encendida):**
```powershell
Suspend-BitLocker -MountPoint 'C:' -RebootCount 1
Get-BitLockerVolume 'C:' | Select-Object MountPoint, ProtectionStatus
# Esperado: ProtectionStatus = Off (suspendido)
```

**Paso 2 — Apagar la VM limpiamente vía MCP:**
```powershell
Stop-Computer -Force
# Esperar ~30 s hasta que VirtualBox muestre "Powered Off"
```

**Paso 3 — Eliminar el adaptador NAT en el HOST (GUI VirtualBox o CLI):**
```powershell
# CLI en el host:
VBoxManage modifyvm "entregablefinal_2" --nic1 none
# Verificar:
VBoxManage showvminfo "entregablefinal_2" | Select-String "NIC 1"
# Esperado: "NIC 1: disabled"
```
> **Nota ejecución de referencia:** solo se eliminó NAT. Las CPUs **no se modificaron** (quedaron en 4 lógicas). El playbook menciona `--cpus 2` pero el operador decidió omitir ese cambio.

**Paso 4 — Arrancar la VM y esperar reconexión SSH/MCP (~90 s).**

**Paso 5 — Resellar BitLocker con los nuevos PCR vía MCP:**
```powershell
Resume-BitLocker -MountPoint 'C:'
Get-BitLockerVolume 'C:' | Select-Object MountPoint, ProtectionStatus, VolumeStatus
# Esperado: ProtectionStatus = On, VolumeStatus = FullyEncrypted
```

**Verificación:**
```powershell
# Sin IP NAT (10.0.2.x)
ipconfig | Select-String 'IPv4'
# Esperado: solo 192.168.56.10

# BitLocker On
(Get-BitLockerVolume 'C:').ProtectionStatus  # On
```

**Control 12 (F70):** PASS — NIC1/NAT eliminada, solo `192.168.56.10`.  
**Control 13 (F70):** N/A — CPUs no modificadas (decisión del operador).

---

### F10 — MS-01 (variante agente)

```powershell
# Crear user1 (usar $plainUser1 del Paso 0)
$User1Password = ConvertTo-SecureString $plainUser1 -AsPlainText -Force
if (-not (Get-LocalUser -Name 'user1' -ErrorAction SilentlyContinue)) {
    New-LocalUser -Name 'user1' -Password $User1Password `
        -Description 'Cuenta operativa sin privilegios' | Out-Null
    Add-LocalGroupMember -Group 'Usuarios' -Member 'user1'
}

# Restricciones logon (NO SeDenyNetworkLogonRight para user2)
secedit /export /cfg C:\Windows\Temp\sec_logon.cfg /quiet
$cfg = Get-Content C:\Windows\Temp\sec_logon.cfg
$cfg = $cfg -replace '^SeInteractiveLogonRight\s*=.*', 'SeInteractiveLogonRight = user1'
$cfg = $cfg -replace '^SeDenyInteractiveLogonRight\s*=.*', 'SeDenyInteractiveLogonRight = user2,DefaultAccount,WDAGUtilityAccount'
$cfg | Set-Content C:\Windows\Temp\sec_logon.cfg -Encoding Unicode
secedit /configure /db $env:windir\security\local.sdb /cfg C:\Windows\Temp\sec_logon.cfg /areas USER_RIGHTS /quiet
Remove-Item C:\Windows\Temp\sec_logon.cfg -Force
gpupdate /force /quiet

# WHfB — usar RequireSecurityDevice=0 para permitir primer logon por contraseña
$whfb = 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork'
if (-not (Test-Path $whfb)) { New-Item -Path $whfb -Force | Out-Null }
Set-ItemProperty -Path $whfb -Name 'Enabled' -Value 1 -Type DWord
Set-ItemProperty -Path $whfb -Name 'RequireSecurityDevice' -Value 0 -Type DWord
```

**⚠️ Advertencia de reproducción:** Si `New-LocalUser` con `-PasswordNeverExpires $false` da error "no parameter accepts argument 'False'", omitir ese parámetro (el default es `$false`).

**⚠️ WHfB:** No usar `RequireSecurityDevice=1` si `user1` no tiene Windows Hello enrolado; bloquea el logon por contraseña en consola (ver advertencia §9).

---

### F11 — MS-02

```powershell
$path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
@('dontdisplaylastusername', 'DontDisplayLastUserName', 'HideFastUserSwitching') |
    ForEach-Object { Set-ItemProperty -Path $path -Name $_ -Value 1 -Type DWord -Force }
```

---

### F12 — MS-08

```powershell
net accounts /lockoutthreshold:3
net accounts /lockoutduration:30
net accounts /lockoutwindow:15
net accounts /minpwlen:16
net accounts /maxpwage:90
net accounts /uniquepw:24
```

---

### F20 — MS-03 (Enforce-Firewall + tarea SYSTEM)

- Crear `C:\Windows\System32\Drivers\en-US\NetworkData\Enforce-Firewall.ps1` (ver §5_2)
- Registrar tarea `BlueTeam_FirewallEnforce` como SYSTEM cada 5 min
- **Usar `-RepetitionDuration (New-TimeSpan -Days 3650)` — NO `[TimeSpan]::MaxValue`** (causa error XML)
- Crear `Deny-Netsh.xml` e intentar `CiTool.exe --update-policy` (puede fallar con 0x80070216)

---

### F21 — MS-04 (BitLocker GPO + WDAC manage-bde)

```powershell
$fvePath = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
if (-not (Test-Path $fvePath)) { New-Item -Path $fvePath -Force | Out-Null }
Set-ItemProperty -Path $fvePath -Name 'EnableBDEWithNoTPM' -Value 0 -Type DWord
Set-ItemProperty -Path $fvePath -Name 'UseTPMPIN'          -Value 0 -Type DWord
Set-ItemProperty -Path $fvePath -Name 'RDVDenyWriteAccess' -Value 1 -Type DWord
```

---

### F22 — MS-05 (AdminGuard + WDAC net)

- Crear `AdminGuard.ps1` en `NetworkData`
- Registrar tarea `BlueTeam_AdminGuard` como SYSTEM cada 5 min (oculta)
- Crear `Deny-Net.xml` e intentar `CiTool.exe --update-policy`

---

### F30 — MS-06 (Sysmon)

```powershell
$sysmonExe = 'C:\Windows\System32\Drivers\en-US\NetworkData\WinNetSvc.exe'
$xmlPath   = 'C:\Windows\System32\Drivers\en-US\NetworkData\WinNetSvc.xml'
# Crear xmlPath con reglas HardeningConsolaInteractiva (ver §5_2 F30)
& $sysmonExe -c $xmlPath
```

---

### F31 — MS-07 (Historial PS + transcripción)

```powershell
# Desactivar historial en profile global
$profilePath = 'C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1'
Add-Content -Path $profilePath -Value "`nif (Get-Module PSReadLine -EA SilentlyContinue) { Set-PSReadLineOption -HistorySaveStyle SaveNothing }"

# Eliminar historial existente
Get-ChildItem 'C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt' -EA SilentlyContinue | Remove-Item -Force

# Habilitar transcripción + ScriptBlock
$trans = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
$sbLog = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
@($trans, $sbLog) | ForEach-Object { if (-not (Test-Path $_)) { New-Item -Path $_ -Force | Out-Null } }
Set-ItemProperty -Path $trans -Name 'EnableTranscripting' -Value 1 -Type DWord
Set-ItemProperty -Path $trans -Name 'OutputDirectory' -Value 'C:\Windows\System32\Config\TxR\PSTranscripts' -Type String
Set-ItemProperty -Path $sbLog -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord
```

---

### F32 — MS-09 (Prevención apagado)

```powershell
secedit /export /cfg C:\Windows\Temp\sec_shutdown.cfg /quiet
(Get-Content C:\Windows\Temp\sec_shutdown.cfg) | ForEach-Object {
    if ($_ -match '^SeShutdownPrivilege\s*=') { 'SeShutdownPrivilege = ' } else { $_ }
} | Set-Content C:\Windows\Temp\sec_shutdown.cfg -Encoding Unicode
secedit /configure /db $env:windir\security\local.sdb /cfg C:\Windows\Temp\sec_shutdown.cfg /areas USER_RIGHTS /quiet
Remove-Item C:\Windows\Temp\sec_shutdown.cfg -Force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ShutdownWithoutLogon' -Value 0 -Type DWord
```

---

### F40 — MS-10 (ACLs SecureCatalog + SQL)

```powershell
$appPath = 'C:\inetpub\wwwroot\SecureCatalog'
icacls $appPath /inheritance:r /T /C /Q
icacls $appPath /grant "IIS AppPool\SecureCatalogPool:(OI)(CI)RX" /T
icacls $appPath /grant "IUSR:(OI)(CI)RX" /T
icacls $appPath /grant "SYSTEM:(OI)(CI)F" /T
icacls $appPath /grant "BUILTIN\Administradores:(OI)(CI)F" /T
@('user1','user2') | ForEach-Object { icacls $appPath /deny "${_}:(OI)(CI)RX" /T }

# SQL (omitir -TrustServerCertificate si la versión del módulo no lo acepta)
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

### F50 — Reinicio WDAC

```powershell
Restart-Computer -Force
# Esperar ~3-5 minutos para que Windows Server 2025 arranque con BitLocker TPM
# El MCP se reconecta automáticamente vía SSH
```

**Post-reinicio:** Verificar `Get-Service sshd`, firewall, BitLocker.

---

### F-WDAC — Remediación WDAC (post-F70, si XML del playbook fallan)

> Ejecutar **solo si** `CiTool --update-policy` sobre los `Deny-*.xml` del playbook devuelve `0x80070216`. Ver advertencia §4 al final del documento para el procedimiento completo.

**Resumen:** generar política base `BlueTeam-Deny-LOLBins` con `Merge-CIPolicy` + `AllowAll.xml`, aplicar vía `ConvertFrom-CIPolicy` → `.cip`, probar en Audit, pasar a Enforce, reiniciar dos veces.

**Verificación Enforce esperada:**
```powershell
CiTool.exe --list-policies | Select-String 'BlueTeam'
netsh advfirewall show allprofiles state    # Bloqueado
manage-bde -status C:                        # Bloqueado
net user                                      # Bloqueado
Get-Service sshd                              # Running
```

---

### F60 — Desplegar Cierre-Operativo.ps1

- Escribir el script en `C:\Windows\System32\Drivers\en-US\NetworkData\Cierre-Operativo.ps1` (ver §5_2 F60)
- **NO ejecutar** en esta fase — solo desplegar
- Verificar: `Test-Path $cierrePath` → True

---

### F-CIERRE — §3.3 Ejecutar Cierre-Operativo (SOLO bajo orden explícita del operador)

> **IRREVERSIBLE** para MCP/SSH. Ejecutar únicamente cuando el trabajo Blue Team haya terminado y F70 esté completado.

**Comando (vía MCP o consola admin):**
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  'C:\Windows\System32\Drivers\en-US\NetworkData\Cierre-Operativo.ps1'
```

**Efectos esperados:**
- Crea `.modo_entrega` → desactiva lógica operativa de `BlueTeam_FirewallEnforce`
- Desregistra `BlueTeam_FirewallEnforce`
- Firewall: solo inbound TCP 80/443
- Detiene MCP (puerto 8000) y desinstala OpenSSH
- Limpia historial y `%TEMP%`
- Log: `C:\Windows\System32\Config\TxR\Diagnostics\cierre_operativo.log`

**Verificación post-cierre (desde host, sin SSH):**
```powershell
# MCP: debe fallar conexión
Test-NetConnection 192.168.56.10 -Port 22   # TcpTestSucceeded: False
Test-NetConnection 192.168.56.10 -Port 80   # TcpTestSucceeded: True
Test-NetConnection 192.168.56.10 -Port 443  # TcpTestSucceeded: True
Test-NetConnection 192.168.56.10 -Port 8000 # TcpTestSucceeded: False
```

**Único canal de gestión restante:** consola VirtualBox (LogonUI).

> **NO usar** el cierre operativo como workaround para problemas de conectividad MCP.

---

### F70 — Verificación final

```powershell
# Ejecutar este bloque consolidado:
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
    $r += [PSCustomObject]@{ Control='WDAC BlueTeam activa'; Pass=(CiTool.exe --list-policies 2>&1 | Out-String) -match 'BlueTeam_Deny_LOLBins' }
    $r | Format-Table -AutoSize
    $failed = $r | Where-Object { -not $_.Pass }
    if ($failed) { Write-Host '[!] CONTROLES FALLIDOS' -ForegroundColor Red; return $false }
    Write-Host '[+] Todos los controles PASS.' -ForegroundColor Green
    return $true
}
Test-AgentHardening
```

**Esperado:** 11/11 PASS (incl. WDAC si se aplicó F-WDAC), último resultado: `True`.

---

## Advertencias de reproducción conocidas

### 1. `&&` no es válido en PowerShell antiguo
Usar `;` en lugar de `&&` para encadenar comandos en el MCP.

### 2. `-PasswordNeverExpires $false` causa error
Omitir el parámetro; el default en `New-LocalUser` ya es `$false`.

### 3. `[TimeSpan]::MaxValue` en `New-ScheduledTaskTrigger`
Usar `-RepetitionDuration (New-TimeSpan -Days 3650)` en su lugar.

### 4. `CiTool.exe --update-policy` error 0x80070216 — SOLUCIÓN

Los XML manuales del playbook (`Deny-Netsh.xml`, etc.) fallan con `0x80070216` en Windows Server 2025 Build 26100. **No reintentar esos XML.**

**Procedimiento correcto** (referencia: remediación 2026-06-27):

```powershell
Import-Module ConfigCI
$outDir = 'C:\Windows\System32\Drivers\en-US\NetworkData'
$workDir = 'C:\Windows\Temp\wdac_work'
New-Item -ItemType Directory -Path $workDir -Force | Out-Null

# 1. Copiar plantilla AllowAll (no leer directamente desde schemas — acceso denegado)
$allowAllCopy = Join-Path $workDir 'AllowAll.xml'
Copy-Item (Join-Path $env:windir 'schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml') $allowAllCopy -Force

# 2. Crear reglas Deny (FilePublisher con fallback)
$binaries = @(
  "$env:windir\System32\netsh.exe",
  "$env:windir\System32\manage-bde.exe",
  "$env:windir\System32\net.exe",
  "$env:windir\System32\net1.exe"
)
$denyRules = @()
foreach ($b in $binaries) {
  $denyRules += New-CIPolicyRule -Level FilePublisher -DriverFilePath $b `
    -Fallback SignedVersion,Publisher,Hash -Deny
}

# 3. Fusionar en política BASE (las reglas Deny NO van en supplemental)
$xml = Join-Path $outDir 'BlueTeam-Deny-LOLBins.xml'
Merge-CIPolicy -PolicyPaths $allowAllCopy -OutputFilePath $xml -Rules $denyRules
Set-CiPolicyIdInfo -FilePath $xml -PolicyName 'BlueTeam_Deny_LOLBins' -ResetPolicyID

# 4. Audit primero
Set-RuleOption -FilePath $xml -Option 3
$cipAudit = Join-Path $workDir 'BlueTeam-Deny-LOLBins-audit.cip'
ConvertFrom-CIPolicy -XmlFilePath $xml -BinaryFilePath $cipAudit
CiTool.exe --update-policy $cipAudit
# → Reiniciar VM

# 5. Verificar Audit: eventos 3076 en CodeIntegrity/Operational; SSH/MCP OK
# 6. Pasar a Enforce
Set-RuleOption -FilePath $xml -Option 3 -Delete
$cipEnforce = Join-Path $workDir 'BlueTeam-Deny-LOLBins-enforce.cip'
ConvertFrom-CIPolicy -XmlFilePath $xml -BinaryFilePath $cipEnforce
CiTool.exe --update-policy $cipEnforce
# → Reiniciar VM

# 7. Verificar Enforce
CiTool.exe --list-policies   # BlueTeam_Deny_LOLBins listada
netsh advfirewall show allprofiles state   # Bloqueado por App Control
manage-bde -status C:                       # Bloqueado
net user                                    # Bloqueado
powershell -NoProfile -Command 'Write-Host OK'  # OK
```

**Puntos críticos:**
- `CiTool --update-policy` sobre **XML** falla (`0x80070216`); sobre **`.cip`** generado por `ConvertFrom-CIPolicy` funciona
- Las reglas Deny deben ir en política **base** fusionada con `AllowAll.xml`, no en supplemental
- Siempre probar en **Audit** antes de Enforce; dos reinicios necesarios
- Policy ID resultante: `{65511DF1-8D54-431B-A929-A4CBDADE5EC2}`

### 5. `Invoke-Sqlcmd -TrustServerCertificate`
Si el módulo SqlServer instalado no acepta `-TrustServerCertificate`, omitir dicho parámetro.

### 6. Reglas de firewall buscadas por Name vs DisplayName
El `Test-AgentHardening` original del playbook usa `Get-NetFirewallRule 'Allow_SSH_MCP'` (posicional = Name). Las reglas se crean con `-DisplayName`, por lo que el parámetro correcto es `-DisplayName 'Allow_SSH_MCP'`.

### 7. Pérdida temporal de SSH al eliminar reglas backdoor
Si se eliminan las reglas `Backdoor MCP-SSE` del Red Team, la tarea `BlueTeam_FirewallEnforce` restaura SSH en ≤5 minutos automáticamente.

### 8. BitLocker recovery al cambiar hardware VirtualBox
Cualquier cambio en la configuración de hardware de VirtualBox (adaptadores de red, CPUs, etc.) mientras BitLocker está activo **sin haberlo suspendido previamente** provoca que el vTPM invalide las mediciones PCR selladas. La VM arranca en modo recuperación (pantalla negra/azul solicitando la recovery key).

**Síntoma:** la VM no arranca normalmente, SSH/MCP no disponibles.

**Solución de emergencia** (si ya se cometió el error):
1. Abrir consola VirtualBox → introducir la recovery key del `5_4`
2. Dentro de la VM: ejecutar `Suspend-BitLocker -MountPoint 'C:' -RebootCount 1`
3. Revertir el cambio de hardware en VirtualBox
4. Arrancar la VM normalmente (BitLocker suspendido, no pide key)
5. Aplicar el cambio de hardware con el procedimiento correcto (ver F03 arriba)

**Prevención:** Siempre ejecutar `Suspend-BitLocker` + apagado limpio **antes** de modificar hardware en VirtualBox.

### 9. WHfB bloquea logon de `user1` en consola

**Síntoma:** LogonUI muestra *«No se permite ese método de inicio de sesión»* al intentar entrar con `user1`.

**Causa:** `RequireSecurityDevice=1` en `PassportForWork` exige TPM/Hello configurado; `user1` no lo tiene.

**Solución:**
```powershell
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork' `
  -Name 'RequireSecurityDevice' -Value 0 -Type DWord
gpupdate /force
```

**Nota control 9:** `user2` en esta VM es la cuenta Administrator integrada (RID 500). Windows puede ignorar `SeDenyInteractiveLogonRight` para esa cuenta. Verificar manualmente en VirtualBox.

### 10. user1 bloqueada durante pruebas F70 (lockout MS-08)

**Síntoma:** *«La cuenta está bloqueada y no se puede utilizar»* tras intentos fallidos en LogonUI.

**Causa:** `LockoutBadCount=3` (MS-08). `net user` no sirve (bloqueado por WDAC); `Unlock-LocalUser` puede no existir.

**Solución (referencia ejecución 2026-06-27):**
```powershell
# 1. Desactivar lockout temporalmente
secedit /export /cfg C:\Windows\Temp\sec_unlock.cfg /quiet
# Editar: LockoutBadCount = 0
secedit /configure /db $env:windir\security\local.sdb /cfg C:\Windows\Temp\sec_unlock.cfg /areas SECURITYPOLICY /quiet

# 2. Reset password admin
Set-LocalUser -Name user1 -Password (ConvertTo-SecureString '<pwd>' -AsPlainText -Force)

# 3. Reiniciar VM (limpia caché LSASS)
Restart-Computer -Force

# 4. Tras confirmar login, restaurar MS-08:
# LockoutBadCount = 3
```

**Prevención:** Corregir WHfB (§9) antes de probar contraseña. Copiar/pegar credenciales del `5_4`.

---

## Recuperación de acceso (si MCP/SSH se pierde)

Consultar `3_3_Restauracion_MCP.md`. Resumen:

```powershell
# Desde host, acceso con nueva contraseña user2 (ver 5_4 de esta corrida):
$plink = "C:\Program Files\PuTTY\plink.exe"
echo "y" | & $plink -pw "<nueva_pwd_user2>" -batch user2@192.168.56.10 "powershell -Command hostname"
```

**NO ejecutar §3.3 (Cierre-Operativo) como workaround para problemas de conectividad.** Solo tras completar F70 y con orden explícita del operador (ver F-CIERRE arriba).

---

## Entregables generados por cada ejecución

| Archivo | Contenido |
|---------|-----------|
| `5_4_resultado_securizacion.md` | Informe completo con **contraseñas y clave BitLocker de esa corrida** |
| `5_5_instrucciones_reproduccion_securizacion.md` | Este documento (genérico, reutilizable) |

---

*Fin de instrucciones de reproducción — Agente LLM Blue Team, 2026-06-26*
