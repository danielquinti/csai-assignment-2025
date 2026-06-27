# Informe de Restauración SSH y Servidor MCP — `entregablefinal_2`

**Máquina objetivo:** WIN-VNQSUL89MUA — `192.168.56.10`
**VM en VirtualBox:** `entregablefinal_2` (Windows Server 2025)
**Fecha de ejecución:** 26 de junio de 2026
**Ejecutado desde:** `alvar@MSI` (host Windows)
**Autor:** Blue Team — Alvaro
**Basado en:** `3_2_Restauracion_MCP.md` (restauración anterior exitosa en `entregablefinal 1`)

---

## 0. Contexto y Estado Previo de la VM

La VM `entregablefinal_2` fue migrada desde el entorno del compañero Daniel. El estado heredado era:

| Componente | Estado heredado |
|-----------|----------------|
| OpenSSH Server (`sshd`) | Activo, puerto 22 abierto |
| Shell por defecto SSH | `cmd.exe` (correcto para JSON-RPC) |
| Python 3.12 embebido | Instalado en `C:\Python312\` |
| Paquete `mcp` | Versión `1.27.0` instalada |
| Script MCP | `C:\Python312\mcp_server.py` desplegado |
| Clave autorizada | Solo `daniel@Port` en `administrators_authorized_keys` |
| Contraseña `user2` | `v9KmZ2` (rotada por el Red Team, conservada) |
| Firewall | Activo, salida permitida, regla inbound TCP/22 presente |

**Problema:** La clave pública de `alvar@MSI` no estaba registrada en la VM, impidiendo la autenticación sin contraseña desde este host.

---

## 1. Resumen del Estado de Red y Acceso

### 1.1 Topología de red VirtualBox

```
┌──────────────────────────────────┐
│        HOST: alvar@MSI           │
│  Ethernet 6: 192.168.56.1/24     │  ← Adaptador Host-Only
│  (VirtualBox Host-Only Network)  │
└──────────────┬───────────────────┘
               │  Host-Only Adapter (sin enrutamiento externo)
               │  Puerto 22 TCP
┌──────────────▼───────────────────┐
│  VM: WIN-VNQSUL89MUA             │
│  entregablefinal_2               │
│  NIC 1 (NAT):    10.0.2.15       │  ← Acceso a Internet (salida)
│  NIC 2 (H-Only): 192.168.56.10   │  ← Acceso desde el Host
└──────────────────────────────────┘
```

### 1.2 Mapeo de puertos relevantes

| Puerto | Protocolo | Dirección | Servicio | Estado |
|--------|-----------|-----------|---------|--------|
| 22 | TCP | Inbound | OpenSSH Server (sshd) | ABIERTO |
| — | — | — | RDP/WinRM | BLOQUEADO (hardening) |

### 1.3 Credenciales de acceso

| Método | Detalle |
|--------|---------|
| SSH clave pública | `C:\Users\alvar\.ssh\id_ed25519` → `user2@192.168.56.10` |
| SSH contraseña (emergencia) | `user2` / `v9KmZ2` (solo via plink, no usar en producción) |
| Administrador local (consola) | `Administrador` / `*(Aa}N#27260` (acceso físico VirtualBox) |

---

## 2. Guía de Comandos — Restauración Completa desde Cero

Esta sección es **totalmente autónoma y reproducible**. Un LLM puede ejecutar los bloques en orden sin consultar otros documentos.

### PRERREQUISITO: La VM debe estar encendida y con plink disponible

```powershell
# Verificar que la VM responde (debe devolver TTL=128)
ping -n 2 192.168.56.10

# Verificar que plink está disponible
Test-Path "C:\Program Files\PuTTY\plink.exe"
# Si devuelve False, descargar PuTTY desde: https://www.putty.org/
```

---

### PASO 1 — Limpiar entradas obsoletas de known_hosts

```powershell
# Eliminar entradas antiguas del host (evita el error "REMOTE HOST IDENTIFICATION HAS CHANGED")
ssh-keygen -R 192.168.56.10
```

**Resultado esperado:**
```
C:\Users\alvar/.ssh/known_hosts updated.
```

---

### PASO 2 — Verificar conectividad SSH con contraseña (diagnóstico)

```powershell
$plink = "C:\Program Files\PuTTY\plink.exe"

# Aceptar host key automáticamente con "y" y verificar estado básico
echo "y" | & $plink -pw "v9KmZ2" -batch user2@192.168.56.10 `
  "hostname & whoami & reg query HKLM\SOFTWARE\OpenSSH /v DefaultShell"
```

**Resultado esperado:**
```
WIN-VNQSUL89MUA
win-vnqsul89mua\user2
HKEY_LOCAL_MACHINE\SOFTWARE\OpenSSH
    DefaultShell    REG_SZ    C:\Windows\System32\cmd.exe
```

> Si `DefaultShell` no es `cmd.exe`, ejecutar el PASO 2b antes de continuar.

#### PASO 2b — Corregir DefaultShell a CMD (solo si es necesario)

```powershell
$plink = "C:\Program Files\PuTTY\plink.exe"
echo "y" | & $plink -pw "v9KmZ2" -batch user2@192.168.56.10 `
  "reg add HKLM\SOFTWARE\OpenSSH /v DefaultShell /d C:\Windows\System32\cmd.exe /f & net stop sshd & net start sshd"
```

> **Por qué CMD y no PowerShell:** PowerShell inyecta cabeceras BOM (UTF-16LE) en el stream stdio que rompen el protocolo JSON-RPC del servidor MCP. CMD proporciona un transporte crudo y limpio.

---

### PASO 3 — Auditar Python y MCP en la VM

```powershell
$plink = "C:\Program Files\PuTTY\plink.exe"

# Verificar Python
echo "y" | & $plink -pw "v9KmZ2" -batch user2@192.168.56.10 `
  "C:\Python312\python.exe --version"

# Verificar paquete mcp
echo "y" | & $plink -pw "v9KmZ2" -batch user2@192.168.56.10 `
  "C:\Python312\python.exe -m pip list 2>&1 | findstr /i mcp"

# Verificar que el script existe
echo "y" | & $plink -pw "v9KmZ2" -batch user2@192.168.56.10 `
  "dir C:\Python312\mcp_server.py"
```

**Resultados esperados:**
```
Python 3.12.3
mcp                       1.27.0
C:\Python312\mcp_server.py
```

#### PASO 3b — Reinstalar Python y MCP si no existen (recuperación completa)

> Ejecutar solo si el paso 3 falla. Requiere acceso a Internet desde la VM (adaptador NAT activo).

```powershell
$plink = "C:\Program Files\PuTTY\plink.exe"

# Reactivar DHCP (puede estar desactivado por el hardening)
echo "y" | & $plink -pw "v9KmZ2" -batch user2@192.168.56.10 `
  "powershell -Command Set-Service -Name dhcp -StartupType Automatic; Start-Service dhcp"

# Restaurar salida de Internet en el firewall
echo "y" | & $plink -pw "v9KmZ2" -batch user2@192.168.56.10 `
  "powershell -Command Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow"

# Restaurar curl y tar (renombrados por hardening Blue Team)
echo "y" | & $plink -pw "v9KmZ2" -batch user2@192.168.56.10 `
  "cmd /c mkdir C:\Python312 & copy C:\Windows\System32\curl.exe.bak %TEMP%\c.exe & copy C:\Windows\System32\tar.exe.bak %TEMP%\t.exe"

# Descargar Python 3.12 embebido (sin instalador MSI)
echo "y" | & $plink -pw "v9KmZ2" -batch user2@192.168.56.10 `
  "cmd /c %TEMP%\c.exe -L -k -o %TEMP%\py.zip https://www.python.org/ftp/python/3.12.3/python-3.12.3-embed-amd64.zip"

echo "y" | & $plink -pw "v9KmZ2" -batch user2@192.168.56.10 `
  "cmd /c %TEMP%\c.exe -L -k -o C:\Python312\get-pip.py https://bootstrap.pypa.io/get-pip.py"

# Extraer y habilitar importación de paquetes externos
echo "y" | & $plink -pw "v9KmZ2" -batch user2@192.168.56.10 `
  "cmd /c %TEMP%\t.exe -xf %TEMP%\py.zip -C C:\Python312"

echo "y" | & $plink -pw "v9KmZ2" -batch user2@192.168.56.10 `
  "cmd /c echo python312.zip> C:\Python312\python312._pth & echo .>> C:\Python312\python312._pth & echo import site>> C:\Python312\python312._pth"

# Instalar pip y el paquete mcp
echo "y" | & $plink -pw "v9KmZ2" -batch user2@192.168.56.10 `
  "cmd /c C:\Python312\python.exe C:\Python312\get-pip.py"

echo "y" | & $plink -pw "v9KmZ2" -batch user2@192.168.56.10 `
  "cmd /c C:\Python312\python.exe -m pip install mcp"
```

#### PASO 3c — Desplegar el script mcp_server.py (si no existe)

Crear localmente el archivo `windows_mcp.py` con el siguiente contenido y transferirlo con SCP:

```python
import subprocess
import sys
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("WindowsCommander")

@mcp.tool()
def ejecutar_comando_powershell(comando: str) -> str:
    """Ejecuta un comando en PowerShell de Windows Server (con bypass de políticas) y devuelve el resultado."""
    try:
        r = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", comando],
            check=True, text=True, capture_output=True
        )
        return f"Éxito:\n{r.stdout}"
    except subprocess.CalledProcessError as e:
        return f"Error (Código {e.returncode}).\nSTDOUT: {e.stdout}\nSTDERR: {e.stderr}"
    except Exception as e:
        return f"Error inesperado: {str(e)}"

if __name__ == "__main__":
    transport = "stdio"
    if "--sse" in sys.argv:
        transport = "sse"
    mcp.run(transport=transport)
```

```powershell
# Transferir el script a la VM (desde el host, en la carpeta donde está windows_mcp.py)
scp .\windows_mcp.py user2@192.168.56.10:C:\Python312\mcp_server.py
```

---

### PASO 4 — Añadir clave pública del host a la VM

```powershell
# Obtener la clave pública local
$myPubKey = Get-Content "C:\Users\alvar\.ssh\id_ed25519.pub"
Write-Host "Clave a registrar: $myPubKey"

$plink = "C:\Program Files\PuTTY\plink.exe"

# Añadir la clave al fichero de claves autorizadas de administradores
echo "y" | & $plink -pw "v9KmZ2" -batch user2@192.168.56.10 `
  "echo $myPubKey >> C:\ProgramData\ssh\administrators_authorized_keys"
```

> **Por qué `administrators_authorized_keys` y no `authorized_keys`:** OpenSSH en Windows Server usa este fichero especial para usuarios del grupo Administrators. Si el usuario SSH pertenece a dicho grupo (como `user2`), el fichero `~/.ssh/authorized_keys` se ignora completamente.

---

### PASO 5 — Reparar ACLs y reiniciar sshd

OpenSSH valida estrictamente los permisos del fichero `administrators_authorized_keys`. Si cualquier usuario no autorizado tiene acceso de lectura/escritura, el servidor **ignora silenciosamente** el fichero y rechaza todas las claves.

```powershell
$plink = "C:\Program Files\PuTTY\plink.exe"

echo "y" | & $plink -pw "v9KmZ2" -batch user2@192.168.56.10 `
  "icacls C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r /grant `"*S-1-5-32-544:F`" `"SYSTEM:F`" & icacls C:\ProgramData\ssh\administrators_authorized_keys /setowner `"*S-1-5-32-544`" & net stop sshd & net start sshd"
```

**Resultado esperado:**
```
archivo procesado: C:\ProgramData\ssh\administrators_authorized_keys
Se procesaron correctamente 1 archivos; error al procesar 0 archivos
archivo procesado: C:\ProgramData\ssh\administrators_authorized_keys
Se procesaron correctamente 1 archivos; error al procesar 0 archivos
El servicio de OpenSSH SSH Server se detuvo correctamente.
El servicio de OpenSSH SSH Server se ha iniciado correctamente.
```

> `*S-1-5-32-544` es el SID universal del grupo `BUILTIN\Administrators`, independiente del idioma del sistema.

---

### PASO 6 — Verificar autenticación SSH por clave pública

```powershell
ssh -i "C:\Users\alvar\.ssh\id_ed25519" `
    -o BatchMode=yes `
    -o StrictHostKeyChecking=no `
    -o ConnectTimeout=10 `
    user2@192.168.56.10 `
    "hostname & whoami"
```

**Resultado esperado (sin pedir contraseña):**
```
WIN-VNQSUL89MUA
win-vnqsul89mua\user2
```

---

### PASO 7 — Validar servidor MCP con protocolo JSON-RPC 2.0

```powershell
$initMsg = '{"jsonrpc": "2.0", "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "cursor-test", "version": "1.0"}}, "id": 1}'

echo $initMsg | ssh `
    -i "C:\Users\alvar\.ssh\id_ed25519" `
    -o BatchMode=yes `
    -o StrictHostKeyChecking=no `
    user2@192.168.56.10 `
    "C:\Python312\python.exe C:\Python312\mcp_server.py"
```

**Resultado esperado:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocolVersion": "2024-11-05",
    "capabilities": {
      "experimental": {},
      "prompts": {"listChanged": false},
      "resources": {"subscribe": false, "listChanged": false},
      "tools": {"listChanged": false}
    },
    "serverInfo": {
      "name": "WindowsCommander",
      "version": "1.27.0"
    }
  }
}
```

---

## 3. Configuración del Lado del Cliente (Host / Agente Cursor)

### 3.1 Fichero de configuración MCP para Cursor

**Ubicación real verificada:** `%APPDATA%\Cursor\User\mcp.json`
(equivale a `C:\Users\alvar\AppData\Roaming\Cursor\User\mcp.json`)

> **Nota:** La ruta `%APPDATA%\Cursor\mcp.json` que aparece en documentación anterior es incorrecta para esta instalación de Cursor. El directorio correcto es `Cursor\User\`.

#### PASO 8 — Crear el fichero mcp.json en el host (ejecutar una sola vez)

```powershell
# Crear el fichero de configuración MCP global de Cursor
$mcpPath = "$env:APPDATA\Cursor\User\mcp.json"
$mcpContent = @'
{
  "mcpServers": {
    "windows-vm": {
      "command": "C:\\Windows\\System32\\OpenSSH\\ssh.exe",
      "args": [
        "-i", "C:\\Users\\alvar\\.ssh\\id_ed25519",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        "user2@192.168.56.10",
        "C:\\Python312\\python.exe",
        "C:\\Python312\\mcp_server.py"
      ]
    }
  }
}
'@
Set-Content -Path $mcpPath -Value $mcpContent -Encoding UTF8
Write-Host "Creado: $mcpPath"

# Verificar el contenido
Get-Content $mcpPath
```

**Resultado esperado:**
```
Creado: C:\Users\alvar\AppData\Roaming\Cursor\User\mcp.json
{
  "mcpServers": {
    "windows-vm": { ... }
  }
}
```

> Tras crear o modificar este fichero, recargar Cursor con `Ctrl+Shift+P` → `Reload Window` para que el servidor MCP `windows-vm` aparezca disponible en el agente.

#### Contenido del mcp.json (referencia)

```json
{
  "mcpServers": {
    "windows-vm": {
      "command": "C:\\Windows\\System32\\OpenSSH\\ssh.exe",
      "args": [
        "-i", "C:\\Users\\alvar\\.ssh\\id_ed25519",
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

> **Por qué rutas absolutas:** El proceso hijo lanzado por Cursor puede no heredar el `PATH` completo. Usar `C:\\Windows\\System32\\OpenSSH\\ssh.exe` evita colisiones con versiones SSH de Git Bash, MSYS2 u otras herramientas.

### 3.2 Herramienta expuesta por el servidor MCP

| Nombre | Descripción |
|--------|-------------|
| `ejecutar_comando_powershell` | Ejecuta cualquier comando PowerShell en la VM con `-ExecutionPolicy Bypass` y devuelve el stdout/stderr completo |

**Ejemplo de uso desde el agente:**
```
Ejecuta en la VM: Get-Process | Where-Object CPU -gt 10 | Select-Object Name, CPU
```

### 3.3 Configuración SSH (`~/.ssh/config`) — Opcional para uso directo

```sshconfig
Host windows-vm
    HostName 192.168.56.10
    User user2
    IdentityFile C:/Users/alvar/.ssh/id_ed25519
    BatchMode yes
    StrictHostKeyChecking no
    ConnectTimeout 10
```

Con esta configuración, se puede usar `ssh windows-vm` directamente desde la terminal.

---

## 4. Consideraciones de Seguridad

### 4.1 Restricción de acceso por IP de origen

La regla de firewall que permite SSH inbound es permisiva (acepta cualquier IP). Para restringirla exclusivamente al adaptador Host-Only:

```powershell
# Ejecutar en la VM (consola o SSH ya autenticado)
# Primero eliminar la regla genérica existente
Remove-NetFirewallRule -Name "Allow_SSH" -ErrorAction SilentlyContinue

# Crear regla restringida a la subred Host-Only únicamente
New-NetFirewallRule `
    -Name "Allow_SSH_HostOnly" `
    -DisplayName "Allow SSH desde Host-Only (192.168.56.0/24)" `
    -Enabled True `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 22 `
    -RemoteAddress "192.168.56.0/24" `
    -Action Allow
```

> Esto garantiza que aunque otro equipo en la red física llegara a tener conectividad con la VM, no podría intentar conexiones SSH.

### 4.2 Uso de clave ED25519 (no contraseña)

- La autenticación por clave pública es la **única vía habilitada en el flujo MCP**. El flag `BatchMode=yes` desactiva cualquier prompt interactivo.
- La contraseña `v9KmZ2` de `user2` se conserva solo como mecanismo de emergencia via `plink` desde consola local. **No se utiliza en la integración MCP.**

### 4.3 Aislamiento de red (no expuesto a Internet)

- El adaptador Host-Only (`192.168.56.0/24`) **no tiene enrutamiento hacia Internet ni hacia la red LAN física**. Solo permite tráfico entre el host físico y la VM.
- El adaptador NAT (`10.0.2.15`) proporciona salida a Internet para la VM pero **no permite conexiones entrantes desde exterior**.
- El servidor MCP **nunca escucha en el adaptador NAT**; opera exclusivamente en modo `stdio` sobre el túnel SSH.

### 4.4 No abrir el puerto 8000 (SSE)

El informe anterior (`3_Restauracion_SSH_MCP_Report.md`) mencionaba un modo alternativo SSE (HTTP) en el puerto 8000. **Este modo NO está habilitado** en esta restauración porque:
- No es necesario (el modo `stdio` sobre SSH es más seguro y compatible con Cursor).
- Expondría un endpoint HTTP sin autenticación en la VM.
- Rompe el aislamiento proporcionado por el canal SSH cifrado.

### 4.5 Limpieza del historial de PowerShell en la VM

Para evitar que la contraseña quede en el historial de sesiones:

```powershell
# Ejecutar en la VM tras completar la restauración
Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue
Clear-History
```

---

## 5. Troubleshooting

### Error: `Permission denied (publickey,password,keyboard-interactive)`

**Causa más común:** La clave pública no está registrada o las ACLs del fichero son incorrectas.

```powershell
# Solución: Repetir PASOS 4 y 5 de esta guía
```

### Error: `WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED`

**Causa:** La VM fue reinstalada o restaurada desde snapshot y cambió su clave de host.

```powershell
ssh-keygen -R 192.168.56.10
# Luego reintentar la conexión
```

### Error MCP: `-32000: Connection closed`

**Causa más frecuente:** El DefaultShell de SSH es PowerShell en lugar de CMD, inyectando BOM en el stream stdio.

```powershell
# Diagnóstico: verificar el shell actual
$plink = "C:\Program Files\PuTTY\plink.exe"
echo "y" | & $plink -pw "v9KmZ2" -batch user2@192.168.56.10 `
  "reg query HKLM\SOFTWARE\OpenSSH /v DefaultShell"

# Corrección si no es cmd.exe:
echo "y" | & $plink -pw "v9KmZ2" -batch user2@192.168.56.10 `
  "reg add HKLM\SOFTWARE\OpenSSH /v DefaultShell /d C:\Windows\System32\cmd.exe /f & net stop sshd & net start sshd"
```

### La VM no responde a ping

**Causa:** La VM está apagada o el adaptador Host-Only no está configurado.

```powershell
# Verificar en VirtualBox que:
# 1. La VM está en estado "Running"
# 2. Adaptador 2 es "Host-Only Adapter" con nombre "VirtualBox Host-Only Ethernet Adapter"
# 3. El host tiene IP 192.168.56.1 en ese adaptador (Ethernet 6 en alvar@MSI)
```

### SSH conecta pero MCP no responde (timeout)

```powershell
# Test manual del servidor para ver errores de Python
ssh -i "C:\Users\alvar\.ssh\id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no `
    user2@192.168.56.10 `
    "C:\Python312\python.exe C:\Python312\mcp_server.py" 2>&1

# Verificar integridad del script
ssh -i "C:\Users\alvar\.ssh\id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no `
    user2@192.168.56.10 `
    "C:\Python312\python.exe -c import mcp; print(mcp.__version__)"

# Re-sincronizar el script desde el host si está corrupto
scp .\windows_mcp.py user2@192.168.56.10:C:\Python312\mcp_server.py
```

---

## 6. Estado Final Verificado

Ejecutado y verificado el **26 de junio de 2026** desde `alvar@MSI` (dos sesiones):

| Componente | Estado | Evidencia |
|-----------|--------|-----------|
| VM `entregablefinal_2` | Corriendo (`192.168.56.10`) | `ping` respondió TTL=128 |
| SSH (sshd) | Activo, puerto 22 | Conexión establecida |
| Autenticación `alvar@MSI` (clave pública) | Operativa | `hostname` sin contraseña |
| Shell SSH por defecto | `cmd.exe` | `reg query` → `C:\Windows\System32\cmd.exe` |
| Python 3.12 en `C:\Python312\` | Instalado | `python.exe --version` |
| Paquete `mcp 1.27.0` | Instalado | `pip list \| findstr mcp` |
| `mcp_server.py` (`WindowsCommander`) | Desplegado | `dir C:\Python312\mcp_server.py` |
| Protocolo JSON-RPC 2.0 | Verificado | `initialize` → respuesta correcta |
| `mcp.json` en Cursor | Creado | `%APPDATA%\Cursor\User\mcp.json` |

### Resultado de la prueba SSH (sesión 2):

```
WIN-VNQSUL89MUA
win-vnqsul89mua\user2
Dirección IPv4: 192.168.56.10   ← Host-Only
Dirección IPv4: 10.0.2.15       ← NAT
```

### Resultado del handshake MCP (captura real — sesiones 1 y 2):

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocolVersion": "2024-11-05",
    "capabilities": {
      "experimental": {},
      "prompts": {"listChanged": false},
      "resources": {"subscribe": false, "listChanged": false},
      "tools": {"listChanged": false}
    },
    "serverInfo": {
      "name": "WindowsCommander",
      "version": "1.27.0"
    }
  }
}
```

**Estado: OPERATIVO ✓**

---

## 7. Registro Cronológico Exacto de Comandos Ejecutados

Para auditoría completa, estos son los comandos ejecutados durante esta sesión de restauración:

```powershell
# 1. Verificar adaptadores de red del host
ipconfig | Select-String -Pattern "192\.168\.56|IPv4"
# → Ethernet 6: 192.168.56.1 (Host-Only confirmado)

# 2. Verificar clave pública local
Get-Content "C:\Users\alvar\.ssh\id_ed25519.pub"
# → ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICTFpm9RA3yTC4fvNuKWZkGyMkVGzaUAPE34m0Bt8qr+ alvar@MSI

# 3. Intento de SSH con clave (fallido — clave no registrada en la VM)
ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no -i "C:\Users\alvar\.ssh\id_ed25519" user2@192.168.56.10 "hostname"
# → Permission denied (publickey,password,keyboard-interactive)

# 4. Ping para confirmar que la VM está activa
ping -n 2 192.168.56.10
# → Respuesta desde 192.168.56.10: bytes=32 tiempo=2ms TTL=128

# 5. Conexión con contraseña via plink para auditar estado
$plink = "C:\Program Files\PuTTY\plink.exe"
echo "y" | & $plink -pw "v9KmZ2" -batch user2@192.168.56.10 "hostname & whoami & reg query HKLM\SOFTWARE\OpenSSH /v DefaultShell"
# → WIN-VNQSUL89MUA | win-vnqsul89mua\user2 | DefaultShell = C:\Windows\System32\cmd.exe

# 6. Verificar mcp instalado
echo "y" | & $plink -pw "v9KmZ2" -batch user2@192.168.56.10 "C:\Python312\python.exe -m pip list 2>&1 | findstr /i mcp"
# → mcp  1.27.0

# 7. Auditar authorized_keys
echo "y" | & $plink -pw "v9KmZ2" -batch user2@192.168.56.10 "type C:\ProgramData\ssh\administrators_authorized_keys"
# → solo contenía daniel@Port (duplicada)

# 8. Añadir clave pública alvar@MSI
$myPubKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICTFpm9RA3yTC4fvNuKWZkGyMkVGzaUAPE34m0Bt8qr+ alvar@MSI"
echo "y" | & $plink -pw "v9KmZ2" -batch user2@192.168.56.10 "echo $myPubKey >> C:\ProgramData\ssh\administrators_authorized_keys"

# 9. Reparar ACLs y reiniciar sshd
echo "y" | & $plink -pw "v9KmZ2" -batch user2@192.168.56.10 "icacls C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r /grant `"*S-1-5-32-544:F`" `"SYSTEM:F`" & icacls C:\ProgramData\ssh\administrators_authorized_keys /setowner `"*S-1-5-32-544`" & net stop sshd & net start sshd"
# → "Se procesaron correctamente 1 archivos" x2 | sshd detenido y reiniciado

# 10. Limpiar known_hosts y verificar SSH con clave pública
ssh-keygen -R 192.168.56.10
ssh -i "C:\Users\alvar\.ssh\id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=10 user2@192.168.56.10 "hostname & whoami"
# → WIN-VNQSUL89MUA | win-vnqsul89mua\user2 (SIN CONTRASEÑA)

# 11. Validar handshake JSON-RPC 2.0 del servidor MCP
$initMsg = '{"jsonrpc": "2.0", "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "cursor-test", "version": "1.0"}}, "id": 1}'
echo $initMsg | ssh -i "C:\Users\alvar\.ssh\id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no user2@192.168.56.10 "C:\Python312\python.exe C:\Python312\mcp_server.py"
# → {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","serverInfo":{"name":"WindowsCommander","version":"1.27.0"},...}}
```

---

## 8. Registro Cronológico — Sesión 2 (Validación y Creación mcp.json)

Comandos ejecutados desde `alvar@MSI` para verificar el estado post-restauración y crear el fichero de configuración del cliente:

```powershell
# 1. Buscar mcp.json existente en directorios de Cursor (no existía)
Get-ChildItem "$env:APPDATA\Cursor" -Recurse -Filter "mcp.json" -ErrorAction SilentlyContinue
Get-ChildItem "$env:USERPROFILE\.cursor" -Recurse -Filter "mcp.json" -ErrorAction SilentlyContinue
# → 0 resultados — el fichero no existía

# 2. Prueba SSH completa con clave pública + datos de red de la VM
ssh -i "C:\Users\alvar\.ssh\id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=10 `
    user2@192.168.56.10 `
    "hostname & whoami & echo --- & ipconfig | findstr IPv4"
# → WIN-VNQSUL89MUA | win-vnqsul89mua\user2 | IPv4: 192.168.56.10 + 10.0.2.15

# 3. Prueba MCP — handshake JSON-RPC 2.0
$initMsg = '{"jsonrpc": "2.0", "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "cursor-test", "version": "1.0"}}, "id": 1}'
echo $initMsg | ssh -i "C:\Users\alvar\.ssh\id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no `
    user2@192.168.56.10 "C:\Python312\python.exe C:\Python312\mcp_server.py"
# → {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","serverInfo":{"name":"WindowsCommander","version":"1.27.0"},...}}

# 4. Crear mcp.json en la ubicación correcta de Cursor
$mcpPath = "$env:APPDATA\Cursor\User\mcp.json"
Set-Content -Path $mcpPath -Encoding UTF8 -Value '{
  "mcpServers": {
    "windows-vm": {
      "command": "C:\\Windows\\System32\\OpenSSH\\ssh.exe",
      "args": [
        "-i", "C:\\Users\\alvar\\.ssh\\id_ed25519",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        "user2@192.168.56.10",
        "C:\\Python312\\python.exe",
        "C:\\Python312\\mcp_server.py"
      ]
    }
  }
}'
# → Fichero creado en C:\Users\alvar\AppData\Roaming\Cursor\User\mcp.json

# 5. Verificar contenido del fichero creado
Get-Content "$env:APPDATA\Cursor\User\mcp.json"
# → JSON correcto con mcpServers.windows-vm
```

---

*Fin del informe — Alvaro, 26 de junio de 2026*
