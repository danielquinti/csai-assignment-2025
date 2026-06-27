# Informe de Restauración de Conectividad MCP sobre SSH

**Máquina objetivo:** WIN-VNQSUL89MUA — `192.168.56.10`  
**VM en VirtualBox:** `entregablefinal 1`  
**Fecha de ejecución:** 24 de junio de 2026  
**Ejecutado desde:** `alvar@MSI` (host Windows)  
**Autor:** Blue Team — Alvaro  

---

## 1. Objetivo

Establecer conectividad con la máquina virtual `entregablefinal 1` (Windows Server 2025, `192.168.56.10`) a través de SSH con autenticación por clave pública, y verificar que el servidor MCP (*Model Context Protocol*) `WindowsCommander` responde correctamente al protocolo JSON-RPC 2.0, de modo que un agente IA (Cursor) pueda ejecutar comandos PowerShell de forma remota y autónoma contra la VM.

---

## 2. Estado previo de la máquina

Basado en el informe de restauración SSH del compañero (`3_Restauracion_SSH_MCP_Report.md`) y en los hallazgos de la auditoría inicial, la máquina se encontraba en el siguiente estado:

- **SSH (OpenSSH Server):** Reinstalado y operativo (servicio `sshd` en estado `Running`)
- **Shell predeterminada SSH:** `cmd.exe` (`HKLM\SOFTWARE\OpenSSH\DefaultShell`)
- **Contraseña de `user2`:** Rotada por el Red Team a `v9KmZ2` durante la fase de restauración
- **Python 3.12 fileless:** Instalado en `C:\Python312\` (embebido, sin instalador MSI)
- **Servidor MCP:** Script `C:\Python312\mcp_server.py` desplegado (paquete `mcp==1.27.0`)
- **Claves autorizadas:** Solo contenía la clave pública del compañero (`daniel@Port`)
- **Firewall:** Activo con tráfico saliente permitido (revertido por el Red Team)

---

## 3. Diagnóstico y resolución de problemas

### 3.1 Conflicto de host key en `known_hosts`

Al intentar la primera conexión SSH, el cliente rechazó la conexión porque la máquina había sido reinstalada y su clave de host ED25519 ya no coincidía con la entrada previa en `known_hosts`.

**Error observado:**
```
WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!
Offending ECDSA key in C:\Users\alvar/.ssh/known_hosts:18
Host key verification failed.
```

**Solución:** Eliminar las entradas obsoletas de `known_hosts`:
```powershell
ssh-keygen -R 192.168.56.10
# Output: C:\Users\alvar/.ssh/known_hosts updated.
```

### 3.2 Rechazo de autenticación en modo batch

Con `BatchMode=yes` y sin clave pública registrada en la VM, el cliente SSH rechazaba la conexión inmediatamente:
```
user2@192.168.56.10: Permission denied (publickey,password,keyboard-interactive).
```

**Causa:** La clave pública local (`id_ed25519.pub` de `alvar@MSI`) no estaba en el fichero `administrators_authorized_keys` de la VM.

**Solución:** Usar `plink.exe` (PuTTY) con autenticación por contraseña para acceder provisionalmente y añadir la clave pública.

---

## 4. Comandos ejecutados (cronología completa)

### Paso 1 — Limpiar host key obsoleta

```powershell
ssh-keygen -R 192.168.56.10
```
```
# Host 192.168.56.10 found: line 16
# Host 192.168.56.10 found: line 17
# Host 192.168.56.10 found: line 18
C:\Users\alvar/.ssh/known_hosts updated.
```

---

### Paso 2 — Verificar conectividad SSH con contraseña (via plink)

```powershell
$plink = "C:\Program Files\PuTTY\plink.exe"
echo "y" | & $plink -pw "v9KmZ2" user2@192.168.56.10 "hostname & whoami & ipconfig | findstr IPv4"
```
```
WIN-VNQSUL89MUA
win-vnqsul89mua\user2
   Dirección IPv4. . . . . . . . . . . . . . : 192.168.56.10
   Dirección IPv4. . . . . . . . . . . . . . : 10.0.2.15
```
> La conexión con contraseña es operativa. La VM responde desde `192.168.56.10` (Host-Only) y `10.0.2.15` (NAT).

---

### Paso 3 — Auditar estado de Python y MCP en la VM

```powershell
& $plink -pw "v9KmZ2" -batch user2@192.168.56.10 "C:\Python312\python.exe -m pip list 2>&1 | findstr mcp"
```
```
mcp                       1.27.0
```

```powershell
& $plink -pw "v9KmZ2" -batch user2@192.168.56.10 "type C:\Python312\mcp_server.py"
```
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
> Python 3.12 y el paquete `mcp 1.27.0` están instalados. El script `mcp_server.py` expone la herramienta `ejecutar_comando_powershell`.

---

### Paso 4 — Verificar shell por defecto de OpenSSH

```powershell
& $plink -pw "v9KmZ2" -batch user2@192.168.56.10 "reg query HKLM\SOFTWARE\OpenSSH /v DefaultShell"
```
```
HKEY_LOCAL_MACHINE\SOFTWARE\OpenSSH
    DefaultShell    REG_SZ    C:\Windows\System32\cmd.exe
```
> La shell por defecto es `cmd.exe`, lo que garantiza un transporte stdio limpio sin cabeceras BOM de PowerShell que romperían el protocolo JSON-RPC.

---

### Paso 5 — Añadir clave pública `alvar@MSI` a `administrators_authorized_keys`

```powershell
# Clave pública local (alvar@MSI):
Get-Content "C:\Users\alvar\.ssh\id_ed25519.pub"
# ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICTFpm9RA3yTC4fvNuKWZkGyMkVGzaUAPE34m0Bt8qr+ alvar@MSI

$myPubKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICTFpm9RA3yTC4fvNuKWZkGyMkVGzaUAPE34m0Bt8qr+ alvar@MSI"
& $plink -pw "v9KmZ2" -batch user2@192.168.56.10 "echo $myPubKey >> C:\ProgramData\ssh\administrators_authorized_keys"
```

---

### Paso 6 — Reparar ACLs y reiniciar el servicio SSH

OpenSSH en Windows requiere que `administrators_authorized_keys` sea propiedad de `BUILTIN\Administrators` y que solo `SYSTEM` y `Administrators` tengan permisos, sin herencia. Sin estas ACLs el servidor ignora el fichero.

```powershell
& $plink -pw "v9KmZ2" -batch user2@192.168.56.10 `
  "icacls C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r /grant `"*S-1-5-32-544:F`" `"SYSTEM:F`" & icacls C:\ProgramData\ssh\administrators_authorized_keys /setowner `"*S-1-5-32-544`" & net stop sshd & net start sshd"
```
```
archivo procesado: C:\ProgramData\ssh\administrators_authorized_keys
Se procesaron correctamente 1 archivos; error al procesar 0 archivos
archivo procesado: C:\ProgramData\ssh\administrators_authorized_keys
Se procesaron correctamente 1 archivos; error al procesar 0 archivos
El servicio de OpenSSH SSH Server se detuvo correctamente.
El servicio de OpenSSH SSH Server se ha iniciado correctamente.
```

---

### Paso 7 — Verificar autenticación SSH sin contraseña (clave pública)

```powershell
ssh -i "C:\Users\alvar\.ssh\id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=10 user2@192.168.56.10 "hostname & whoami"
```
```
WIN-VNQSUL89MUA
win-vnqsul89mua\user2
```
> **Autenticación por clave pública verificada.** No se requiere contraseña.

---

### Paso 8 — Validar servidor MCP con protocolo JSON-RPC 2.0

```powershell
$initMsg = '{"jsonrpc": "2.0", "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "cursor-test", "version": "1.0"}}, "id": 1}'
echo $initMsg | ssh -i "C:\Users\alvar\.ssh\id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no user2@192.168.56.10 "C:\Python312\python.exe C:\Python312\mcp_server.py"
```
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
> **Servidor MCP operativo.** Responde correctamente al handshake de inicialización JSON-RPC 2.0.

---

## 5. Configuración del servidor MCP para Cursor

Para integrar el servidor MCP en Cursor y permitir que el agente ejecute comandos PowerShell de forma remota en la VM, añadir el siguiente bloque al fichero de configuración MCP del IDE (normalmente `%APPDATA%\Cursor\mcp.json` o en la configuración del proyecto `.cursor/mcp.json`):

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

**Herramienta expuesta por el servidor:**

| Nombre | Descripción |
|--------|-------------|
| `ejecutar_comando_powershell` | Ejecuta cualquier comando PowerShell en la VM con `-ExecutionPolicy Bypass` y devuelve stdout/stderr |

---

## 6. Resumen del estado final

| Componente | Estado |
|-----------|--------|
| VM `entregablefinal 1` | Corriendo (`VMState=running`) |
| SSH (sshd) | Activo, puerto 22 |
| Autenticación `alvar@MSI` (clave) | Operativa (sin contraseña) |
| Shell SSH por defecto | `cmd.exe` (limpio para JSON-RPC) |
| Python 3.12 en `C:\Python312\` | Instalado |
| Paquete `mcp 1.27.0` | Instalado |
| `mcp_server.py` (`WindowsCommander`) | Desplegado y validado |
| Protocolo JSON-RPC 2.0 | Verificado (`initialize` → respuesta correcta) |

---

*Fin del informe — Alvaro, 24 de junio de 2026*
