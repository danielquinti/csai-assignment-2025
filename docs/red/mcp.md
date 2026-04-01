# Guía: Configuración de Kali Linux como Servidor MCP Remoto
Esta configuración permite que un agente de IA ejecute comandos nativos de hacking y auditoría directamente en tu máquina virtual Kali desde tu sistema host (Windows).

## 1. Preparación e Instalación de Kali Linux
1. Entra en la [página oficial de Kali Linux](https://www.kali.org/get-kali/#kali-virtual-machines) y descarga la imagen preconstruida para **VirtualBox**.
2. Descomprime el archivo descargado.
3. Carga el archivo `.vbox` en VirtualBox (haciendo doble clic o añadiéndolo desde el menú).
4. Ve a la **Configuración** de la máquina virtual recién agregada:
   - **Sistema**: Asígnale al menos **4 GB de RAM**.
   - **Red**: 
     - **Adaptador 1**: Asegúrate de que esté configurado como **NAT** (viene así por defecto).
     - **Adaptador 2**: Habilítalo y configúralo como **Adaptador de solo anfitrión (Host-Only)**. Esto es vital para que la máquina pueda conectarse con la del Blue Team y con tu host.
5. Inicia la máquina virtual.
6. Inicia sesión con las credenciales por defecto:
   - **Usuario:** `kali`
   - **Contraseña:** `kali`
7. Abre una terminal y actualiza los paquetes del sistema:
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```
8. Reinicia la máquina para aplicar las actualizaciones:
   ```bash
   sudo systemctl reboot
   ```

## 2. Configuración de IP Estática (Red Host-Only)
Para que el host y la VM se comuniquen de forma estable, necesitamos fijar una IP estática en el adaptador "Host-Only" que añadimos en el paso anterior.

Dentro de Kali, abre la terminal y ejecuta estos comandos para fijar la IP `192.168.56.90`:

```bash
# Crear perfil de red estática
sudo nmcli con add type ethernet ifname eth1 con-name eth1-estatica ipv4.method manual ipv4.addresses 192.168.56.90/24
# Activar la interfaz
sudo nmcli con up eth1-estatica
```

## 3. Habilitar Acceso SSH para Root
El agente necesita privilegios máximos para ejecutar herramientas como nmap o msfconsole sin bloqueos de contraseña.

Establecer contraseña de root:

```bash
sudo passwd root
```

Permitir login de root por SSH:

```bash
sudo sed -i 's/.*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
sudo systemctl enable ssh --now
sudo systemctl restart ssh
```

## 4. Configuración de Llaves SSH (Desde Windows)
Para que el IDE se conecte de forma transparente, no debe pedir contraseña. Usaremos llaves SSH.

En tu PowerShell de Windows, genera una llave (si no tienes una) pulsando Enter a todo (sin passphrase):

```powershell
ssh-keygen -t ed25519
```

Copiar la llave a Kali:

```powershell
type $env:USERPROFILE\.ssh\id_ed25519.pub | ssh root@192.168.56.90 "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
```

(Escribe la contraseña de root una última vez).

Limpiar registros antiguos (Si da error de "Host Identification Changed"):

```powershell
ssh-keygen -R 192.168.56.90
```

## 5. Instalación del Servidor MCP en Kali
Ejecuta este bloque "todo en uno" en la terminal de Kali como root (esto asume que entraste como root) para preparar el entorno y el script del servidor:

```bash
# 1. Instalar dependencias de Python
apt update && apt install -y python3-venv

# 2. Crear entorno virtual e instalar MCP
mkdir -p /root/mcp-server && cd /root/mcp-server
python3 -m venv venv
./venv/bin/pip install mcp

# 3. Crear el script del servidor MCP (A prueba de errores de sintaxis)
cat << 'EOF' > /root/mcp-server/kali_mcp.py
import subprocess
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("KaliCommander")

@mcp.tool()
def ejecutar_comando_bash(comando: str) -> str:
    """Ejecuta un comando en la terminal de Kali Linux y devuelve el resultado."""
    try:
        r = subprocess.run(comando, shell=True, check=True, text=True, capture_output=True)
        return f"Éxito:\n{r.stdout}"
    except subprocess.CalledProcessError as e:
        return f"Error (Código {e.returncode}).\nSTDOUT: {e.stdout}\nSTDERR: {e.stderr}"
    except Exception as e:
        return f"Error inesperado: {str(e)}"

if __name__ == "__main__":
    mcp.run(transport='stdio')
EOF

chmod +x /root/mcp-server/kali_mcp.py
```

## 6. Configuración del IDE (Cursor, Claude, etc.)
Añade este bloque JSON en la configuración de servidores MCP de tu IDE. Esto le indica que use SSH para levantar el servidor Python en la VM:

```json
{
  "mcpServers": {
    "kali-server": {
      "command": "ssh",
      "args": [
        "root@192.168.56.90",
        "/root/mcp-server/venv/bin/python",
        "/root/mcp-server/kali_mcp.py"
      ]
    }
  }
}
```

## 7. Resolución de Problemas (Troubleshooting)
Si el IDE no conecta, prueba la conexión manualmente desde el PowerShell de Windows:

Prueba de ejecución remota:

```powershell
ssh root@192.168.56.90 "/root/mcp-server/venv/bin/python /root/mcp-server/kali_mcp.py"
```

Si se queda esperando sin errores, el servidor está vivo.