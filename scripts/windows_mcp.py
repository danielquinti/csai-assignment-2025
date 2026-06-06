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
    # Detectamos si queremos SSE por argumento
    transport = "stdio"
    if "--sse" in sys.argv:
        transport = "sse"
    
    # mcp.run manejará el servidor si transport='sse', pero requiere 'uvicorn' y 'starlette'.
    mcp.run(transport=transport)
