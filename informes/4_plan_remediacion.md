# 🛡️ Plan de Securización Reactiva, Remediación y Políticas de Hardening

**Caso:** Securización Reactiva del Servidor WIN-VNQSUL89MUA  
**Máquina afectada:** Windows Server 2025 — `192.168.56.10`  
**Autor:** Blue Team — Analista de Respuesta a Incidentes  
**Fecha:** 22 de junio de 2026  
**Clasificación:** CONFIDENCIAL  

---

## 1. Resumen Ejecutivo

Este documento detalla el plan estratégico de remediación y endurecimiento (*hardening*) reactivo para el servidor **WIN-VNQSUL89MUA** tras el compromiso confirmado por el Red Team el 25 de marzo de 2026. A partir del Análisis de Causa Raíz (RCA) y de los hallazgos del informe forense, se establecen medidas correctoras inmediatas y políticas a largo plazo. 

Debido a que el entorno **carece de un sistema centralizado de alertas (Wazuh)**, las políticas de detección y respuesta se han diseñado para operar a nivel local en el host, valiéndose de la optimización del servicio **Sysmon** y del despliegue de **sesiones agénticas automatizadas mediante el protocolo MCP (Model Context Protocol)**. Esta arquitectura de bucle cerrado garantiza que el sistema recupere y mantenga de forma autónoma su postura de seguridad.

---

## 2. Análisis de Causa Raíz (RCA) del Incidente

El análisis del historial de comandos (`ConsoleHost_history.txt`) y de los logs de eventos del sistema permitió identificar la secuencia exacta y las debilidades explotadas por el atacante:

1. **Vector de Entrada (LogonType 2):** El atacante obtuvo acceso físico a la consola de la máquina virtual (interfaz de VirtualBox) empleando credenciales legítimas comprometidas del usuario administrador `user2`. Este acceso interactivo local evadió el endurecimiento perimetral previo (el cual había desinstalado SSH y configurado un firewall restrictivo mediante el script `nuke.ps1`).
2. **Punto Ciego de Telemetría (Sysmon):** Sysmon registró más de 2,600 eventos de registro (IDs 12 y 13) el día del ataque, pero **ningún evento de creación de procesos (ID 1)**. La configuración defensiva inicial de Sysmon (`WinNetSvc.xml`) estaba restringida a auditar procesos hijos del servidor web IIS (`w3wp.exe`) y herramientas selectas de movimiento lateral. Los comandos ejecutados desde la shell interactiva de la consola local no fueron auditados, permitiendo al atacante operar en la sombra técnica.
3. **Desactivación de Controles Críticos:** Al no existir telemetría de procesos de consola, el atacante desactivó el Firewall de Windows (`netsh advfirewall set allprofiles state off`) y el cifrado de disco BitLocker (`manage-bde -off C:`), dejando al host totalmente desprotegido.
4. **Persistencia Instalada:** El atacante creó una cuenta backdoor local denominada `yishiego` (SID `S-1-5-21-1664551603-4127425987-2585137545-1002`), la elevó al grupo de `Administradores` y le asignó la contraseña `EstuveAqui.1234`.
5. **Evasión Forense Volátil:** Para eliminar la evidencia volátil y dificultar el análisis de la memoria RAM (impidiendo la extracción de secretos mediante Volatility u otras herramientas en caliente), el atacante forzó el apagado inmediato del host con `shutdown /s /t 0`.

---

## 3. Plan de Remediación Inmediata (Saneamiento)

La primera fase del plan consiste en restablecer el estado limpio de la máquina y blindar el acceso local e interactivo:

### 3.1 Saneamiento de Cuentas y Accesos
* **Eliminación del Backdoor:** Ejecutar de forma inmediata la eliminación de la cuenta de persistencia `yishiego`:
  ```cmd
  net user yishiego /delete
  ```
* **Rotación y Robustecimiento de Credenciales:** Cambiar la contraseña del usuario legítimo `user2` forzando una longitud mínima de 16 caracteres, el uso de caracteres especiales, números, mayúsculas y minúsculas.
* **Habilitación de Directivas de Bloqueo de Cuenta:** Configurar directivas de grupo local (GPO) para bloquear temporalmente cualquier cuenta tras 5 intentos fallidos de inicio de sesión.

### 3.2 Restablecimiento de Servicios de Protección
* **Restauración del Firewall de Windows (manteniendo el canal MCP):** Para no interrumpir la conectividad de la sesión agéntica remota (la cual es la base para ejecutar el hardening y la monitorización activa), la habilitación del firewall y su política por defecto de bloqueo debe implementarse de forma ordenada, asegurando primero las reglas que permiten el tráfico de SSH (puerto 22) y el servidor MCP alternativo SSE (puerto 8000). **Cortar el acceso de gestión debe ser el último recurso operativo.**
  ```powershell
  # 1. Habilitar perfiles de firewall
  Set-NetFirewallProfile -All -Enabled True
  # 2. Declarar excepciones explícitas para la administración agéntica
  New-NetFirewallRule -DisplayName "Allow_SSH_MCP" -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow
  New-NetFirewallRule -DisplayName "Allow_MCP_SSE" -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow
  # 3. Aplicar política por defecto (inbound block) a todo lo demás
  Set-NetFirewallProfile -All -DefaultInboundAction Block
  ```
* **Reactivación del Cifrado de Disco:** Volver a habilitar BitLocker en la unidad del sistema (`C:`) y almacenar la clave de recuperación en un entorno seguro y fuera de la máquina virtual.

### 3.3 Saneamiento y Configuración de OpenSSH y MCP
Para garantizar que las herramientas de administración y auditoría del Blue Team se ejecuten sin problemas de codificación ni errores de transporte de datos JSON-RPC:
1. **Configuración de Shell Pura:** Modificar el registro de Windows para establecer `cmd.exe` como la shell predeterminada de OpenSSH. Esto previene que PowerShell inyecte cabeceras de control invisibles o marcas de orden de bytes (BOM) en el stream `stdio` que romperían la serialización JSON del protocolo MCP:
   ```cmd
   reg add HKLM\SOFTWARE\OpenSSH /v DefaultShell /d C:\Windows\System32\cmd.exe /f
   ```
2. **Auditoría de llaves autorizadas:** Saneamiento del archivo `C:\ProgramData\ssh\administrators_authorized_keys` de modo que contenga únicamente la clave pública del host del analista del Blue Team (preservando y garantizando siempre la clave del agente MCP para evitar bloqueos accidentales), aplicando los permisos estrictos mediante `icacls`.

---

## 4. Políticas de Telemetría Basadas en Sysmon (Sin Wazuh)

Al no disponer de un agente SIEM como Wazuh para centralizar logs, es imperativo que la monitorización local de Windows Event Logs sea robusta. Para cerrar de forma definitiva el punto ciego de consola interactiva, se actualiza la configuración del servicio Sysmon (`WinNetSvc`) para capturar la creación de procesos (`ProcessCreate`, ID 1) en sesiones interactivas locales (`LogonType 2`).

Se integra el siguiente fragmento XML en el archivo de reglas `WinNetSvc.xml`:

```xml
<Sysmon schemaversion="4.50">
  <EventFiltering>
    <RuleGroup name="Hardening Consola Interactiva" groupRelation="or">
      <ProcessCreate onmatch="include">
        <!-- Monitoreo de procesos originados por shells y consolas interactivas -->
        <ParentImage condition="image">powershell.exe</ParentImage>
        <ParentImage condition="image">cmd.exe</ParentImage>
        <Image condition="image">powershell.exe</Image>
        <Image condition="image">cmd.exe</Image>
        <Image condition="image">pwsh.exe</Image>
        <Image condition="image">wscript.exe</Image>
        <Image condition="image">cscript.exe</Image>
        
        <!-- Monitoreo de utilidades de gestión crítica que usó el Red Team -->
        <OriginalFileName condition="is">net.exe</OriginalFileName>
        <OriginalFileName condition="is">net1.exe</OriginalFileName>
        <OriginalFileName condition="is">netsh.exe</OriginalFileName>
        <OriginalFileName condition="is">manage-bde.exe</OriginalFileName>
        <OriginalFileName condition="is">sc.exe</OriginalFileName>
        <OriginalFileName condition="is">reg.exe</OriginalFileName>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

---

## 5. Políticas de Hardening Continuo Mediante Sesiones Agénticas via MCP

Para prevenir la degradación de la seguridad del host a lo largo del tiempo, se define una **política de remediación y auditoría automatizada en bucle cerrado**. Esta política se apoya en sesiones agénticas en las cuales una Inteligencia Artificial defensiva se conecta al servidor MCP del host a través de SSH (o a través del puerto transaccional `8000` mediante Server-Sent Events - SSE en caso de contingencia) y ejecuta de forma autónoma tareas de verificación y autorremediación.

```
       [ Agente de IA Defensivo (Host) ]
                       │
             (JSON-RPC / SSH-CMD)
                       ▼
             [ Servidor MCP (VM) ]
                       │
       ┌───────────────┼───────────────┐
       ▼               ▼               ▼
[Audit Users]   [Audit Firewall]   [Audit Disk]
```

### 5.1 Playbook de Herramientas MCP del Agente
El servidor MCP expone herramientas específicas que el agente IA consume para auditar y restablecer las políticas en caliente:

| Nombre de la Herramienta | Acción del Agente IA | Lógica de Autorremediación |
|--------------------------|----------------------|----------------------------|
| `check_local_users` | Compara los usuarios del grupo Administradores con una whitelist autorizada. | Si detecta un usuario fuera de la lista (ej. `yishiego`), ejecuta su eliminación inmediata. |
| `enforce_firewall` | Verifica si el firewall está activo en todos los perfiles de red. | Si detecta que el firewall está deshabilitado, lo activa y restablece las reglas restrictivas por defecto. |
| `enforce_bitlocker` | Audita el estado de cifrado de la unidad del sistema `C:`. | Si detecta que el cifrado está desactivado o pausado, reinicia el cifrado de volumen. |
| `audit_ssh_keys` | Calcula el hash SHA-256 del archivo `administrators_authorized_keys` y lo compara con el original. | Si los hashes no coinciden, sobrescribe el archivo con la lista autorizada de claves públicas y reinicia el servicio SSH. |

> [!IMPORTANT]
> **Preservación Obligatoria del Canal de Comunicación (SSH/MCP):**
> Dado que la mayor parte de las tareas de supervisión y mitigación de este plan se delegan en el agente inteligente que opera mediante MCP (a través de SSH o SSE), **cualquier acción que corte o ponga en riesgo la conectividad (como bloquear puertos de gestión o vaciar incorrectamente las llaves autorizadas) debe evitarse a toda costa y considerarse estrictamente como último recurso.** Mantener la línea de comunicación abierta y operativa es indispensable para sostener el bucle cerrado de hardening.

---

## 6. Métricas de Calidad y KPIs de Seguridad

Para garantizar la estabilidad del sistema y medir la eficacia del canal de comunicación agéntico y de las políticas de telemetría local, se define la siguiente matriz de KPIs:

| KPI | Nombre del Indicador | Definición y Fórmula | Frecuencia | Objetivo (Target) |
|---|---|---|---|---|
| **MTTR-A** | Tiempo Medio de Contención Agéntica | Tiempo transcurrido desde la alteración no autorizada de un control (ej. desactivación de firewall) hasta que la sesión agéntica vía MCP lo restaura. | Ante cada desviación | $< 5$ minutos |
| **TCH** | Tasa de Cumplimiento de Hardening | Porcentaje de controles críticos de seguridad que permanecen en el estado requerido de endurecimiento. <br> $\text{TCH} = \frac{\text{Controles conformes}}{\text{Total controles}} \times 100$ | Semanal | $100\%$ |
| **CECI** | Cobertura de Eventos de Consola Interactiva | Proporción de procesos lanzados en sesiones locales interactivas (LogonType 2) que han sido logueados por Sysmon. | Mensual | $100\%$ |
| **FCMCP** | Fiabilidad del Canal MCP | Porcentaje de sesiones de comunicación MCP completadas con éxito sin errores de stream ni interrupciones del proceso. | Semanal | $> 99\%$ |
| **FAA** | Frecuencia de Auditoría Agéntica | Frecuencia programada o basada en eventos con la que el agente IA escanea el host para verificar controles. | Diaria y por Evento | Mínimo 1 diaria (y reactiva tras evento 4624) |

---
*Fin del Plan de Securización Reactiva y Políticas de Hardening.*
