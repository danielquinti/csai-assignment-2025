# Informe Exhaustivo: Lectura y Análisis de Memoria RAM para Ruptura de BitLocker (vTPM)

**Fecha de compilación:** 2026-06-07  
**Objetivo:** Máquina del Blue Team — Windows Server 2025 (VM VirtualBox `CSAI`)  
**Operador:** Red Team (ejercicio autorizado CSAI 2025)  
**Condición de victoria global:** Montar el volumen BitLocker cifrado (`CSAI-disk001.vdi`) en Kali y acceder al sistema de ficheros  
**Alcance:** Fase de **lectura, adquisición y análisis forense de RAM** orientada a extraer VMK/FVEK/TWEAK — no inyección ni ataques lógicos web.

---

## Índice

1. [Análisis de la configuración de la VM](#1-análisis-de-la-configuración-de-la-vm)
2. [Justificación del ataque a BitLocker vía RAM](#2-justificación-del-ataque-a-bitlocker-vía-ram)
3. [Infraestructura de adquisición de memoria](#3-infraestructura-de-adquisición-de-memoria)
4. [Metodología I — Volatility 3 Framework](#4-metodología-i--volatility-3-framework)
5. [Metodología II — MemProcFS](#5-metodología-ii--memprocfs)
6. [Metodología III — Herramientas auxiliares (HxD, strings, aeskeyfind, GDB lectura)](#6-metodología-iii--herramientas-auxiliares-hxd-strings-aeskeyfind-gdb-lectura)
7. [Metodología IV — WinDbg y lectura kernel (evaluación)](#7-metodología-iv--windbg-y-lectura-kernel-evaluación)
8. [Metodología V — Pipeline `AnalisisDeVolcados`](#8-metodología-v--pipeline-analisisdevolcados)
9. [Metodología VI — Extractor híbrido `intento_romper_bitlocker`](#9-metodología-vi--extractor-híbrido-intento_romper_bitlocker)
10. [Metodología VII — Scripts Python (tallado manual y heurísticas estadísticas)](#10-metodología-vii--scripts-python-tallado-manual-y-heurísticas-estadísticas)
11. [Intento de montaje en Kali Linux / Windows host](#11-intento-de-montaje-en-kali-linux--windows-host)
12. [Análisis integrado de resultados](#12-análisis-integrado-de-resultados)
13. [Problemas encontrados y lecciones aprendidas](#13-problemas-encontrados-y-lecciones-aprendidas)
14. [Mapeo MITRE ATT&CK](#14-mapeo-mitre-attck)
15. [Conclusiones y líneas futuras](#15-conclusiones-y-líneas-futuras)
16. [Anexos](#16-anexos)

---

# 1. Análisis de la configuración de la VM

## 1.1 Artefactos de orquestación analizados

| Artefacto | Ubicación típica | Rol en el ataque |
|-----------|------------------|------------------|
| `CSAI.vbox` | `VirtualBox VMs/CSAI/` | Definición hardware, RAM, vTPM, red |
| `CSAI.nvram` | Misma carpeta + `KaliShared/` | Estado UEFI + **vTPM 2.0** emulado |
| `CSAI-disk001.vdi` | Misma carpeta | Disco cifrado BitLocker |
| `memoria.elf` / `CSAI.elf` | RedTeam, KaliShared | Volcado RAM forense |
| `*.sav` | `Snapshots/` VirtualBox | Save State completo |

**VirtualBox:** 7.2.6 (r172322)  
**Nombre VM:** `CSAI`  
**SO declarado:** `Windows2022_64` (Windows Server 2025, build 26100)

## 1.2 Parámetros hardware relevantes (`.vbox`)

| Parámetro | Valor | Implicación forense |
|-----------|-------|---------------------|
| `Memory RAMSize` | 4096 MB | Volcados ~4 GB; barrido lineal costoso |
| `Firmware` | EFI | Arranque UEFI; integración TPM |
| `TrustedPlatformModule` | `v2_0` | BitLocker **Solo TPM** (sin PIN) |
| `Display` | VBoxSVGA, 128 MB VRAM | UI login; buffers gráficos separados de pool kernel |
| `Network` | Host-Only `192.168.56.137` | Target aislado; ataque desde host |
| `PAE` | `enabled="false"` | Confirmado por `windows.info`: `IsPAE=False` |
| `NX` | Deshabilitado (notas operativas) | DEP debilitado; simplifica post-explotación (no extracción directa) |
| CPUs | 3 (`KeNumberProcessors=3`) | `dumpvmcore` congela 3 vCPUs atómicamente |

## 1.3 Análisis del `.nvram` (vTPM)

**Hallazgo documentado (`intento_romper_bitlocker.md`):**

```text
Header inicial: TpmEmuTpms/permall
```

**Interpretación:**

- Confirma emulador TPM persistente de VirtualBox.
- El estado del vTPM almacena mediciones PCR y secretos sellados usados por BitLocker en arranque.
- Complemento al volcado RAM: el `.nvram` es candidato para extracción VMK offline (vector paralelo, no completado).

## 1.4 Servicios defensivos observados en RAM

Desde MemProcFS / análisis de procesos:

| Componente | Evidencia | Impacto |
|------------|-----------|---------|
| **Sysmon64.exe** | PID 592 en `memoria_examination.md` | Monitorización host/guest; irrelevante para volcado desde hipervisor |
| **BDESVC** | Registro `HKLM\...\Services\BDESVC` | Servicio BitLocker activo |
| **fvevol.sys** | Módulo kernel + tags pool | Driver de cifrado de volumen |
| **Defender host** | Exclusiones necesarias para `VBoxManage` | Riesgo corrupción dump 4 GB |

---

# 2. Justificación del ataque a BitLocker vía RAM

## 2.1 Cadena criptográfica BitLocker (modelo operativo)

```mermaid
flowchart LR
    A[Arranque UEFI] --> B[vTPM valida PCRs]
    B --> C[TPM libera VMK]
    C --> D[Windows descifra FVEK]
    D --> E[fvevol.sys carga FVEK en Non-Paged Pool]
    E --> F[Volumen C: accesible en caliente]
    F --> G[Pantalla Login — claves AÚN en RAM]
```

## 2.2 Por qué la pantalla de login es el «sweet spot»

Documentado en `intento2LecturaRam.md`:

1. Firmware UEFI virtual inicializa entorno seguro.
2. vTPM mide Firmware, ACPI, Bootloader → extiende PCR 0, 2, 4, 11.
3. Coincidencia con estado sellado → **liberación VMK**.
4. VMK descifra **FVEK**.
5. `fvevol.sys` carga FVEK en **Non-Paged Pool** para I/O en tiempo real.

**Consecuencia:** En pantalla de login el disco sigue cifrado en reposo, pero el SO mantiene material criptográfico en RAM para operar el volumen montado.

## 2.3 Objetivos criptográficos buscados en RAM

| Material | Tamaño típico | Uso |
|----------|---------------|-----|
| **VMK** | 256 bit (32 B) | Desbloquea FVEK wrapped |
| **FVEK** | 128/256 bit | Cifrado sectorial AES-XTS |
| **TWEAK key** | 128/256 bit | Segunda mitad par AES-XTS |
| **AES Key Schedule** | 176 B (AES-128) / 240 B (AES-256) | Expansión de clave detectable por `aeskeyfind` |
| **Tags pool** | Variable | `FVEp`, `FVE0`, `Cngb`, `TpmP` — marcadores estructurales |

## 2.4 Hipótesis de trabajo (todos los informes agente)

> Si se obtiene un volcado suficientemente completo con BitLocker ya desbloqueado, es posible recuperar VMK/FVEK y montar el `.vdi` offline en Kali con `dislocker` / `bdemount`.

**Resultado global:** Hipótesis **parcialmente confirmada** (estructuras presentes) pero **clave utilizable no extraída**.

---

# 3. Infraestructura de adquisición de memoria

## 3.1 Fuentes de memoria evaluadas

| Fuente | Formato | Evaluación | Documento |
|--------|---------|------------|-----------|
| Hibernación `hiberfil.sys` | Comprimido Windows | Secundaria — momento crítico incierto | `intento4LecturaRam.md` |
| **Volcado ELF** | `memoria.elf`, `CSAI.elf` | **Principal** — compatible Volatility/MemProcFS | Intento 5 §2.2 |
| **Save State** | `*.sav` ~500 MB | Valiosa (TPM+RAM) pero LZF comprimido | Intento 5 §2.1 |
| GDB lectura live | TCP 1234 | Degradada — timeouts/SIGTRAP | `intento1LecturaRam.md` |

## 3.2 Volcado principal: `debugvm dumpvmcore` → `.elf`

**Comandos utilizados:**

```powershell
VBoxManage debugvm "CSAI" dumpvmcore --filename=memoria.elf
VBoxManage debugvm "CSAI" dumpvmcore --filename=CSAI.elf
VBoxManage debugvm "CSAI" dumpvmcore --filename="AnalisisDeVolcados/Volcados/CSAI1.elf"
```

**Estado de captura (ideal):**

```text
Arrancada | BitLocker desbloqueado | Login visible | Sin credenciales
```

**Mecánica interna (`intento2LecturaRam.md`):**

- Congelamiento atómico de 3 vCPUs.
- Copia lineal de 4096 MB RAM → archivo ELF64 core dump.
- Secciones `PT_LOAD` mapean RAM física; notas CPU (RIP, RSP, CR3/DTB).

**Mitigación EDR host:**

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
Add-MpPreference -ExclusionPath "./"
Add-MpPreference -ExclusionProcess "VBoxManage.exe"
```

**Estructura ELF resultante:**

```text
+ ELF64 HEADER (Core Dump, x86_64)
+ PROGRAM HEADERS (PT_LOAD → segmentos RAM)
+ NOTE SECTION (registros CPU: CR3=0x1ae000, ...)
+ RAW PHYSICAL MEMORY (~4 GB)
```

## 3.3 Save State (`.sav`)

**Obtención:**

```text
VirtualBox → Close → Save Machine State
→ Snapshots\{uuid}.sav
```

**Contenido:** RAM + CPU + dispositivos + **estado vTPM**.

**Problema crítico (`intento1LecturaRam.md` L.2, Intento 5 §2.1):**

- VirtualBox 7.x comprime RAM con **LZF**.
- ~4 GB RAM → ~500 MB en disco.
- Búsquedas `strings`/`grep` de tags `FVE*`, `HOLAHOLAHOLA` → **cero coincidencias** en texto plano.
- Referencias sí encontradas indirectamente tras descompresión implícita al restaurar (cadenas `FveOpenVolumeW`, `FveTpmLib`).

## 3.4 Validación del volcado `.elf`

**Plugin:** `windows.info` (Volatility 3.2.28.1)

| Variable | Valor | Significado |
|----------|-------|-------------|
| `layer_name` | `WindowsIntel32e` | Capa x64 canónica |
| `Kernel Base` | `0xf805bce00000` | Base ntoskrnl |
| `DTB` / CR3 | `0x1ae000` | Traducción VA→PA |
| `Major/Minor` | `15.26100` | Windows Server 2025 |
| `Is64Bit` | `True` | x64 |
| `IsPAE` | `False` | Coherente con `.vbox` |
| `NtProductType` | `NtProductServer` | Server SKU |
| `SystemTime` | `2026-04-05 11:31:07` | Timestamp dump |
| `KeNumberProcessors` | `3` | 3 vCPUs |

**Conclusión:** Dump **válido** para análisis estructurado.

---

# 4. Metodología I — Volatility 3 Framework

**Ubicación toolchain:** `RedTeam/ForensicToolbox/volatility3/`  
**Versión:** 2.28.1  
**Salidas consolidadas:** `RedTeam/ScaningCSAIelf/`

## 4.1 INTENTO V-1 — Perfilado básico (`windows.info`)

| Campo | Detalle |
|-------|---------|
| **Comando** | `vol.py -f ./CSAI.elf windows.info` |
| **Objetivo** | Validar integridad dump, kernel, DTB, símbolos |
| **Resultado** | **ÉXITO** — PDB `ntkrnlmp.pdb` descargado automáticamente |
| **Fuente** | `intento2LecturaRam.md` Intento #1 |

## 4.2 INTENTO V-2 — Plugin nativo `windows.bitlocker`

| Campo | Detalle |
|-------|---------|
| **Comando** | `vol.py -f ./CSAI.elf windows.bitlocker` |
| **Objetivo** | Extracción automatizada FVEK desde `fvevol.sys` |
| **Resultado** | **FALLO** |
| **Error** | `invalid choice 'windows.bitlocker'` |
| **Causa** | Plugin **no integrado** en build local Vol3; era exclusivo Vol2 (elceef) |

## 4.3 INTENTO V-3 — Plugin comunitario Alexandre-D'Hondt

| Campo | Detalle |
|-------|---------|
| **Acción** | `wget` de `bitlocker.py` a `plugins/windows/` |
| **Resultado** | **FALLO** — HTTP 404 |
| **Causa** | Repositorio reestructurado; URL obsoleta |

## 4.4 INTENTO V-4 — Búsqueda lineal `strings` + `grep`

| Campo | Detalle |
|-------|---------|
| **Comando** | `strings -a -t x ./CSAI.elf \| grep "FVE-"` |
| **Objetivo** | Offsets físicos aproximados metadatos BitLocker |
| **Resultado** | **PARCIALMENTE ÚTIL** — confirma actividad `fvevol.sys`, no extrae clave binaria |
| **Limitación** | FVEK almacenada como bytes no imprimibles |

## 4.5 INTENTO V-5 — `aeskeyfind`

| Campo | Detalle |
|-------|---------|
| **Comando** | `aeskeyfind ./CSAI.elf > aes_keys_found.txt` |
| **Objetivo** | Detectar **AES Key Schedules** (128/256 bit) independiente de símbolos Windows |
| **Base estadística** | Relación matemática de expansión Rijndael — no entropía simple |
| **Resultado documentado en intento2** | **ALTAMENTE EFECTIVO** para generar candidatos |
| **Resultado documentado en Intento5** | **No candidatos válidos confirmados** para montaje |
| **Matiz** | Discrepancia entre informes: herramienta produjo listado pero validación FVEK falló |

## 4.6 INTENTO V-6 — `windows.modules`

| Campo | Detalle |
|-------|---------|
| **Comando** | `vol.py -f ./CSAI.elf windows.modules` |
| **Objetivo** | Localizar base de `fvevol.sys` en VA |
| **Resultado** | **ÉXITO** — lista `PsLoadedModuleList` build 26100 |
| **Utilidad** | Acotar búsqueda manual posterior |

## 4.7 INTENTO V-7 — `windows.bigpools.BigPools`

| Campo | Detalle |
|-------|---------|
| **Comando** | `vol.py -r csv ... windows.bigpools.BigPools --tags FVEp,FVEx,FVE0,dFVE,TpmP,Cngb` |
| **Objetivo** | Enumerar allocations kernel BitLocker/TPM/CNG |
| **Resultado** | **ÉXITO — evidencia sólida** |

**Tags Allocated localizados (`intento_romper_bitlocker.md`):**

| Dirección Virtual | Tag | Tamaño | Estado |
|-------------------|-----|--------|--------|
| `0xffff9d0f3a302000` | FVEp | 0x10000 | Allocated |
| `0xffffd003d8657000` | TpmP | 0x1010 | Allocated ⭐ |
| `0xffff9d0f3c424000` | FVEp | 0x10000 | Allocated |
| `0xffffd003d8765000` | FVE0 | 0x10000 | Allocated |
| `0xffff9d0f3701e000` | FVEx | 0x1730 | Allocated |
| `0xffff9d0f37fa4000` | dFVE | 0x4000 | Allocated |
| `0xffff9d0f37025000` | **Cngb** | 0x1430 | Allocated ⭐ |
| `0xffffd003d8775000` | FVE0 | 0x10000 | Allocated |

**Interpretación tags:**

| Tag | Significado |
|-----|-------------|
| FVEp | Pool header FVE |
| FVE0 | Metadata block 0 |
| FVEx | Datos extendidos |
| dFVE | Buffer datos FVE |
| **TpmP** | Pool TPM — candidato **VMK** |
| **Cngb** | CNG buffer — candidato **FVEK** en Windows modernos |

## 4.8 INTENTO V-8 — `windows.memmap` + volcado PID 4

| Campo | Detalle |
|-------|---------|
| **Comando** | `windows.memmap.Memmap --pid 4 --dump` |
| **Objetivo** | Traducir VA BigPools → bytes físicos en dump |
| **Resultado parcial** | `pid.4.dmp` generado (~**1.64 GB**) |
| **Problema** | **Missing memmap page** en VAs críticas (Cngb, FVEx, dFVE, varios FVEp) |

## 4.9 INTENTO V-9 — Plugins adicionales ejecutados

| Plugin | Salida | Hallazgo |
|--------|--------|----------|
| `windows.pslist` | `windows.pstree.txt` | PID 4 System, lsass 860 |
| `windows.memmap` (global) | `memmap_all.csv` | Cobertura incompleta |
| `windows.poolscanner` | `poolscanner_all.csv` | Sin material cripto directo adicional |
| `windows.vadinfo` (lsass) | `windows.vadinfo_lsass.txt` | Reconocimiento credenciales |
| `windows.dumpfiles` (lsass) | `windows.dumpfiles_lsass.txt` | Artefactos LSASS |
| Plugin bitlocker tmp | `860.fve.txt`, `860.aes.txt` | Referencias FVEAPI, strings FVE0 |

## 4.10 INTENTO V-10 — `layerwriter` (reconstrucción capa completa)

| Campo | Detalle |
|-------|---------|
| **Objetivo** | Volcar capa `WindowsIntel32e` completa → eliminar Missing pages |
| **Resultado** | **CANCELADO** antes de finalizar |
| **Artefacto parcial** | `layerdump/tmp_vd02v2oo.vol3` (muy grande) |
| **Consecuencia** | VAs Cngb/FVE no reconstruidas |

## 4.11 Plugins community3 / bitlocker local

Directorio `RedTeam/tmp_plugins/community3/` — repositorio clonado para plugins Vol3 adicionales (Hyper-V, Docker, Yara, etc.). **Sin plugin BitLocker funcional** integrado para WS2025.

Script local `tmp_plugins/bitlocker/bitlocker.py` — intento port; no produjo extracción validada.

## 4.12 Tabla resumen Volatility 3

| ID | Plugin/Acción | Resultado | Bloqueo |
|----|---------------|-----------|---------|
| V-1 | windows.info | ✅ OK | — |
| V-2 | windows.bitlocker | ❌ | No existe en Vol3 |
| V-3 | Plugin comunitario | ❌ | 404 GitHub |
| V-4 | strings/grep | ⚠️ | Solo strings |
| V-5 | aeskeyfind | ⚠️ | Sin validación montaje |
| V-6 | windows.modules | ✅ OK | — |
| V-7 | bigpools | ✅ OK | Solo VA, no bytes |
| V-8 | memmap --pid 4 | ⚠️ | Missing pages |
| V-9 | pslist/vadinfo/... | ✅ Recon | — |
| V-10 | layerwriter | ❌ | Cancelado |

---

# 5. Metodología II — MemProcFS

**Documentos:** `Intentos/intento4LecutraRam.md`, `Analisis_MemProcFS_elf/`  
**Motivación:** Volatility3 insuficiente para WS2025 + BitLocker moderno.

## 5.1 Problemas instalación Kali (descartados)

| Error | Causa | Decisión |
|-------|-------|----------|
| `CMakeLists.txt not found` | Makefile build | — |
| `fuse.h not found` | Falta libfuse-dev | **Pivot a Windows** |

## 5.2 Montaje exitoso en Windows (Dokany)

```powershell
MemProcFS.exe -f CSAI.elf -mount M:
```

**Salida:**

```text
Initialized 64-bit Windows 10.0.26100
M:\
```

## 5.3 Estructura filesystem virtual M:

```text
M:\
├── memory.pmem      (~4.5 GB — RAM física raw)
├── memory.dmp       (~4.8 GB — dump estructurado)
├── forensic/        (artefactos DFIR)
├── registry/        (HKLM, HKU, SAM, SYSTEM...)
├── pid/             (memoria por PID)
│   ├── 4/           → System
│   └── 860/         → lsass.exe
├── name/            (por nombre proceso)
├── sys/version.txt  → 10.0.26100
└── py/regsecrets/   (plugin secretos — explorado)
```

## 5.4 Análisis BitLocker vía MemProcFS

**Servicios confirmados en registro:**

```text
BDESVC, fvevol, CryptSvc, EFS, FileCrypt
```

**Procesos objetivo:**

| PID | Proceso | Probabilidad material BitLocker |
|-----|---------|--------------------------------|
| 4 | System | **Alta** — kernel, drivers |
| 860 | lsass.exe | Alta credenciales / media FVEK |
| 624 | csrss.exe | Media |
| 1484 | VBoxService.exe | Baja |

**Resultado clave:** Registro accesible; **VMK/FVEK no en HKLM** (esperado — claves en RAM/pools, no registry).

## 5.5 Valor forense MemProcFS

| Logró | No logró |
|-------|----------|
| Montaje dump WS2025 | Parser BitLocker nativo FVEK |
| Registro completo | Extracción automática claves |
| memory.pmem para tallado | Sustituir Missing pages Vol3 |
| Enumeración 85+ procesos | Montaje Kali directo |

## 5.6 Scripts shell PowerShell en `Analisis_MemProcFS_elf/`

| Script | Función |
|--------|---------|
| `analyze_bitlocker.ps1` | Orquestación análisis |
| `extract_bitlocker_keys.ps1` | Extracción claves (sin éxito final) |
| `extract_bitlocker_kali.sh` | Pipeline Kali |
| `extract_bitlocker_vol3.sh` | Integración Vol3 |

Informe agente: `INFORME_FINAL_BITLOCKER_EXTRACTION.md` — confirma candidatos estructurales, montaje Kali pendiente.

---

# 6. Metodología III — Herramientas auxiliares (HxD, strings, aeskeyfind, GDB lectura)

## 6.1 HxD — Análisis visual previo a Python

**Usos documentados:**

| Contexto | Patrón buscado | Resultado |
|----------|----------------|-----------|
| Volcado `.elf` | `FVEK`, `FVE-SET`, `IOCTL_FVE` | Confirmación visual buffers |
| Disco montado VHD (Z:) | `-FVE-FS-`, Key Package `64 4A 3F 52` | Localización metadatos disco |
| Blob metadatos | Secuencia `B0 B6 CF 98...` | Base para `probarCandidatos.py` |

**Justificación metodológica (`recopilacion2.md`):** Búsqueda visual manual **antes** de barridos masivos Python — reduce falsos positivos al fijar regiones de interés.

**Limitación:** Impracticable sobre ~4 GB repetidamente; migración obligatoria a scripts.

## 6.2 INTENTO L.1–L.5 — Lectura vía GDB Stub (`intento1LecturaRam.md`)

Aunque orientados también a inyección, documentan **lectura** de RAM live:

| ID | Acción | Resultado |
|----|--------|-----------|
| L.1 | Búsqueda UTF-16 login en `.elf` | ✅ Offsets `0x2DEDD0F0`, `0x7B9AF5C` |
| L.2 | Búsqueda en `.sav` | ❌ LZF |
| L.3 | GDB `target remote :1234` | ❌ Timeout |
| L.4 | Handshake PS `$?#3f` | ⚠️ Respuesta `$` parcial |
| L.5 | Lectura `m7b9af5c,14#00` | ❌ SIGTRAP T05 — kernel protegido |

## 6.3 Búsqueda canario `HOLAHOLAHOLA` (Intento 5 §13)

| Paso | Resultado |
|------|-----------|
| Escribir en login, Save State | — |
| `strings` + `grep` | ❌ No encontrado |
| Lección | UTF-16, compresión, buffers gráficos — **strings insuficiente** |

## 6.4 Impacto PAE/NX deshabilitado (`intento2LecturaRam.md` §5)

**A nivel forense:**

- Esquema protección páginas simplificado.
- Estructuras FVEK potencialmente más lineales en pool.
- Sin VBS/Credential Guard mandatorio.

**Nota:** Vol3 confirma x64 canónico pese a `IsPAE=False`.

---

# 7. Metodología IV — WinDbg y lectura kernel (evaluación)

| Aspecto | Detalle |
|---------|---------|
| **Objetivo** | Lectura/depuración kernel pools BitLocker |
| **Requisitos** | `bcdedit /set hypervisorlaunchtype off`, desactivar Defender |
| **Resultado** | **FALLO** — excepción *Meditation Guru* VirtualBox |
| **Decisión** | Descartado; priorizar dumps offline |

---

# 8. Metodología V — Pipeline `AnalisisDeVolcados`

**Directorio:** `AnalisisDeVolcados/`  
**Documento agente:** `intento3LecturaRam.md` (intentos 1–5 estadísticos)

## 8.1 INTENTO D-1 — Firma disco `-FVE-FS-` en RAM (`analisisVolcados.py`)

| Campo | Detalle |
|-------|---------|
| **Script** | `analisisVolcados.py` |
| **Heurística** | Buscar magic `-FVE-FS-` (8 B), extraer **512 B** posteriores → CSV |
| **Base teórica** | Metadatos volumen en disco |
| **Resultado** | **INOPERANTE en RAM** |
| **Error conceptual** | OS no copia bloque metadatos disco literalmente; usa `_FVE_CONTROL_BLOCK` en pool |

## 8.2 INTENTO D-2 — Ventana deslizante + AES Key Unwrap (`probarCandidatos.py`)

| Campo | Detalle |
|-------|---------|
| **Entrada** | Blob HxD 48 B + `candidatos.csv` VMK |
| **Heurística** | Sliding window 48 B + `aes_key_unwrap(vmk, ventana)` |
| **Variantes** | VMK normal + invertida `[::-1]` (endianness) |
| **Resultado** | **NEGATIVO** — candidatos CSV no contenían VMK real |

## 8.3 INTENTO D-3 — Inversión endianness

| Campo | Detalle |
|-------|---------|
| **Herramienta** | Python slice `[::-1]` |
| **Justificación** | x86 little-endian vs arrays criptográficos secuenciales |
| **Resultado** | **NEGATIVO** — universo candidatos ya inválido |

## 8.4 INTENTO D-4 — `range_coverage_score` (Density Testing)

| Campo | Detalle |
|-------|---------|
| **Heurística** | Dividir byte `0x00-0xFF` en **16 bins** de 16 valores; score = bins ocupados / 16 |
| **Umbral implícito** | Clave legítima → score ≈ 1.0; ASCII/punteros → < 0.4 |
| **Resultado** | **Parcial** — reduce FP a la mitad |
| **Fallo** | Secuencias pseudoordenadas (`00 10 20 30...`) score 1.0 sin ser aleatorias |

**Base estadística:**

$$\text{Score}_{\text{cobertura}} = \frac{|\{b_i : count(b_i) > 0\}|}{16}$$

donde $b_i$ son bins de 16 valores hex cada uno sobre ventana 32 B.

## 8.5 INTENTO D-5 — Chi-cuadrado $\chi^2$ (`analisisVolcados3.py`)

| Campo | Detalle |
|-------|---------|
| **Fórmula** | $\chi^2 = \sum \frac{(O_i - E_i)^2}{E_i}$ |
| **Bins** | 16 (byte // 16) |
| **Esperado $E_i$** | $32/16 = 2.0$ por bin |
| **Umbral** | $\chi^2 \leq 30.6$ |
| **Resultado** | ~**10⁷ candidatos** (~320 MB archivo) |
| **Problema** | Explosión combinatoria posterior |

## 8.6 Pipeline evolutivo de scripts

```text
Volcados/*.elf
    → analisisVolcados.py      (-FVE-FS- markers → CSV)  [FALLIDO concepto RAM]
    → analisisVolcados2.py     (entropía Shannon > 4.5, paralelo 8 proc)
    → analisisVolcados3.py     (+ χ² + entropía modular diferencias)
    → candidatos.py            (intersección 3 CSV, umbral 4.8)
    → candidatos2.py           (SQLite intersección CSAI1/2/3)
    → candidatos3.py           (intersección 3 .bin ordenados, 8 proc)
    → probarCandidatos*.py     (validación unwrap vs blob disco)
```

## 8.7 Montaje disco VHD en Windows (`comandos.md`)

```powershell
VBoxManage clonemedium disk CSAI-disk001.vdi CSAI-disk001.vhd --format VHD
# Montar Z: en Administración de discos
manage-bde -unlock Z: -RecoveryKey llave.bek   # FRACASO documentado
```

**Segmento Key Package identificado en disco (HxD):**

```hex
64 4A 3F 52 99 71 E2 4A 1A 5A 90 21 4E 3F EC C3 ...
```

---

# 9. Metodología VI — Extractor híbrido `intento_romper_bitlocker`

**Directorio:** `intento_romper_bitlocker/`  
**Informe:** `intento_romper_bitlocker.md`

## 9.1 Pipeline `extract_fvek_from_vol3.py`

**Entradas:**

- `bigpools_fve.csv` / `bigpools_cngb.csv`
- `memmap_pid4_dump.csv`
- `pid.4.dmp` (1.64 GB)

**Lógica:**

1. Parse CSV BigPools (auto-detect UTF-16/UTF-8).
2. Para cada región tagged → `carve_region()` vía memmap.
3. `scan_for_aes_keys()` — validación **AES Key Schedule** matemática (S-box + Rcon).
4. Emitir JSON + blobs `.bin` + candidatos `.fvek`.

## 9.2 Resultados JSON (`fvek_extraction_report.json`)

| Región | Tallado | AES128 | AES256 | Error |
|--------|---------|--------|--------|-------|
| FVEp `0x9D0F3A302000` | ❌ | — | — | Missing memmap page |
| **TpmP** `0xD003D8657000` | ✅ blob | 0 | 0 | — |
| FVEp `0x9D0F3C424000` | ✅ blob | 0 | 0 | — |
| FVE0 `0xD003D8765000` | ✅ blob | 0 | 0 | — |
| FVEx `0x9D0F3701E000` | ❌ | — | — | Missing memmap page |
| **Cngb** `0x9D0F37025000` | ❌ | — | — | Missing memmap page |

**Conclusión:** Blobs tallados **sin key schedules AES válidos**; regiones más prometedoras (**Cngb**, **TpmP** parcial) con errores mapeo.

## 9.3 Artefactos generados

```text
allocated_fve_tags.txt
bigpools_*.csv
memmap_all.csv / memmap_pid4*.csv
poolscanner_all.csv
fve_offset_map.txt / map_fve_offsets.ps1
fvek_candidates/ + fvek_candidates_cngb/
memdump/pid.4.dmp
```

---

# 10. Metodología VII — Scripts Python (tallado manual y heurísticas estadísticas)

> **Última metodología** según criterio operativo — análisis exhaustivo de heurísticas y bases estadísticas.

## 10.1 Inventario completo scripts RAM/BitLocker

| Script | Ubicación | Generación |
|--------|-----------|------------|
| `key_search.py` | RedTeam/ | Contexto FVEK @ offset fijo |
| `key_search2.py` | RedTeam/ | Firmas FVEK/VMK lineales |
| `key_search3.py` | RedTeam/ | Multi-patrón BitLocker |
| `key_search4.py` | RedTeam/ | Entropía ratio + alineación 16 B |
| `extraer_fvep.py` | RedTeam/ | Tag pool FVEp |
| `extract_fvek_from_vol3.py` | intento_romper_bitlocker/ | Híbrido Vol3 + AES schedule |
| `analisisVolcados.py` | AnalisisDeVolcados/ | Marker -FVE-FS- |
| `analisisVolcados2.py` | AnalisisDeVolcados/ | Entropía Shannon paralela |
| `analisisVolcados3.py` | AnalisisDeVolcados/ | Shannon + χ² + diff entropy |
| `candidatos.py` | AnalisisDeVolcados/ | Intersección 3 volcados |
| `candidatos2.py` | AnalisisDeVolcados/ | SQLite intersección |
| `candidatos3.py` | AnalisisDeVolcados/ | Merge .bin multiproceso |
| `probarCandidatos.py` | AnalisisDeVolcados/ | AES-KW unwrap |

---

## 10.2 `key_search.py` — Ventana contextual alrededor de hallazgo previo

**Heurística:** No barrido — **salto directo** a offset conocido `0xae32db16` (hallazgo agente previo con tag FVEK).

```python
target_pos = 0xae32db16
f.seek(target_pos - 64)
data = f.read(512)  # ventana [-64, +448] bytes
```

| Parámetro | Valor | Justificación |
|-----------|-------|---------------|
| Pre-contexto | 64 B | Headers pool / metadata antes del tag |
| Post-contexto | 448 B | Suficiente para VMK+FVEK adyacentes |
| Formato salida | Hex dump 16 B/línea | Inspección manual |
| Marcador | `->` si chunk contiene `FVEK` | Localización visual |

**Base estadística:** Ninguna — **análisis determinista por puntero**.

**Resultado:** Contexto hex around FVEK; clave aislada no identificada automáticamente.

---

## 10.3 `key_search2.py` — Búsqueda lineal firmas ASCII

**Patrones:** `b'FVEK'`, `b'VMK'`

**Heurística ventana:** `[-32, +96]` bytes alrededor de cada hit.

| Aspecto | Detalle |
|---------|---------|
| Complejidad | O(n) sobre 4 GB — carga completa en RAM |
| Supuesto | Tags ASCII visibles adyacentes a claves |
| Realidad Windows | Claves binarias; tags en pool headers separados del material |

**Resultado:** Localiza posiciones firmas; **no extrae clave utilizable** sin parser estructural.

---

## 10.4 `key_search3.py` — Diccionario multi-firma

**Patrones:**

```python
patterns = {
    'FVE_SET': b'FVE_SET',
    'IOCTL_FVE': b'IOCTL_FVE',
    'BitLocker': b'BitLocker',
    'EFS0': b'EFS0', 'EFS1': b'EFS1',
}
```

**Heurísticas:**

- Reportar **máximo 5** ocurrencias/patrón (anti-saturación consola).
- Extracción fija región `0x612162d4` (256 B) — offset VMK de sesión anterior.

**Base estadística:** Conteo frecuencias ocurrencias (descriptivo, no inferencial).

**Resultado:** Confirma presencia strings BitLocker; región VMK manual requiere validación entropía posterior.

---

## 10.5 `key_search4.py` — Entropía por ratio de unicidad

**Parámetros:**

| Parámetro | Valor |
|-----------|-------|
| Ventana | 32 bytes |
| Paso | **16 bytes** (alineación x64 pool) |
| Umbral entropía | **> 0.93** (ratio, no Shannon) |
| Máx nulls | ≤ 2 |
| Máx 0xFF | ≤ 2 |
| Primer byte | ≠ 0x00, ≠ 0xFF |
| Máx repetición byte | ≤ 4 |

**Fórmula entropía usada (ratio simplificado):**

$$\text{entropy}_{\text{ratio}} = \frac{|\text{unique bytes}|}{32}$$

**Justificación vs Shannon:**

- Ratio unicidad es **O(32)** por ventana vs O(256) histograma — 100× más rápido en Python puro.
- Umbral 0.93 → ≥ 30 bytes distintos en ventana 32 — filtra bloques repetitivos/ceros.
- Alineación 16 B: Non-Paged Pool Windows alinea allocations múltiplos 16.

**Limitación estadística:**

- Ratio alto **no implica** aleatoriedad criptográfica — permutaciones casi-full también pasan.
- Genera falsos positivos masivos sin segundo filtro (χ²).

**Salida:** TOP 15 candidatos hex para prueba manual `dislocker -k`.

---

## 10.6 `extraer_fvep.py` — Tallado por tag pool

**Heurística:** `data.find(b'FVEp')` → volcar 512 B desde tag.

**Supuesto:** Clave inmediatamente después del tag en `_POOL_HEADER`.

**Realidad:** Estructura FVEp es header 64 KB allocation — clave no necesariamente adyacente ASCII.

---

## 10.7 `extract_fvek_from_vol3.py` — Validación matemática AES Key Schedule

**Base estadística:** **Determinística criptográfica**, no probabilística.

La función `valid_schedule()` reconstruye expansión de claves Rijndael:

1. Toma segmento 176 B (AES-128) o 240 B (AES-256).
2. Aplica `core()` con S-box + Rcon.
3. Compara byte a byte con schedule observado en memoria.

**Teorema operativo:** Si el schedule es válido, los primeros 16/32 B son la **clave AES original** con alta confianza.

**Heurística selección candidato FVEK:**

```python
if 0 < len(aes128) <= 2: selected = aes128[:2]  # FVEK + TWEAK pair
elif 0 < len(aes256) <= 2: selected = aes256[:2]
```

**Justificación par 1–2 claves:** BitLocker AES-XTS usa **dos claves** (data + tweak).

**Fallo observado:** Blobs tallados no contenían schedules válidos — posible ofuscación XOR, AES-NI sin schedule en RAM, o blob incompleto por Missing pages.

---

## 10.8 `analisisVolcados2.py` — Entropía de Shannon optimizada

**Constantes:**

```python
WINDOW_SIZE = 32
ENTROPY_THRESHOLD = 4.5
NUM_PROCESSES = 8
PIECES_PER_DUMP = 100
```

**Fórmula Shannon (bits/byte):**

$$H(X) = -\sum_{i=0}^{255} p_i \log_2 p_i$$

**Implementación optimizada:**

- Ventana deslizante con **actualización incremental** histograma (no recalcular desde cero).
- `TERM_CACHE[c] = c * log2(c)` precalculado.
- `_window_entropy(sum_terms) = log2(32) - sum_terms/32`

**Justificación umbral 4.5:**

- Máximo teórico $H_{\max} = \log_2(32) = 5.0$ bits (32 bytes todos distintos).
- Umbral 4.5 → ≥ 90% del máximo — **muy estricto**.
- Texto ASCII típico $H \approx 3.0$–3.5 → descartado.

**Paralelización:** 100 chunks/dump × 8 workers → escala lineal en cores.

---

## 10.9 `analisisVolcados3.py` — Triple filtro estadístico

### 10.9.1 Filtro 1: Entropía Shannon > 4.5

(Idéntico a analisisVolcados2.)

### 10.9.2 Filtro 2: Entropía modular de diferencias (`modular_diff_entropy`)

**Definición:** Para ventana $w[0..31]$, calcular diferencias circulares:

$$d_i = \min\big((w_{i+1} - w_i) \bmod 256,\; 256 - (w_{i+1} - w_i) \bmod 256\big)$$

Entropía Shannon sobre histograma de $d_i$.

**Umbral:** `DIFF_ENTROPY_THRESHOLD = 3.6`

**Justificación (`intento3LecturaRam.md`):**

- Claves aleatorias → diferencias uniformemente distribuidas en [0,128].
- Estructuras ordenadas (tablas, punteros) → diferencias pequeñas repetidas → entropía baja.
- Filtra secuencias `00 10 20 30...` que pasaban χ² de cobertura binaria.

### 10.9.3 Filtro 3: Chi-cuadrado uniformidad

```python
CHI2_UNIFORMITY_MAX = 30.6
```

**Cálculo:**

$$\chi^2 = \sum_{j=0}^{15} \frac{(O_j - 2.0)^2}{2.0}$$

con 16 bins (byte // 16), $E_j = 32/16 = 2.0$.

**Justificación umbral 30.6 (`intento3LecturaRam.md`):**

- Para 16 bins y $E=2$, distribución uniforme esperada $\chi^2 \approx 15$ (df=15) en el límite ideal.
- Texto/estructuras → $\chi^2 > 100$.
- 30.6 es **corte empírico** entre ruido estructural y aleatoriedad criptográfica — ligeramente permisivo para no perder claves con ligera asimetria muestral.

**Distribución teórica referencia:**

| Tipo dato | $\chi^2$ típico | $H$ Shannon | Diff entropy |
|-----------|-----------------|-------------|--------------|
| Clave AES-256 | 5–25 | 4.7–5.0 | 3.8–4.5 |
| Texto ASCII | >100 | 3.0–3.8 | 1.5–2.5 |
| Punteros x64 | 80–200 | 3.5–4.0 | 2.0–3.0 |
| Ceros/FF padding | >150 | <1.0 | <1.0 |

### 10.9.4 Complejidad combinatoria resultante

Documentado en `intento3LecturaRam.md`:

$$\text{Ops}_{\text{unwrap}} = 10^7 \times 10^6 \times 2 \approx 2 \times 10^{13}$$

**Mitigación propuesta no implementada:**

- Alineación estricta paso 16 B → reduce $10^7$ → $<2 \times 10^6$.
- Pre-filtro Key Package disco → $<5$ blobs disco.
- Producto final viable: $\approx 10^7$ unwraps (horas vs años).

---

## 10.10 `candidatos.py` — Intersección multi-volcado

**Heurística clave:** Candidato válido solo si aparece en **todos** los CSV (CSAI1, CSAI2, CSAI3).

**Base estadística — argumento frecuentista:**

- Probabilidad random 32 B idénticos en 3 dumps independientes del **mismo estado** ≈ 0 salvo material persistente kernel.
- Falsos positivos aleatorios **no correlacionados** entre dumps → eliminados por intersección.

**Umbral adicional:** `ENTROPY_THRESHOLD = 4.8` (más estricto que 4.5).

**Entropía implementada (nota):** Versión sobre **string hex** en una iteración — bug metodológico menor; versión corregida en analisisVolcados2/3 sobre bytes raw.

---

## 10.11 `candidatos2.py` — SQLite WAL intersección

**Optimización:** Base SQLite con flags `p2`, `p3` por presencia en volcado 2/3.

**Heurística:** Mismo principio intersección; escala a millones filas con índices.

---

## 10.12 `candidatos3.py` — Merge ordenado multiproceso

**Entrada:** 3 archivos `.bin` de 32 B/registro (salida analisisVolcados3).

**Algoritmo:** Intersección **ordenada** tipo merge-sort externo:

- `SliceReader` por archivo.
- Avance sincronizado al máximo de tres punteros.
- 64 tareas por rango byte inicial + 8 procesos.

**Complejidad:** O(N) por archivo vs O(N²) naive.

**Salida:** `candidatos.bin` — intersección estable tri-volcado.

---

## 10.13 `probarCandidatos.py` — Validación criptográfica AES-KW

**Heurística final:** Único test con **significado criptográfico definitivo**:

```python
fvek = aes_key_unwrap(vmk_test, ventana_48_bytes)
```

Si no lanza excepción → par VMK/FVEK válido.

**Ventana 48 B:** Tamaño estándar bloque AES Key Wrap RFC 3394 para clave 256-bit.

---

## 10.14 Evolución de umbrales estadísticos (tabla maestra)

| Script | Métrica | Umbral | Tipo | Justificación |
|--------|---------|--------|------|---------------|
| key_search4 | Ratio unicidad | >0.93 | Heurística rápida | 30/32 bytes distintos |
| analisisVolcados2 | Shannon H | >4.5 | Información | 90% H_max |
| analisisVolcados3 | Shannon H | >4.5 | Información | Idem |
| analisisVolcados3 | Diff entropy | ≥3.6 | Información | Diferencias byte-a-byte |
| analisisVolcados3 | χ² uniformidad | ≤30.6 | Bondad ajuste | vs uniforme 16 bins |
| candidatos.py | Shannon (hex) | >4.8 | Información | Más estricto + intersección |
| extract_fvek | AES schedule | válido/inválido | Determinista | Matemática Rijndael |
| probarCandidatos | AES-KW unwrap | excepción/no | Determinista | RFC 3394 |

---

# 11. Intento de montaje en Kali Linux / Windows host

## 11.1 Flujo objetivo Kali

```bash
sudo dislocker -V /dev/sdb4 -k <LLAVE_RAM> -- /mnt/bitlocker
# o
bdemount -k FVEK -t TWEAK ...
```

## 11.2 Intentos documentados

| Plataforma | Acción | Resultado |
|------------|--------|-----------|
| Kali | `dislocker` con candidatos TOP key_search4 | ❌ Ninguna clave válida |
| Kali | `guestmount` sobre .vdi | ❌ LUKS/BitLocker bloqueado |
| Windows | `manage-bde -unlock Z: -RecoveryKey llave.bek` | ❌ (`comandos.md`: "no funciona") |
| Windows | Candidatos `.fvek` extract_fvek | ❌ Sin validación exitosa |

## 11.3 Estado frente a objetivo

```text
PARCIAL — evidencia BitLocker en RAM confirmada
NO COMPLETADO — montaje volumen con clave extraída
```

---

# 12. Análisis integrado de resultados

## 12.1 Matriz global de intentos de lectura RAM

| # | Fuente informe | Metodología | ID | Resultado clave |
|---|----------------|-------------|-----|-----------------|
| 1 | intento1 | `.elf` búsqueda UI | L.1 | ✅ Offsets login |
| 2 | intento1 | `.sav` LZF | L.2 | ❌ Compresión |
| 3 | intento1 | GDB read | L.3–L.5 | ❌ Timeout/SIGTRAP |
| 4 | intento2 | windows.info | V-1 | ✅ Dump válido |
| 5 | intento2 | bitlocker plugin | V-2–V-3 | ❌ No disponible |
| 6 | intento2 | strings/aeskeyfind | V-4–V-5 | ⚠️ Parcial |
| 7 | intento2 | bigpools/memmap | V-7–V-8 | ✅ Tags / ❌ bytes |
| 8 | intento4 | MemProcFS | — | ✅ Montaje M: |
| 9 | Intento5 | Save State | §2.1 | ✅ Tags strings |
| 10 | Intento5 | dumpvmcore | §2.2 | ✅ ELF válido |
| 11 | Intento5 | extract_fvek | §7–9 | ❌ Missing pages |
| 12 | Intento5 | layerwriter | §12 | ❌ Cancelado |
| 13 | Intento5 | HOLAHOLAHOLA | §13 | ❌ strings |
| 14 | intento3 | -FVE-FS- RAM | D-1 | ❌ Concepto erróneo |
| 15 | intento3 | sliding+unwrap | D-2 | ❌ Candidatos malos |
| 16 | intento3 | endianness | D-3 | ❌ |
| 17 | intento3 | range coverage | D-4 | ⚠️ FP |
| 18 | intento3 | χ² 30.6 | D-5 | ⚠️ 10⁷ candidatos |
| 19 | RedTeam | key_search 1–4 | — | ⚠️ PoC tallado |
| 20 | AnalisisDeVolcados | candidatos 1–3 | — | ⚠️ Intersección |
| 21 | AnalisisDeVolcados | probarCandidatos | — | ❌ Sin match |
| 22 | intento_romper | extract_fvek vol3 | — | ❌ Missing Cngb |

## 12.2 Qué funcionó

- Adquisición `.elf` y `.sav` en sweet spot login.
- Validación Volatility + MemProcFS WS2025.
- Localización tags FVE*/TpmP/Cngb Allocated.
- Volcado 1.64 GB PID 4 System.
- Pipeline estadístico evolutivo (Shannon → χ² → intersección).
- Validador criptográfico AES schedule + AES-KW (herramientas listas).
- Identificación metadatos disco (Key Package HxD).

## 12.3 Qué no funcionó

- Extracción VMK/FVEK montable.
- Plugin BitLocker Vol3 nativo.
- Resolución completa VAs Cngb/TpmP críticas.
- layerwriter completo.
- Cruce combinatorio RAM×disco a escala 10¹³.
- Montaje Kali/Windows con candidatos generados.

## 12.4 Evaluación global (`Intento5LecturaRam.md`)

```text
PARCIALMENTE EXITOSA
```

Confirmada presencia material criptográfico; **no** recuperada clave utilizable por cobertura memmap y explosión combinatoria.

---

# 13. Problemas encontrados y lecciones aprendidas

## 13.1 Missing memmap page

| Causa | Efecto | Mitigación propuesta |
|-------|--------|---------------------|
| Paged pool no presente en dump lineal | No tallar Cngb | Completar layerwriter |
| Memmap PID4 incompleto | Blobs parciales | memmap global + pid específico fvevol |
| VA canonicalización | Offsets erróneos | Usar canonical48() |

## 13.2 Explosión combinatoria

| Fase | Magnitud |
|------|----------|
| Entropía sola | ~688 MB candidatos.bin |
| χ² filtrado | ~320 MB (~10⁷) |
| Cruce disco | ~10¹³ unwraps |

**Lección:** Filtro estadístico necesario pero **insuficiente** sin ancla estructural (BigPools, Key Package disco).

## 13.3 Error conceptual Intento D-1

Buscar `-FVE-FS-` (firma **disco**) en RAM — **invalido**. RAM contiene objetos kernel, no sectores VBR.

## 13.4 Windows Server 2025 soporte herramientas

Build 26100 extremadamente reciente → plugins Vol2 obsoletos, Vol3 incompleto, MemProcFS mejor pero sin parser BitLocker.

## 13.5 Ofuscación BitLocker en memoria (`intento3` §3)

1. Non-Paged Pool aislado (no pagefile).
2. XOR dinámico VMK en reposo (anti cold boot).
3. AES-NI → key schedule expandido, no clave plana 32 B.

---

# 14. Mapeo MITRE ATT&CK

| Técnica | ID | Aplicación |
|---------|-----|------------|
| OS Credential Dumping: LSASS Memory | T1003.001 | Análisis lsass PID 860 |
| Data from Local System | T1005 | Volcado RAM hipervisor |
| Exploitation for Credential Access | T1212 | Extracción VMK/FVEK RAM |
| Weaken Encryption | T1600 | Objetivo BitLocker |
| Impair Defenses: Disable AV (host) | T1562.001 | Exclusiones Defender VBoxManage |

---

# 15. Conclusiones y líneas futuras

## 15.1 Conclusión

La fase de **lectura RAM para romper BitLocker** demostró:

1. **Viabilidad teórica** — material FVE/TPM/CNG presente con volumen desbloqueado en login.
2. **Viabilidad práctica parcial** — adquisición y reconocimiento exitosos; extracción clave bloqueada.
3. **Bloqueo principal** — Missing memmap pages en regiones Cngb/TpmP + ausencia parser BitLocker WS2025.

## 15.2 Prioridades siguientes

| Prioridad | Acción |
|-----------|--------|
| 🔴 | Completar `layerwriter` primary |
| 🔴 | Re-ejecutar `extract_fvek_from_vol3.py` sobre capa completa |
| 🔴 | Validar candidatos con `dislocker` automatizado |
| 🟡 | Combinar `.sav` (TPM state) + `.elf` (RAM) |
| 🟡 | Alinear barrido χ² a paso 16 B fijo |
| 🟡 | Anclar unwrap solo a Key Package disco (<5 blobs) |
| 🟢 | Pivot inyección RAM / bypass offline utilman |

---

# 16. Anexos

## Anexo A — Comandos Volatility consolidados

```powershell
cd ForensicToolbox\volatility3
py vol.py -f ..\..\CSAI.elf windows.info
py vol.py -f ..\..\CSAI.elf windows.bigpools.BigPools
py vol.py -f ..\..\CSAI.elf windows.modules
py vol.py -r csv -f ..\..\CSAI.elf windows.bigpools.BigPools --tags FVEp,FVEx,FVE0,dFVE,TpmP,Cngb > bigpools_fve.csv
py vol.py -o memdump -f ..\..\CSAI.elf windows.memmap.Memmap --pid 4 --dump
```

## Anexo B — Comandos adquisición

```powershell
VBoxManage debugvm "CSAI" dumpvmcore --filename=memoria.elf
VBoxManage controlvm "CSAI" savestate
MemProcFS.exe -f CSAI.elf -mount M:
```

## Anexo C — Fuentes documentales

| Archivo | Contenido |
|---------|-----------|
| `Intentos/intento1LecturaRam.md` | Adquisición .elf/.sav/GDB L.1–L.5 |
| `Intentos/intento2LecturaRam.md` | dumpvmcore, Volatility V-1–V-6, PAE/NX |
| `Intentos/intento3LecturaRam.md` | Pipeline estadístico D-1–D-5, χ² |
| `Intentos/intento4LecutraRam.md` | MemProcFS, migración Windows |
| `Intentos/Intento5LecturaRam.md` | Cronología completa BitLocker RAM |
| `intento_romper_bitlocker.md` | extract_fvek, artefactos CSV |
| `recopilacion2.md` | Esquema secciones 1–2 |
| `recopilacionLecturaRam.md` | Síntesis previa |
| `Analisis_MemProcFS_elf/*` | Informes agente MemProcFS |

## Anexo D — Glosario

| Término | Definición |
|---------|------------|
| **FVEK** | Full Volume Encryption Key |
| **VMK** | Volume Master Key |
| **Cngb** | CNG Buffer pool tag |
| **TpmP** | TPM Pool tag |
| **DTB/CR3** | Directory Table Base — traducción VA→PA |
| **AES-KW** | AES Key Wrap (RFC 3394) |
| **Key Schedule** | Expansión Rijndael para round keys |
| **LZF** | Compresión RAM en `.sav` VirtualBox |
| **Missing page** | VA no resuelta en memmap Vol3 |

---

**Fin del informe — `recopilacionLecturaRamDefinitiva.md`**

*Ejercicio Red Team vs Blue Team CSAI 2025. Entorno aislado Host-Only. Uso educativo.*
