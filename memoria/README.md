# Instrucciones de Compilación y Limpieza de la Memoria

Este directorio contiene la estructura y configuración en LaTeX para la memoria del proyecto.

## 1. Compilación del PDF

El archivo raíz del documento es `memoria.tex`. Para generar y compilar el documento PDF resolviendo correctamente el índice de contenidos y las referencias, ejecuta las siguientes instrucciones consecutivas desde la terminal:

```bash
# Primera pasada (genera la estructura y el índice de contenidos)
xelatex -interaction=nonstopmode -halt-on-error memoria.tex

# Segunda pasada (resuelve referencias y actualiza números de página en el índice)
xelatex -interaction=nonstopmode -halt-on-error memoria.tex
```

---

## 2. Limpieza de Archivos Intermedios

Durante la compilación se generan diversos archivos auxiliares (`.aux`, `.log`, `.toc`, `.out`, etc.), tanto en el directorio raíz como en los subdirectorios. Puedes borrarlos de forma recursiva ejecutando el siguiente comando en PowerShell:

```powershell
Get-ChildItem -Path . -Include *.aux, *.log, *.out, *.toc, *.lof, *.lot, *.fls, *.fdb_latexmk, *.synctex.gz, *.acn, *.glo, *.ist -Recurse | Remove-Item -Force
```
