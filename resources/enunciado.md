Objetivo: Comprometer la máquina rival mediante cualquier vector disponible (Lógico
o Físico).
 Reconocimiento: Descubrimiento de activos en la red ciega (netdiscover,
arp-scan).
 Vectores de Ataque Permitidos:
o Vector Lógico: Explotación de vulnerabilidades en la Web (SQLi, XSS,
RCE) o servicios mal configurados.
o Vector Físico/Infraestructura: Intentar eludir la BIOS, atacar el cifrado
BitLocker, manipulación de la VM (Evil Maid Attack), reseteo de
contraseñas offline (si el disco no está cifrado).
 Condición de Victoria (Flag): Obtener una shell como NT AUTHORITY\SYSTEM
o exfiltrar la base de datos de usuarios.
Tecnología / Herramientas Marco Normativo de Referencia
Nmap, Wireshark, Burp Suite PTES (Penetration Testing Execution Standard)
Metasploit, SQLMap, Hydra MITRE ATT&CK (Tácticas y Técnicas)
Chntpw, Lazesoft (Ataque Físico) OSSTMM (Manual de Metodología de Seguridad)

Revisa el informe, plantea, ejecuta y documenta ataques que no se hayan realizado todavía sobre la máquina objetivo. Documenta los pasos y comandos al detalle. Evita el ataque a bitlocker.