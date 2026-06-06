# Script de reparación de SSH en el servidor
$sshdConfig = "C:\ProgramData\ssh\sshd_config"

if (Test-Path $sshdConfig) {
    Write-Host "[+] Reparando $sshdConfig..."
    $content = Get-Content $sshdConfig
    $newContent = $content -replace '#Match Group administrators', 'Match Group administrators' -replace '#\s+AuthorizedKeysFile', '   AuthorizedKeysFile'
    $newContent | Set-Content $sshdConfig -Encoding UTF8
    
    Write-Host "[+] Configurando ACLs en administrators_authorized_keys..."
    $authKeys = "C:\ProgramData\ssh\administrators_authorized_keys"
    if (Test-Path $authKeys) {
        icacls $authKeys /inheritance:r /grant '*S-1-5-32-544:F' 'SYSTEM:F'
        icacls $authKeys /setowner '*S-1-5-32-544'
    }
    
    Write-Host "[+] Reiniciando servicio SSH..."
    Restart-Service sshd
    Write-Host "[!] SSH Reparado."
} else {
    Write-Error "No se encontro el archivo de configuracion en $sshdConfig"
    exit 1
}
