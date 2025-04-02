#!/bin/bash
# scan_services.sh: Varredura de serviços utilizando Nmap

TARGET=$1

if [ -z "$TARGET" ]; then
    echo "Uso: $0 <target>"
    exit 1
fi

echo "Iniciando varredura de serviços no host $TARGET..."
nmap -sV -T4 $TARGET -oN services_scan.txt

echo "Varredura de serviços concluída. Resultado salvo em services_scan.txt."
