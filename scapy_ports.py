#!/usr/bin/env python3
import sys
from scapy.all import IP, TCP, sr1, conf

def scan_port(target, port, timeout=1):
    """
    Envia um pacote SYN para a porta especificada e analisa a resposta.
    
    Retorna:
      - "Open" se a porta responder com SYN/ACK (flags 0x12)
      - "Closed" se responder com RST/ACK (flags 0x14)
      - "Filtered or No Response" se não houver resposta
    """
    # Cria o pacote IP/TCP com flag SYN
    packet = IP(dst=target) / TCP(dport=port, flags="S")
    # Envia o pacote e espera pela resposta
    response = sr1(packet, timeout=timeout, verbose=0)
    
    if response is None:
        return "Filtered or No Response"
    elif response.haslayer(TCP):
        tcp_layer = response.getlayer(TCP)
        if tcp_layer.flags == 0x12:  # SYN/ACK
            # Envia um RST para fechar a conexão de forma limpa
            sr1(IP(dst=target) / TCP(dport=port, flags="R"), timeout=timeout, verbose=0)
            return "Open"
        elif tcp_layer.flags == 0x14:  # RST/ACK
            return "Closed"
    return "Unknown"

def scan_ports(target, ports):
    """
    Varre uma lista de portas em um determinado alvo.
    """
    results = {}
    print(f"Scanning ports on {target}...")
    for port in ports:
        status = scan_port(target, port)
        results[port] = status
        print(f"Port {port}: {status}")
    return results

if __name__ == "__main__":
    # Uso: sudo python3 port_scanner.py <target_ip> <port1> [<port2> ...]
    if len(sys.argv) < 3:
        print("Usage: sudo python3 port_scanner.py <target_ip> <port1> [<port2> ...]")
        sys.exit(1)
        
    target_ip = sys.argv[1]
    ports_to_scan = list(map(int, sys.argv[2:]))
    
    # Desativa a verificação de resposta para evitar interferência com outras configurações de scapy
    conf.verb = 0  
    scan_ports(target_ip, ports_to_scan)
