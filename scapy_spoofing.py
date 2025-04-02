#!/usr/bin/env python3
from scapy.all import sniff, ARP
from collections import defaultdict

# Tabela para armazenar mapeamento IP -> conjunto de MACs
arp_table = defaultdict(set)

def arp_monitor_callback(packet):
    # Verifica se o pacote tem a camada ARP
    if packet.haslayer(ARP):
        arp_layer = packet[ARP]
        ip_src = arp_layer.psrc  # IP de origem (quem envia a resposta)
        mac_src = arp_layer.hwsrc  # MAC de origem

        # Se o IP já estiver registrado, mas com um MAC diferente, pode ser um sinal de spoofing
        if arp_table[ip_src] and mac_src not in arp_table[ip_src]:
            print("[ALERTA] Possível ARP spoofing detectado!")
            print(f"  IP {ip_src} foi visto com os MACs: {arp_table[ip_src]} e {mac_src}")
        else:
            print(f"[*] ARP: {ip_src} está em {mac_src}")

        # Atualiza a tabela com o novo mapeamento
        arp_table[ip_src].add(mac_src)

def main():
    print("Iniciando monitoramento de ARP para detectar ARP spoofing...")
    print("Pressione Ctrl+C para encerrar.")
    # Inicia a captura apenas de pacotes ARP
    sniff(filter="arp", prn=arp_monitor_callback, store=False)

if __name__ == "__main__":
    main()
