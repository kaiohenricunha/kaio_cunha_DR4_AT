#!/usr/bin/env python3
from scapy.all import sniff
import datetime

def packet_handler(packet):
    """
    Callback chamada para cada pacote capturado.
    Exibe um timestamp e um resumo do pacote.
    """
    # Obtém o timestamp atual
    time_stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Exibe informações básicas do pacote
    print(f"[{time_stamp}] {packet.summary()}")

def main():
    print("Iniciando a detecção de pacotes na rede. Pressione Ctrl+C para encerrar.")
    # Inicia a captura: captura todos os pacotes sem armazená-los (store=False)
    sniff(prn=packet_handler, store=False)

if __name__ == "__main__":
    main()
