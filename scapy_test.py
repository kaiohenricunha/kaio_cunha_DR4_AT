#!/usr/bin/env python3
from scapy.all import sniff, IP, send

def packet_callback(packet):
    # Exibe informações do pacote capturado
    print("\n=== Pacote Capturado ===")
    packet.show()

    # Se o pacote tiver camada IP, vamos modificá-lo
    if IP in packet:
        original_ttl = packet[IP].ttl
        # Exemplo de modificação: definir o TTL para 200
        packet[IP].ttl = 200
        print(f"Modificando TTL de {original_ttl} para {packet[IP].ttl}")

        # Remove o checksum para que o scapy o recalcule automaticamente
        del packet[IP].chksum

        # Injeção: reenvia o pacote modificado
        print("Injetando pacote modificado...")
        send(packet)
        print("Pacote injetado com sucesso!")
    else:
        print("Pacote sem camada IP. Nenhuma modificação aplicada.")

def main():
    print("Iniciando captura de pacotes com scapy...")
    # Captura 5 pacotes com filtro "ip" e chama o callback para cada um
    sniff(filter="ip", prn=packet_callback, count=5)
    print("Captura encerrada.")

if __name__ == '__main__':
    main()
