import pcapy
import sys
import socket
import struct
import time

def packet_handler(header, data):
    # Função de callback para processar pacotes capturados.
    print("Pacote capturado: {} bytes".format(len(data)))
    # Exibe os primeiros 60 bytes do pacote para visualização.
    print("Dados (hex):", data[:60].hex())
    print("-" * 50)

def main():
    # Lista os dispositivos de rede disponíveis
    devices = pcapy.findalldevs()
    if not devices:
        print("Nenhum dispositivo encontrado para captura!")
        sys.exit(1)
        
    print("Dispositivos disponíveis:")
    for dev in devices:
        print(" -", dev)
    
    # Seleciona o primeiro dispositivo encontrado
    dev = devices[0]
    print("\nUtilizando o dispositivo:", dev)
    
    # Abre o dispositivo para captura:
    # - 65536: tamanho máximo do snapshot (em bytes)
    # - 1: modo promíscuo (True)
    # - 100: timeout em milissegundos
    cap = pcapy.open_live(dev, 65536, 1, 100)
    
    # Define um filtro para capturar apenas pacotes IP (opcional)
    cap.setfilter("ip")
    
    print("\nIniciando a captura de 5 pacotes...")
    # Captura 5 pacotes e processa cada um com a função 'packet_handler'
    cap.loop(5, packet_handler)
    
    # -- INJEÇÃO DE PACOTES --
    # Para injetar um pacote, um frame Ethernet simples.
    #
    # Formato do frame Ethernet:
    #   - 6 bytes: Endereço MAC de destino
    #   - 6 bytes: Endereço MAC de origem
    #   - 2 bytes: Tipo/EtherType
    #   - Dados: Payload (aqui usaremos uma mensagem simples)
    
    # Endereço MAC de destino: broadcast (envia para todos)
    dest_mac = b'\xff\xff\xff\xff\xff\xff'
    # Endereço MAC de origem: exemplo (deve ser válido na sua interface ou apenas para teste)
    src_mac = b'\x00\x0c\x29\xab\xcd\xef'
    # EtherType: 0x0800 indica um pacote IP; usaremos esse valor apenas como exemplo.
    eth_type = b'\x08\x00'
    # Payload: mensagem de teste (pode ser qualquer dado binário)
    payload = 'Hello, pcapy-ng! This is an injected packet.'.encode('ascii')
    
    # Monta o frame Ethernet completo
    ethernet_frame = dest_mac + src_mac + eth_type + payload
    
    print("\nInjetando pacote personalizado na rede...")
    # Utiliza o método sendpacket para enviar o frame Ethernet
    cap.sendpacket(ethernet_frame)
    print("Pacote injetado com sucesso!")
    
if __name__ == '__main__':
    main()
