#!/usr/bin/env python3
import nmap
import asyncio

def sync_scan(host, port_range):
    """
    Realiza uma varredura síncrona utilizando nmap.PortScanner.
    Parâmetros:
      - host: IP ou hostname a ser escaneado.
      - port_range: intervalo de portas (ex: '22-80').
    Retorna um dicionário com o(s) protocolo(s) e o estado das portas encontradas.
    """
    nm = nmap.PortScanner()
    print(f"[SYNC] Escaneando {host} nas portas {port_range}...")
    nm.scan(host, port_range)
    
    scan_result = {}
    if host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            ports = sorted(nm[host][proto].keys())
            scan_result[proto] = {port: nm[host][proto][port]['state'] for port in ports}
    else:
        scan_result = "Host não encontrado ou sem resposta"
    
    return scan_result

async def async_scan(host, port_range, loop):
    """
    Realiza uma varredura utilizando a função síncrona, mas executada em um executor.
    Essa abordagem permite realizar varreduras concorrentes de diferentes hosts.
    """
    return await loop.run_in_executor(None, sync_scan, host, port_range)

async def run_async_scans(hosts, port_range):
    """
    Agrega varreduras assíncronas para uma lista de hosts.
    Retorna um dicionário mapeando cada host ao resultado da varredura.
    """
    loop = asyncio.get_running_loop()
    tasks = [async_scan(host, port_range, loop) for host in hosts]
    results = await asyncio.gather(*tasks)
    return dict(zip(hosts, results))

def main():
    # Varredura Síncrona (Exemplo)
    host_sync = '127.0.0.1'
    port_range_sync = '22-443'
    print("=== Varredura Síncrona ===")
    sync_result = sync_scan(host_sync, port_range_sync)
    print(f"Resultados para {host_sync}:")
    print(sync_result)
    
    # Varredura Assíncrona (Concorrente)
    hosts_async = ['127.0.0.1', '192.168.1.1']  # Ajuste conforme seu ambiente
    port_range_async = '22-80'
    print("\n=== Varredura Assíncrona ===")
    async_results = asyncio.run(run_async_scans(hosts_async, port_range_async))
    for host, result in async_results.items():
        print(f"Resultados para {host}:")
        print(result)

if __name__ == '__main__':
    main()
