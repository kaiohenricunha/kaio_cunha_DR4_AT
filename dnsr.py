#!/usr/bin/env python3
import dns.resolver
import dns.zone
import dns.query

# Tentativa de importar DNSRecontools (caso esteja instalado)
try:
    from DNSRecontools import DNSRecon  # Exemplo: a classe DNSRecon é fictícia e serve para ilustrar
except ImportError:
    DNSRecon = None

def query_dns_records(domain):
    """
    Consulta registros A, NS, MX e TXT para o domínio usando dnspython.
    Retorna um dicionário com os resultados.
    """
    records = {}
    for rtype in ['A', 'NS', 'MX', 'TXT']:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [r.to_text() for r in answers]
        except Exception as e:
            records[rtype] = f"Erro: {e}"
    return records

def zone_transfer(domain, nameserver):
    """
    Tenta realizar uma transferência de zona (AXFR) do domínio utilizando o servidor de nomes especificado.
    Retorna um dicionário com os registros ou uma mensagem de erro.
    """
    try:
        zone = dns.zone.from_xfr(dns.query.xfr(nameserver, domain, timeout=5))
        zonerecords = {}
        for name, node in zone.nodes.items():
            # Cada nó pode ter vários rdatasets (ex: A, TXT, etc.)
            zonerecords[str(name)] = []
            for rdataset in node.rdatasets:
                for rdata in rdataset:
                    zonerecords[str(name)].append(rdata.to_text())
        return zonerecords
    except Exception as e:
        return f"AXFR não permitida: {e}"

def dns_recon(domain):
    """
    Se o DNSRecontools estiver disponível, executa uma varredura avançada no domínio.
    Essa função é opcional e depende do pacote DNSRecontools.
    """
    if DNSRecon is None:
        return "DNSRecontools não instalado ou não disponível."
    try:
        recon = DNSRecon(domain)
        results = recon.scan_domain()  # Método hipotético que retorna dados de reconhecimento
        return results
    except Exception as e:
        return f"Erro ao executar DNSRecontools: {e}"

def main():
    domain = input("Digite o domínio a ser analisado (ex: example.com): ").strip()
    
    print("\n--- Consulta de Registros DNS ---")
    records = query_dns_records(domain)
    for rtype, result in records.items():
        print(f"{rtype} records: {result}")
    
    print("\n--- Tentativa de Transferência de Zona (AXFR) ---")
    ns_records = records.get('NS')
    if isinstance(ns_records, list):
        for ns in ns_records:
            print(f"\nTransferência de zona usando nameserver {ns}:")
            axfr_result = zone_transfer(domain, ns)
            print(axfr_result)
    else:
        print("Nenhum registro NS válido encontrado para tentar AXFR.")
    
    print("\n--- Reconhecimento Avançado com DNSRecontools ---")
    recon_results = dns_recon(domain)
    print("Resultados do DNSRecontools:")
    print(recon_results)

if __name__ == "__main__":
    main()
