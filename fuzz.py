#!/usr/bin/env python3
import requests
import random
import string

def get_baseline(url):
    """
    Gera um endpoint aleatório para obter a resposta padrão (404) do servidor.
    Retorna o status code e o tamanho do conteúdo (em bytes) como baseline.
    """
    random_endpoint = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
    full_url = f"{url}/{random_endpoint}"
    try:
        r = requests.get(full_url, timeout=5)
        return r.status_code, len(r.content)
    except Exception as e:
        print(f"[!] Erro ao obter baseline de {full_url}: {e}")
        return None, None

def fuzz_endpoints(base_url, endpoints):
    """
    Para cada endpoint na wordlist, envia uma requisição GET e compara a resposta com o baseline.
    Se o status for 200 e o tamanho do conteúdo for significativamente diferente do baseline,
    considera-o potencialmente vulnerável.
    """
    baseline_code, baseline_len = get_baseline(base_url)
    if baseline_code is None:
        print("[!] Não foi possível obter a resposta baseline. Abortando fuzzing.")
        return []

    print(f"\nBaseline: Status Code = {baseline_code}, Content Length = {baseline_len}\n")
    vulnerables = []

    for endpoint in endpoints:
        full_url = f"{base_url}/{endpoint}"
        try:
            r = requests.get(full_url, timeout=5)
            content_len = len(r.content)
            # Se a resposta for 200 e o tamanho for diferente do baseline (diferença arbitrária de 50 bytes)
            if r.status_code == 200 and abs(content_len - baseline_len) > 50:
                print(f"[+] {full_url} => Status: {r.status_code}, Length: {content_len}")
                vulnerables.append(full_url)
            else:
                print(f"[-] {full_url} => Status: {r.status_code}, Length: {content_len}")
        except Exception as e:
            print(f"[!] Erro ao acessar {full_url}: {e}")
    return vulnerables

def main():
    base_url = input("Digite a URL base do alvo (ex: http://example.com): ").strip().rstrip("/")
    
    # Wordlist simples de endpoints a testar
    endpoints = [
        "admin", "login", "dashboard", "config", "wp-admin", "phpmyadmin",
        "server-status", "backup", "test", "old", "hidden"
    ]
    
    print(f"\nIniciando fuzzing em {base_url}...\n")
    vuln_endpoints = fuzz_endpoints(base_url, endpoints)
    
    print("\nFuzzing concluído. Endpoints potencialmente vulneráveis:")
    for ep in vuln_endpoints:
        print(ep)

if __name__ == "__main__":
    main()
