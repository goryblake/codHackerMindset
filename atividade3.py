import requests

def verificar_subdominios(url):
    with open('SecLists/Discovery/DNS/subdomains-top1million-5000.txt', 'r') as file:
        subdominios = [line.strip() for line in file.readlines()[:20]]
    
    for subdominio in subdominios:
        sub_url = f"http://{subdominio}.{url}"
        try:
            resposta = requests.get(sub_url)
            print(f"{sub_url} - Status Code: {resposta.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"{sub_url} - Erro: {e}")


# verificar_subdominios('exemplo.com')