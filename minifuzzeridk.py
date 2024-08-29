import requests
import threading

def fuzzer(url, wordlist, num_threads):
    def fazer_requisicao(pasta):
        resposta = requests.get(f"{url}/{pasta}")
        if resposta.status_code == 200:
            print(f"Diretório encontrado: {url}/{pasta}")

    with open(wordlist, 'r') as arquivo:
        pastas = arquivo.read().splitlines()

    threads = []
    for pasta in pastas:
        thread = threading.Thread(target=fazer_requisicao, args=(pasta,))
        threads.append(thread)
        thread.start()

        if len(threads) >= num_threads:
            for t in threads:
                t.join()
            threads = []

    for t in threads:
        t.join()

if __name__ == "__main__":
    url_alvo = input("Digite a URL alvo: ")
    caminho_wordlist = input("Digite o caminho da wordlist: ")
    numero_threads = int(input("Digite o número de threads: "))
    fuzzer(url_alvo, caminho_wordlist, numero_threads)