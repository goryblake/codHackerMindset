#Crie uma função em python que leia o arquivo SecLists/Passwords/darkweb2017-top100.txt
# e exiba na tela as 10 primeiras senhas do arquivo.

def ler_arquivo():
    with open("darkweb2017-top100.txt", "r") as arq:
        for i in range (0,10):
            conteudo = arq.readline()
            print(conteudo)

ler_arquivo()