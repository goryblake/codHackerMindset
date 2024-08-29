 
def leitura_arquivo ():
    import ipdb;ipdb.set_trace()
    with open ("wordlist.txt", "r") as arquivo:
        for i in range (0,10):
            print(f"senha : {arquivo.readline()}")
 
leitura_arquivo()

# Código simples para debug.
# Exportar o código apenas aonde pretende debugar, seja no inicio, meio, fim.
