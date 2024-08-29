import socket

ip = "192.10.30.8"

for porta in range(1,65536):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = s.connect_ex ((ip, porta))
    if result == 0:
        print("{} open/aberta".format(porta))
    else:
        pass

# Port scanner simples,
# Modificar IP conforme o alvo.
