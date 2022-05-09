# -------------------------------------------------------
# Cifrado RSA
# -------------------------------------------------------
# Francisco Rosal
# -------------------------------------------------------

import random
import base64

def menu():
    print("""
----------------------------
  Sistema de Criptografia RSA
    1. Generar llaves
    2. Cifrar
    3. Decifrar
    4. Salir
----------------------------
    """)

def is_prime(n):
    if n == 2 or n == 3:
        return True
    if n < 2 or n % 2 == 0:
        return False
    if n < 9:
        return True
    if n % 3 == 0:
        return False
    r = int(n ** 0.5) 
    f = 5
    while f <= r: # verifica si n es divisible por el resto de numeros
        # print ('\t',f)
        if n % f == 0:
            return False
        if n % (f + 2) == 0:
            return False
        f += 6
    return True

def random_prime(min, max):
    rand = random.randint(min, max)
    while (not is_prime(rand)):
        rand = random.randint(min, max)
    return rand

def mcd(a, b):
    if a < b:
        a, b = b, a

    res = a % b
    if (res == 0):
        return b
    return mcd(b, res)

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        return False
    else:
        return x % m

def generar_llaves():
    min = 100
    max = 1000
    p = 0
    q = 0

    while (p == q):
        p = random_prime(min, max)
        q = random_prime(min, max)
    # n = modulo
    n = p * q
    print("p = {p}, q = {q}".format(p=p, q=q))
    print("n = {n}".format(n=n))

    # Funcion phi de Euler phi(n)
    phiN = (p - 1) * (q - 1)
    print("phi(n) = {phiN}".format(phiN = phiN))

    d = False
    while (not d):
        e = random.randint(0, phiN-1)
        while (mcd(e, phiN) != 1 or e > 1000000): # 1,000,000 para evitar numeros muy grandes y que tarde mucho
            e = random.randint(0, phiN-1)

        # d es el inverso de e mod phiN
        d = modinv(e, phiN)
    print("e = {e}".format(e=e))
    print("d = {d}".format(d=d))
    # print((e*d) % phiN)
    public_key = str(n) + '.' + str(e)
    private_key = str(n) + '.' + str(d)

    public_key_bytes = public_key.encode('ascii')
    public_key_b64_bytes = base64.b64encode(public_key_bytes)
    public_key_encoded = public_key_b64_bytes.decode('ascii')

    private_key_bytes = private_key.encode('ascii')
    private_key_b64_bytes = base64.b64encode(private_key_bytes)
    private_key_encoded = private_key_b64_bytes.decode('ascii')

    return public_key_encoded, private_key_encoded

def cifrar(message, public_key_encoded):
    m = message

    public_key_base64_bytes = public_key_encoded.encode('ascii')
    public_key_bytes = base64.b64decode(public_key_base64_bytes)
    public_key = public_key_bytes.decode('ascii')

    n, e = public_key.split('.')
    n, e = int(n), int(e)
    cifrado = pow((m % n), (e % n)) % n
    return cifrado

def decifrar(cifrado, private_key_encoded):
    private_key_base64_bytes = private_key_encoded.encode('ascii')
    private_key_bytes = base64.b64decode(private_key_base64_bytes)
    private_key = private_key_bytes.decode('ascii')

    n, d = private_key.split('.')
    n, d = int(n), int(d)
    m = pow((cifrado % n), (d % n)) % n
    return m

# ----------------------------------------------------------------------------------------------------------------------------------------- #

opcion = "0"
while (opcion != "4"):
    menu()
    opcion = input("Seleccione un numero: ")

    if (opcion == "1"):
        # Generar Llaves
        public_k, private_k = generar_llaves()
        print("Llave Publica: ", public_k)
        print("Llave Privada: ", private_k)

    elif (opcion == "2"):
        # Cifrado
        message = input("Ingrese su mensaje:\n\t")
        public_key = input("Ingrese la llave publica:\n\t")
        print(">> Encriptando mensaje...")
        cifrado_total = ""
        for letra_index in range(len(message)):
            message_b = message[letra_index].encode()
            message_number = int.from_bytes(message_b, "big")
            cifrado_letra = cifrar(message_number, public_key)
            cifrado_total += str(cifrado_letra)
            if (letra_index + 2 <= len(message)):
                cifrado_total += "."

        cifrado_bytes = cifrado_total.encode('ascii')
        cifrado_base64_bytes = base64.b64encode(cifrado_bytes)
        print("Mensaje cifrado:\n" +  cifrado_base64_bytes.decode('ascii'))

    elif (opcion == "3"):
        # Decifrado
        cifrado_base64 = input("Ingrese el mensaje cifrado:\n\t")
        cifrado_base64_bytes = cifrado_base64.encode('ascii')
        cifrado_bytes = base64.b64decode(cifrado_base64_bytes)
        cifrado = cifrado_bytes.decode('ascii')

        private_key = input("Ingrese la llave privada:\n\t")
        print(">> Decifrar mensaje...")
        final_decrypt = ""
        cifrado_partes = cifrado.split(".")
        for e in range(len(cifrado_partes)):
            if (e == len(cifrado_partes) // 4):
                print(">> Decifrar mensaje... 25%")
            elif (e == len(cifrado_partes) // 2):
                print(">> Decifrar mensaje... 50%")
            elif (e == (len(cifrado_partes) // 2 + len(cifrado_partes) // 4)):
                print(">> Decifrar mensaje... 75%")
            m = decifrar(int(cifrado_partes[e]), private_key)
            # print(m)
            try:
                final_decrypt += (m.to_bytes(1, "big").decode())
            except:
                print("LLave incorrecta!")
                break
        print("Mensaje original:\n\t" + final_decrypt)

    elif (opcion == "4"):
        print("Gracias por utilizar el programa.")
    else:
        print("Opcion no valida")