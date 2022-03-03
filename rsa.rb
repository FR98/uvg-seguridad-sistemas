# -------------------------------------------------------
# Cifrado RSA
# -------------------------------------------------------
# Francisco Rosal
# -------------------------------------------------------

require "base64"

MIN = 100
MAX = 1000

def menu()
    puts("
----------------------------
  Sistema de Criptografia RSA
    1. Generar llaves
    2. Cifrar
    3. Decifrar
    4. Salir
----------------------------
    ")
end

def is_prime(n)
    return true if n == 2 or n == 3
    return false if n < 2 or n % 2 == 0
    return true if n < 9
    return false if n % 3 == 0

    r = n ** 0.5
    r = r.to_i
    f = 5

    # verifica si n es divisible por el resto de numeros
    while f <= r do
        return false if n % f == 0
        return false if n % (f + 2) == 0
        f += 6
    end

    return true
end

def random_prime(min, max)
    while true do
        rand_num = rand(min..max)
        break if is_prime(rand_num)
    end

    rand_num
end

def mcd(a, b)
    a, b = b, a if a < b

    res = a % b

    return b if res == 0

    mcd(b, res)
end

def egcd(a, b)
    return b, 0, 1 if a == 0

    g, y, x = egcd(b % a, a)

    return g, x - (b / a) * y, y
end

def modinv(a, m)
    g, x, y = egcd(a, m)

    return false if g != 1
    return x % m
end

def generar_llaves()
    min = MIN
    max = MAX
    p_num = 0
    q_num = 0

    while p_num == q_num do
        p_num = random_prime(min, max)
        q_num = random_prime(min, max)
    end

    # n = modulo
    n = p_num * q_num
    puts("p = #{p_num}, q = #{q_num}")
    puts("n = #{n}")

    # Funcion phi de Euler phi(n)
    phiN = (p_num - 1) * (q_num - 1)
    puts("phi(n) = #{phiN}")

    d = false
    while true do
        break if d

        e = rand(0..phiN-1)

        # 1,000,000 para evitar numeros muy grandes y que tarde mucho
        while mcd(e, phiN) != 1 || e > 1000000 do
            e = rand(0..phiN-1)
        end

        # d es el inverso de e mod phiN
        d = modinv(e, phiN)
    end

    puts("e = #{e}")
    puts("d = #{d}")
    # puts((e*d) % phiN)

    puts("Llave Publica: #{n},#{e}")
    puts("Llave Privada: #{n},#{d}")

    # public_key = n.to_s + '.' + e.to_s
    # private_key = n.to_s + '.' + d.to_s

    # public_key_bytes = public_key.encode('ascii')
    # public_key_b64_bytes = Base64.encode64(public_key_bytes)
    # public_key_encoded = public_key_b64_bytes

    # private_key_bytes = private_key.encode('ascii')
    # private_key_b64_bytes = Base64.encode64(private_key_bytes)
    # private_key_encoded = private_key_b64_bytes

    # return public_key_encoded, private_key_encoded
end

def cifrar(m_num, public_key_encoded)
    public_key_base64_bytes = public_key_encoded.encode('ascii')
    public_key_bytes = Base64.decode64(public_key_base64_bytes)
    public_key = public_key_bytes

    n, e = public_key.split('.')
    n, e = n.to_i, e.to_i
    temp = (m_num.to_i % n) ** (e % n)
    cifrado = temp % n

    cifrado
end

def decifrar(cifrado, private_key_encoded)
    private_key_base64_bytes = private_key_encoded.encode('ascii')
    private_key_bytes = Base64.decode64(private_key_base64_bytes)
    private_key = private_key_bytes

    n, d = private_key.split('.')
    n, d = n.to_i, d.to_i
    temp = (cifrado % n) ** (d % n)
    m = temp % n

    m
end

# ----------------------------------------------------------------------------------------------------------------------------------------- #

opcion = "0"
while opcion != "4" do
    menu()
    puts "Seleccione una opcion: "
    opcion = gets.chomp

    if opcion == "1"
        # Generar Llaves
        generar_llaves()
    elsif opcion == "2"
        # Cifrado
        puts("Ingrese el mensaje a cifrar:\n\t")
        message = gets.chomp
        puts("Ingrese la llave publica:\n\t")
        public_key_nums = gets.chomp

        n, e = public_key_nums.split(',')
        public_key_nums = n.to_s + '.' + e.to_s

        public_key_bytes = public_key_nums.encode('ascii')
        public_key_b64_bytes = Base64.encode64(public_key_bytes)
        public_key_encoded = public_key_b64_bytes
        public_key = public_key_encoded

        puts(">> Encriptando mensaje...")
        cifrado_total = ""

        for letra_index in (0...message.length)
            message_b = message[letra_index].encode()
            message_number = message_b.ord
            cifrado_letra = cifrar(message_number, public_key)
            cifrado_total += cifrado_letra.to_s

            if (letra_index + 2 <= message.length)
                cifrado_total += "."
            end
        end

        cifrado_bytes = cifrado_total.encode('ascii')
        cifrado_base64_bytes = Base64.encode64(cifrado_bytes)
        puts("Mensaje cifrado:\n" +  cifrado_base64_bytes.encode('ascii'))

    elsif opcion == "3"
        # Decifrado
        puts("Ingrese el mensaje cifrado:\n\t")
        cifrado_base64 = gets.chomp
        cifrado_base64_bytes = cifrado_base64.encode('ascii')
        cifrado_bytes = Base64.decode64(cifrado_base64_bytes)
        cifrado = cifrado_bytes

        puts("Ingrese la llave privada:\n\t")
        private_key_nums = gets.chomp

        n, d = private_key_nums.split(',')
        private_key_nums = n.to_s + '.' + d.to_s

        private_key_nums = n.to_s + '.' + d.to_s

        private_key_bytes = private_key_nums.encode('ascii')
        private_key_b64_bytes = Base64.encode64(private_key_bytes)
        private_key_encoded = private_key_b64_bytes
        private_key = private_key_encoded

        puts(">> Decifrar mensaje...")
        final_decrypt = ""
        cifrado_partes = cifrado.split(".")

        for e in (0...cifrado_partes.length)
            if e == cifrado_partes.length / 4
                puts(">> Decifrar mensaje... 25%")
            elsif e == cifrado_partes.length / 2
                puts(">> Decifrar mensaje... 50%")
            elsif e == (cifrado_partes.length / 2 + cifrado_partes.length / 4)
                puts(">> Decifrar mensaje... 75%")
            end

            m = decifrar(cifrado_partes[e].to_i, private_key)

            begin
                final_decrypt += m.chr
            rescue => exception
                puts("LLave incorrecta!")
                break
            end
        end

        puts("Mensaje original:\n\t" + final_decrypt)

    elsif opcion == "4"
        puts("Gracias por utilizar el programa.")
    else
        puts("Opcion no valida")
    end

end
