from math import ceil, floor, log
from pygost.gost34112012 import GOST34112012
from pygost.gost3412 import GOST3412Kuznechik
from pygost.gost3413 import ecb_decrypt, ecb_encrypt
from random import SystemRandom
from Server_app.IBСCrypto.optimized_math import optimized_field_elements as fq, optimized_pairing as ate, optimized_curve as ec

FAILURE = False
SUCCESS = True


# Генерация ключа заданной длины на основе хэш функции
def KDF(z, klen):
    klen = int(klen)
    ct = 0x00000001
    rcnt = ceil(klen / 32)
    ha = ""
    for i in range(rcnt):
        ha = ha + GOST34112012(z + bytes(ct), 32).hexdigest()
        ct += 1
    return ha[0: klen * 2]


# Определение битовой длины числа
def bitlen(n):
    return floor(log(n, 2) + 1)


# Преобразование точки кривой к 16-ной строке
def fe2sp(fe):
    fe_str = ''.join(['%x' % c for c in fe.coeffs])
    # if (len(fe_str) % 2) == 1:
    # fe_str = '0' + fe_str
    return fe_str


# Преобразование вектора из точек кривой к 16-ной строке
def ec2sp(P):
    ec_str = ''.join([fe2sp(fe) for fe in P])
    return ec_str


# Преобразование значения хэшфункции к числу от 1 до n-1
def h2rf(i, z, n):
    l = 8 * ceil((5 * bitlen(n)) / 32)
    ha = KDF(z, l)
    h = int(ha, 16)
    return (h % (n - 1)) + 1


# Генерация главного закрытого ключа
def master_secret_gen():
    rand_gen = SystemRandom()
    s = rand_gen.randrange(ec.curve_order)
    return s


# Генерация расширенного открытого ключа по заданному открытому
def gen_pub_g(scheme, master_public_key):
    P1 = ec.G2
    P2 = ec.G1

    if scheme == 'sign':
        g = ate.pairing(P1, master_public_key)
    elif scheme == 'encrypt':
        g = ate.pairing(master_public_key, P2)
    else:
        raise Exception('Invalid scheme')
    master_public_key = (P1, P2, master_public_key, g)
    return master_public_key


# Генерация параметров системы
def setup(scheme, master_secret):
    P1 = ec.G2
    P2 = ec.G1

    s = master_secret

    if scheme == 'sign':
        Ppub = ec.multiply(P2, s)
    elif scheme == 'encrypt':
        Ppub = ec.multiply(P1, s)
    else:
        raise Exception('Invalid scheme')

    return Ppub


# Генерация закрытого ключа
def private_key_gen(master_secret, identity):
    user_id = GOST34112012(identity.encode('utf-8'), 32).hexdigest()
    m = h2rf(1, (user_id).encode('utf-8'), ec.curve_order)
    m = master_secret + m
    if (m % ec.curve_order) == 0:
        return FAILURE
    m = master_secret * fq.prime_field_inv(m, ec.curve_order)

    return m


# Преобразование закрытого ключа в точку
def private_key_extract(scheme, master_public, m):
    P1 = master_public[0]
    P2 = master_public[1]

    if scheme == 'sign':
        Da = ec.multiply(P1, m)
    elif scheme == 'encrypt':
        Da = ec.multiply(P2, m)
    else:
        raise Exception('Invalid scheme')

    return Da


# Генерация открытого ключа
def public_key_extract(scheme, master_public, identity):
    P1, P2, Ppub, g = master_public

    user_id = GOST34112012(identity.encode('utf-8'), 32).hexdigest()
    h1 = h2rf(1, user_id.encode('utf-8'), ec.curve_order)

    if scheme == 'sign':
        Q = ec.multiply(P2, h1)
    elif scheme == 'encrypt':
        Q = ec.multiply(P1, h1)
    else:
        raise Exception('Invalid scheme')

    Q = ec.add(Q, Ppub)

    return Q


# Генерация электронной подписи
def sign(master_public, Da, msg):
    g = master_public[3]

    rand_gen = SystemRandom()
    x = rand_gen.randrange(ec.curve_order)
    w = g ** x

    msg_hash = GOST34112012(msg.encode('utf-8'), 32).hexdigest()
    z = (msg_hash + fe2sp(w)).encode('utf-8')
    h = h2rf(2, z, ec.curve_order)
    l = (x - h) % ec.curve_order

    S = ec.multiply(Da, l)
    return h, S


# Проверка электронной подписи
def verify(master_public, identity, msg, signature):
    (h, S) = signature

    if (h < 0) | (h >= ec.curve_order):
        return FAILURE
    if ec.is_on_curve(S, ec.b2) == False:
        return FAILURE

    Q = public_key_extract('sign', master_public, identity)

    g = master_public[3]
    u = ate.pairing(S, Q)
    t = g ** h
    wprime = u * t

    msg_hash = GOST34112012(msg.encode('utf-8'), 32).hexdigest()
    z = (msg_hash + fe2sp(wprime)).encode('utf-8')
    h2 = h2rf(2, z, ec.curve_order)

    if h != h2:
        return FAILURE
    return SUCCESS


# Вспомогательная функция для ключевого обмена
def generate_ephemeral(master_public, identity):
    Q = public_key_extract('encrypt', master_public, identity)

    rand_gen = SystemRandom()
    x = rand_gen.randrange(ec.curve_order)
    R = ec.multiply(Q, x)

    return x, R


# Генерация сессионного ключа
def generate_session_key(idA, idB, Ra, Rb, D, x, master_public, entity, l):
    P1, P2, Ppub, g = master_public

    if entity == 'A':
        R = Rb
    elif entity == 'B':
        R = Ra
    else:
        raise Exception('Invalid entity')

    g1 = ate.pairing(R, D)
    g2 = g ** x
    g3 = g1 ** x

    if (entity == 'B'):
        (g1, g2) = (g2, g1)

    uidA = GOST34112012(idA.encode('utf-8'), 32).hexdigest()
    uidB = GOST34112012(idB.encode('utf-8'), 32).hexdigest()

    kdf_input = uidA + uidB
    kdf_input += ec2sp(Ra) + ec2sp(Rb)
    kdf_input += fe2sp(g1) + fe2sp(g2) + fe2sp(g3)

    sk = KDF(kdf_input.encode('utf-8'), l / 2)

    return sk


# Инкапсуляция ключа шифрования
def kem_encap(master_public, identity, l):
    P1, P2, Ppub, g = master_public

    Q = public_key_extract('encrypt', master_public, identity)

    rand_gen = SystemRandom()
    x = rand_gen.randrange(ec.curve_order)

    C1 = ec.multiply(Q, x)
    t = g ** x

    uid = GOST34112012(identity.encode('utf-8'), 32).hexdigest()
    kdf_input = ec2sp(C1) + fe2sp(t) + uid
    k = KDF(kdf_input.encode('utf-8'), l / 2)

    return k, C1


# Декапсуляция ключа шифрования
def kem_decap(identity, D, C1, l):
    if ec.is_on_curve(C1, ec.b2) == False:
        return FAILURE

    t = ate.pairing(C1, D)

    uid = GOST34112012(identity.encode('utf-8'), 32).hexdigest()
    kdf_input = ec2sp(C1) + fe2sp(t) + uid
    k = KDF(kdf_input.encode('utf-8'), l / 2)

    return k


# Алгоритм шифрования
def kem_dem_enc(master_public, identity, message, v):
    k, C1 = kem_encap(master_public, identity, v * 2)
    k1 = k[:v]
    k2 = k[v:]

    C2 = sym_encr(k1, message)

    hash_input = C2.decode('mbcs') + k2
    C3 = GOST34112012(hash_input.encode('utf-8'), 32).hexdigest()

    return (C1, C2, C3), k1


# Алгоритм расшифрования
def kem_dem_dec(identity, D, ct, v):
    C1, C2, C3 = ct

    k = kem_decap(identity, D, C1, v * 2)
    k1 = k[:v]
    k2 = k[v:]

    hash_input = C2.decode('mbcs') + k2
    C3prime = GOST34112012(hash_input.encode('utf-8'), 32).hexdigest()

    if C3 != C3prime:
        return FAILURE

    message = sym_decr(k1, C2).decode('mbcs')

    return message


# Функция добивки текста до размера блока
def to_block_size(msg, size):
    msg = bytearray(msg)
    musor = size - len(msg) % size
    for i in range(musor):
        if i == musor - 1:
            msg.append(musor)
        else:
            msg.append(0)
    return bytes(msg)


# Функция отсечения добивки
def to_open_text(msg):
    msg = bytearray(msg)
    musor = msg[-1]
    flag = 1
    for i in range(2, musor + 1):
        if msg[-i] != 0:
            flag = 0
            break
    if flag:
        msg = msg[:-musor]
    return bytes(msg)


# Симметричное шифрование - Кузнечик
def sym_encr(key, msg):
    ciph = GOST3412Kuznechik(key.encode('utf-8'))
    message = to_block_size(msg.encode('mbcs'), 16)
    return ecb_encrypt(ciph.encrypt, 16, message)


# Симметричное расшифрование - Кузнечик
def sym_decr(key, msg):
    ciph = GOST3412Kuznechik(key.encode('utf-8'))
    return to_open_text(ecb_decrypt(ciph.decrypt, 16, msg))
