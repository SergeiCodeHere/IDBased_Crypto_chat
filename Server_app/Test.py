from IBСCrypto import IBC_SK
import time

if __name__ == '__main__':
    idA = 'Алиса'
    idB = 'Боб'

    print("-----------------test sign and verify---------------")
    master_secret = IBC_SK.master_secret_gen()
    master_public_sign_short = IBC_SK.setup('sign', master_secret)
    master_public_sign = IBC_SK.gen_pub_g('sign', master_public_sign_short)
    secret_a = IBC_SK.private_key_gen(master_secret, idA)

    Da_sign = IBC_SK.private_key_extract('sign', master_public_sign, secret_a)

    message = 'Алиса и Боб'

    start = time.time()
    signature = IBC_SK.sign(master_public_sign, Da_sign, message)
    print("--- %s Sign seconds ---" % (time.time() - start))
    start = time.time()
    assert (IBC_SK.verify(master_public_sign, idA, message, signature))
    print("--- %s Verify seconds ---" % (time.time() - start))

    print("\t\t\t success")

    print("-----------------test key agreement---------------")

    master_public_enc_short = IBC_SK.setup('encrypt', master_secret)
    master_public_enc = IBC_SK.gen_pub_g('encrypt', master_public_enc_short)
    secret_b = IBC_SK.private_key_gen(master_secret, idB)
    Da_enc = IBC_SK.private_key_extract('encrypt', master_public_enc, secret_a)
    Db_enc = IBC_SK.private_key_extract('encrypt', master_public_enc, secret_b)

    start = time.time()
    xa, Ra = IBC_SK.generate_ephemeral(master_public_enc, idB)
    xb, Rb = IBC_SK.generate_ephemeral(master_public_enc, idA)
    ska = IBC_SK.generate_session_key(idA, idB, Ra, Rb, Da_enc, xa, master_public_enc, 'A', 32)
    skb = IBC_SK.generate_session_key(idA, idB, Ra, Rb, Db_enc, xb, master_public_enc, 'B', 32)
    print("--- %s Exchange seconds ---" % (time.time() - start))

    assert (ska == skb)
    print("\t\t\t success")

    print("-----------------test encrypt and decrypt---------------")

    message = "Здесь будет зашифрованное сообщение!!!!"
    start = time.time()
    ct, k = IBC_SK.kem_dem_enc(master_public_enc, idA, message, 32)
    print("--- %s Encr seconds ---" % (time.time() - start))

    start = time.time()
    pt = IBC_SK.kem_dem_dec(idA, Da_enc, ct, 32)
    print("--- %s Decr seconds ---" % (time.time() - start))

    assert (message == pt)
    print("\t\t\t success")
