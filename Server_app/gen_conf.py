import sqlite3

from IBСCrypto import IBC_SK
from db_structure import QUERY_conf_server, QUERY_conf_user

server_name = 'Мessenger_SERVER'


def create_db(filename):
    con = sqlite3.connect(filename)
    cur = con.cursor()
    if filename == 'db_konf_s.sqlite':
        cur.executescript(QUERY_conf_server)

    else:
        cur.executescript(QUERY_conf_user)
    con.commit()

    if filename == 'db_konf_s.sqlite':
        cur.execute(
            'INSERT INTO SERVER_CONF(server_name, master_secret, server_secret) VALUES (?,?,?)',
            [server_name, str(master_secret), str(server_secret)])
        con.commit()
    else:
        cur.execute(
            'INSERT INTO USER_CONF(server_name, puplic_enc, puplic_sign) VALUES (?,?,?)',
            [server_name, master_public_enc_txt, master_public_sign_txt])
        con.commit()


master_secret = IBC_SK.master_secret_gen()
server_secret = IBC_SK.private_key_gen(master_secret, server_name)
master_public_enc = IBC_SK.setup('encrypt', master_secret)
master_public_sign = IBC_SK.setup('sign', master_secret)
master_public_enc_txt = str(master_public_enc[0].coeffs) + '||' + str(master_public_enc[1].coeffs) + '||' + str(
    master_public_enc[2].coeffs)
master_public_sign_txt = str(master_public_sign[0].n) + '||' + str(master_public_sign[1].n) + '||' + str(
    master_public_sign[2].n)
create_db('db_konf_s.sqlite')
create_db('db_konf_u.sqlite')
