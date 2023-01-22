import logging
import json
import os
from random import choices
from Server_app.IBСCrypto import IBC_SK

from pygost.gost34112012 import GOST34112012

# Хеширование паролей в базе данных
get_hash = lambda x: GOST34112012(x.encode('utf8')).hexdigest()
password_salt = 'IdentityBasedCrypto'


# Определяем класс пользователь
class User:
    def __init__(self, websocket, database, pkg, myapp, clients):
        self.ws = websocket
        self.db = database
        self.myapp = myapp
        self.pkg = pkg
        self.client_chat = clients
        self.id = None
        self.name = None
        self.chats = None
        self.url_txt = None
        self.session_key = None
        self.serv_xs = None
        self.serv_rs = None

    async def listen_messages(self):
        await self.ws.send(json.dumps({'method': 'init', 'message': 'Need client auth!'}))

        async for message in self.ws:
            if message.find('method') != -1:
                message = json.loads(message)
                await self.router(message)
            else:
                message_decr = IBC_SK.sym_decr(self.session_key, message.encode('mbcs'))
                message_decr = json.loads(message_decr)
                await self.router(message_decr)

        # При отключении клиента отмечаем его статус как оффлайн

        self.db.cur.execute('UPDATE users SET status_online = ? WHERE id = ?', ['No', self.id])
        self.myapp.in_table()
        self.client_chat.remove_client(self)

    async def router(self, message):
        logging.info(f'Новое сообщение: {message["method"]}')

        if message['method'] == 'auth':
            await self.handler_auth(message['data'])
        elif message['method'] == 'userChats':
            await self.handler_userChats()
        elif message['method'] == 'init':
            await self.handler_sendServerAuth()
        elif message['method'] == 'init_key':
            await self.handler_sendServerKey(message['data'])
        elif message['method'] == 'roundkey':
            await self.handler_keyExchange(message['data'])
        elif message['method'] == 'roundkey_user':
            await self.handler_keyExchangeUser(message['data'])
        elif message['method'] == 'start_secure':
            await self.handler_startSecure(message['data'])
        elif message['method'] == 'joinChat':
            await self.handler_joinChat(message['data'])
        elif message['method'] == 'createChat':
            await self.handler_createChat(message['data'])
        elif message['method'] == 'messages':
            await self.handler_getMessages(message['chat_id'])
        elif message['method'] == 'send':
            await self.handler_send(message['data'])

    async def handler_userChats(self):
        # Получение всех чатов пользователя и отправка
        chats = self.db.cur.execute('''
            SELECT uc.chat_id, c.name, uc.entry_date FROM user_chats uc
            INNER JOIN chats c ON uc.chat_id = c.id
            WHERE uc.user_id = ?
        ''', [self.id]).fetchall()
        self.chats = [{'id': i[0], 'name': i[1], 'entry_date': i[2]} for i in chats]

        # Добавление пользователя в объект онлайна по каждому чату
        # Это используется в дальнейшем, чтобы рассылать новые сообщения
        self.client_chat.add_client(self)

        await self.ws.send(json.dumps({'method': 'userChats', 'data': self.chats}))

    async def handler_auth(self, data):

        data = IBC_SK.sym_decr(self.session_key, data.encode('mbcs')).decode('mbcs').split('||')

        username = data[1]
        password = get_hash(data[2] + password_salt)
        user_url = self.ws.remote_address[0] + ' : ' + str(self.ws.remote_address[1])
        user = self.db.cur.execute('SELECT * FROM users WHERE name = ?', [username]).fetchall()

        if user[0][2] == '0' and data[0] == 'True':
            # Добавляем пароль пользователя
            self.db.cur.execute(
                'UPDATE users SET password = ? WHERE name = ?',
                [password, self.name])
            self.db.con.commit()
        elif user[0][2] != '0' and data[0] == 'True':
            # логин уже занят
            await self.send_crypto(json.dumps({'method': 'auth', 'success': ['Registration', 'False']}))
            return

        elif not user:
            # Такого пользователя нет в системе
            await self.send_crypto(json.dumps({'method': 'auth', 'success': ['Auth', 'False']}))
            return

        elif user and password != user[0][2]:
            # Неверный пароль
            await self.send_crypto(json.dumps({'method': 'auth', 'success': ['Auth', 'False']}))
            return

        user = self.db.cur.execute('SELECT id, name, url_txt FROM users WHERE name = ?', [username]).fetchall()[0]

        self.id = user[0]
        self.name = user[1]
        self.url_txt = user[2]

        self.db.cur.execute('UPDATE users SET status_online = ? WHERE id = ?', ['Yes', self.id])
        self.myapp.in_table()

        await self.send_crypto(json.dumps({
            'method': 'auth',
            'success': True,
            'data': {'id': self.id, 'name': self.name}
        }))
        # Сразу обновляем список пользователей
        self.myapp.in_table()

        # Логируем
        self.myapp.logs_txt("Подключение пользователя с идентификатором " + self.name)
        self.myapp.logs_txt("Установление защищенного канала связи с пользователем " + self.name)
        self.myapp.logs_txt("Генерация и отправка закрытого ключа пользователя " + self.name)

        # И отправляем список чатов пользователя
        await self.handler_userChats()

    async def send_system_message(self, chat_id, message):
        # Метод для быстрой отправки сообщения от имени системы
        await self.handler_send({'msg': message, 'chat_id': chat_id}, user_id=1, username='System')

    async def handler_createChat(self, data):
        if not data['name']:
            await self.send_crypto(json.dumps({'method': 'createChat', 'success': False,
                                           'text': 'Пользователь отказался создавать чат!'}))
            return

        # ОТправляем запрос нужному пользователю

        user = self.db.cur.execute('SELECT * FROM users WHERE name = ?', [data['name']]).fetchall()
        chat = self.db.cur.execute('SELECT id FROM chats WHERE name = ? or name  = ?',
                                   [self.name + ' || ' + data['name'], data['name'] + ' || ' + self.name]).fetchall()
        if user:
            if user[0][1] != self.name:
                if not chat:
                    if user[0][1] in self.client_chat.clients_online:
                        await self.client_chat.sync_invite(user[0][1], self.name)
                    else:
                        await self.send_crypto(json.dumps({'method': 'createChat', 'success': False,
                                                       'text': 'Данный пользователь сейчас недоступен'}))
                else:
                    await self.send_crypto(json.dumps({'method': 'createChat', 'success': False,
                                                   'text': 'Чат уже существует'}))
            else:
                await self.send_crypto(json.dumps({'method': 'createChat', 'success': False,
                                               'text': 'Нельзя создавать чат с собой'}))
        else:
            await self.send_crypto(json.dumps({'method': 'createChat', 'success': False,
                                           'text': 'Указанного имени нет в базе'}))

    async def handler_joinChat(self, data):
        # Пришел ответ от пользователя
        user = self.client_chat.clients_online[data['name']]

        await self.send_crypto(json.dumps({'method': 'AnswerChat', 'success': True}))

        if data['Answer'] == 'No':
            await self.send_crypto(json.dumps({'method': 'createChat', 'success': False,
                                           'text': 'Пользователь отказался создавать чат'}))
            return

        # Создание чата
        self.db.cur.execute(
            'INSERT INTO chats(name) VALUES (?)',
            [user.name + ' || ' + self.name]
        )
        chat_id = self.db.cur.lastrowid

        # Добавление пользователей в список участников
        self.db.cur.execute(
            'INSERT INTO user_chats(user_id, chat_id) VALUES (?, ?)',
            [self.id, chat_id]
        )
        self.db.con.commit()

        self.db.cur.execute(
            'INSERT INTO user_chats(user_id, chat_id) VALUES (?, ?)',
            [user.id, chat_id]
        )
        self.db.con.commit()

        await self.handler_userChats()
        await user.handler_userChats()

        await self.send_system_message(chat_id,
                                       f'Чат пользователя {user.name} с пользователем {self.name} успешно создан!')

        await self.send_crypto(json.dumps({'method': 'createChat', 'success': True}))
        await self.send_crypto(json.dumps({'method': 'createChat', 'success': True}))
        await self.handler_getMessages(int(chat_id))
        await user.handler_getMessages(int(chat_id))

    async def handler_send(self, data, user_id=None, username=None):
        # Обработка нового сообщения
        chat_id = int(data['chat_id'])
        msg = data['msg']

        self.db.cur.execute(
            'INSERT INTO messages(chat_id, user_id, message) VALUES (?, ?, ?)',
            [chat_id, user_id if user_id else self.id, msg]
        )
        data = self.db.cur.execute(
            'SELECT id, chat_id, created_at, message FROM messages WHERE id=?',
            [self.db.cur.lastrowid]
        ).fetchall()[0]
        self.db.con.commit()

        # Отправляем всем участникам чата уведомление о новом сообщении
        await self.client_chat.sync_message(
            chat_id,
            [data[0], data[1], data[2], username if username else self.name, data[3]]
        )

    async def handler_getMessages(self, chat_id: int):
        # Получение списка всех сообщений
        data = self.db.cur.execute('''
                SELECT m.id, m.chat_id, m.created_at, u.name, message FROM messages m 
                INNER JOIN users u on m.user_id = u.id
                WHERE m.chat_id=? ORDER BY m.created_at
            ''', [chat_id]).fetchall()
        await self.send_crypto(json.dumps({'method': 'messages', 'data': data}))

    async def handler_sendServerAuth(self):

        server_r = bytes(os.urandom(32)).decode('mbcs')
        sign = IBC_SK.sign(self.pkg.master_public_sign, self.pkg.server_secret_sign, server_r)

        await self.ws.send(json.dumps({'method': 'start', 'data': {'sign_1': sign[0],
                                                                   'sign_2': sign[1][0].coeffs,
                                                                   'sign_3': sign[1][1].coeffs,
                                                                   'sign_4': sign[1][2].coeffs,
                                                                   'rand_s': server_r
                                                                   }}))

    async def send_crypto(self, message):
        message_crypto = IBC_SK.sym_encr(self.session_key, message)
        await self.ws.send(message_crypto.decode('mbcs'))

    async def handler_startSecure(self, data):

        ct = ((IBC_SK.ec.FQ2(data['chiphr_C1_1']), IBC_SK.ec.FQ2(data['chiphr_C1_2']),
               IBC_SK.ec.FQ2(data['chiphr_C1_3'])), data['chiphr_C2'].encode('mbcs'), data['chiphr_C3'])
        pt = IBC_SK.kem_dem_dec(self.pkg.server_name, self.pkg.server_secret_enc, ct, 32)
        username = pt.encode('mbcs')[32:].decode('mbcs')
        user = self.db.cur.execute('SELECT * FROM users WHERE name = ?', [username]).fetchall()

        if not user:
            # Предварительно регистрируем пользователя
            user_url = self.ws.remote_address[0] + ' : ' + str(self.ws.remote_address[1])
            self.db.cur.execute(
                'INSERT INTO users(name, password, url_txt, status_online) VALUES (?, ?, ?, ?)',
                [username, '0', user_url, 'YES'])
            self.db.con.commit()
            self.name = username
            pt = pt.encode('mbcs')[:32].decode('mbcs')
            self.session_key = IBC_SK.kem_decap(self.pkg.server_name, self.pkg.server_secret_enc, ct[0], 32)
            user_secret = IBC_SK.private_key_gen(self.pkg.master_secret, username)
            ct_new = IBC_SK.sym_encr(self.session_key, pt + str(user_secret))

            await self.ws.send(json.dumps({'method': 'crypto', 'data': {'ct': ct_new.decode('mbcs')}}))

        else:
            await self.ws.send(json.dumps({'method': 'auth', 'success': ['Registration', 'False']}))
            return

    async def handler_sendServerKey(self, message):
        username = message['username']
        user = self.db.cur.execute('SELECT * FROM users WHERE name = ?', [username]).fetchall()
        if user:
            self.name = user[0][1]
            self.serv_xs, self.serv_rs = IBC_SK.generate_ephemeral(self.pkg.master_public_enc, self.name)

            await self.ws.send(json.dumps({'method': 'roundkey', 'data': {'serv_rs_1': self.serv_rs[0].coeffs,
                                                                          'serv_rs_2': self.serv_rs[1].coeffs,
                                                                          'serv_rs_3': self.serv_rs[2].coeffs,
                                                                          }}))
        else:
            await self.ws.send(json.dumps({'method': 'auth', 'success': ['RoundKey', 'False']}))
            return

    async def handler_keyExchange(self, r):

        user_ru = (IBC_SK.ec.FQ2(r['user_ru_1']), IBC_SK.ec.FQ2(r['user_ru_2']), IBC_SK.ec.FQ2(r['user_ru_3']))
        self.session_key = IBC_SK.generate_session_key(
            self.pkg.server_name, self.name, self.serv_rs, user_ru, self.pkg.server_secret_enc, self.serv_xs,
            self.pkg.master_public_enc, 'A', 32)
        server_r = bytes(os.urandom(10)).decode('mbcs')
        ct_new = IBC_SK.sym_encr(self.session_key, self.name + server_r)

        await self.ws.send(json.dumps({'method': 'testkey', 'data': {'ct': ct_new.decode('mbcs')}}))

    async def handler_keyExchangeUser(self, r):

        if r['username_send'] in self.client_chat.clients_online:
            await self.client_chat.sync_roundkey(r['username_send'], r)


