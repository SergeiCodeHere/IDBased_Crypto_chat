from PyQt5 import QtWebSockets
from PyQt5.QtCore import QUrl
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import QMainWindow
from IBСCrypto import IBC_SK
import json
import logging
import os

from screens.auth import AuthScreen
from screens.chat import ChatScreen
from screens.Inform import InformScreen


class WebsocketWrapper(QMainWindow):
    def __init__(self, db_user, db_conf):
        super().__init__()
        self.db_conf = db_conf
        self.db_user = db_user
        self.id = None
        self.url = None
        self.name = None
        self.password = None
        self.user_xa = None
        self.user_ra = None

        self.user_secret = None
        self.master_public_enc = None
        self.master_public_sign = None
        self.user_secret_sign = None
        self.user_secret_enc = None
        self.server_name = None
        self.server_session_key = None
        self.test_chiphr = None

        self.informScreen = InformScreen()
        self.informScreen.show()
        self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
        self.informScreen.LogBrowser.append('Инициализация...')

        # Инициализация
        if self.init_conf_db():
            logging.info('Клиентское приложение успешно инициализировано!')
            self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
            self.informScreen.LogBrowser.append('Клиентское приложение успешно инициализировано!')
            # Инициализация QWebSocket и открытие экрана авторизации
            self.ws = QtWebSockets.QWebSocket("", QtWebSockets.QWebSocketProtocol.Version13, None)
            self.routes = {}

            logging.info('Открытие authScreen')
            self.informScreen.LogBrowser.append('Открытие окна авторизации')
            self.authScreen = AuthScreen(self)
            self.authScreen.show()
            self.chatScreen = ChatScreen(self)

            # Подключение всех websocket обработчиков
            self.ws.error.connect(self.error)
            self.ws.textMessageReceived.connect(self.message_handler)
            self.ws.pong.connect(self.on_pong)

    def init_conf_db(self):
        try:
            param = self.db_conf.cur.execute('SELECT server_name, puplic_enc, puplic_sign FROM USER_CONF').fetchall()
        except:
            logging.info('Ошибка инициализации клиента!')
            self.authScreen.errorText.setStyleSheet("color: #7F0000;")
            self.authScreen.errorText.setText('Ошибка инициализации клиента!')
            return False

        if not param:
            logging.info('Ошибка инициализации клиента!')
            self.authScreen.errorText.setStyleSheet("color: #7F0000;")
            self.authScreen.errorText.setText('Ошибка инициализации клиента!')
            return False

        else:
            self.server_name = param[0][0]
            self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
            self.informScreen.LogBrowser.append('Главный открытый ключ шифрования:')
            self.informScreen.LogBrowser.setTextColor(QColor(255, 0, 0))
            self.informScreen.LogBrowser.append('\n' + param[0][1] + '\n')
            self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
            self.informScreen.LogBrowser.append('Главный открытый ключ электронной подписи:')
            self.informScreen.LogBrowser.setTextColor(QColor(255, 0, 0))
            self.informScreen.LogBrowser.append('\n' + param[0][2] + '\n')
            self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
            self.informScreen.LogBrowser.append('Идентификатор сервера: ')
            self.informScreen.LogBrowser.setTextColor(QColor(255, 0, 0))
            self.informScreen.LogBrowser.append('\n' + param[0][0] + '\n')

            temp = param[0][1].split('||')
            self.master_public_enc = IBC_SK.gen_pub_g('encrypt',
                                                      (IBC_SK.ec.FQ2([int(x) for x in temp[0][1:-1].split(', ')]),
                                                       IBC_SK.ec.FQ2([int(x) for x in temp[1][1:-1].split(', ')]),
                                                       IBC_SK.ec.FQ2([int(x) for x in temp[2][1:-1].split(', ')])))
            temp = [int(x) for x in param[0][2].split('||')]
            self.master_public_sign = IBC_SK.gen_pub_g('sign',
                                                       (IBC_SK.ec.FQ(temp[0]),
                                                        IBC_SK.ec.FQ(temp[1]),
                                                        IBC_SK.ec.FQ(temp[2])))
            return True

    def connect_ws(self):
        self.url = 'ws://' + self.authScreen.URLInput.text()
        self.name = self.authScreen.inputName.text()
        self.password = self.authScreen.inputPassword.text()

        self.subscribe_basic_methods()

        logging.info(f'Подключение к Websocket по адресу {self.url}')
        self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
        self.informScreen.LogBrowser.append(f'Подключение к серверу по адресу {self.authScreen.URLInput.text()} ...')
        self.ws.open(QUrl(self.url))

    def send_message(self, message):
        message = json.dumps(message)
        logging.info(f'[Out]: {message}')
        self.ws.sendTextMessage(message)

    def send_message_crypto(self, message):
        message = json.dumps(message)
        message_crypto = IBC_SK.sym_encr(self.server_session_key, message)
        logging.info(f'[Out]: {message}')
        self.ws.sendTextMessage(message_crypto.decode('mbcs'))

    def message_handler(self, message):
        logging.info(f'[In]: {message}')
        if message.find('method') != -1:
            message = json.loads(message)
            if message['method'] in self.routes.keys():
                self.routes[message['method']](message)
        else:
            message_decr = IBC_SK.sym_decr(self.server_session_key, message.encode('mbcs'))
            message_decr = json.loads(message_decr)
            if message_decr['method'] in self.routes.keys():
                self.routes[message_decr['method']](message_decr)

    def subscribe(self, method_name, handler):
        # Подписка обработчика на события от бекенда
        self.routes[method_name] = handler

    def subscribe_basic_methods(self):
        self.subscribe('init', lambda x: self.init_user())
        self.subscribe('auth', lambda x: self.auth_handler(x))
        self.subscribe('start', lambda x: self.start_crypto(x['data']))
        self.subscribe('crypto', lambda x: self.crypto(x['data']))
        self.subscribe('session_key', lambda x: self.session_key(x['data']))
        self.subscribe('roundkey', lambda x: self.round_key(x['data']))
        self.subscribe('roundkey_user', lambda x: self.round_key_user(x['data']))
        self.subscribe('testkey', lambda x: self.test_round_key(x['data']))
        self.subscribe('userChats', lambda x: self.chatScreen.render_chats(x))
        self.subscribe('joinChat', lambda x: self.chatScreen.join_chats(x))
        self.subscribe('AnswerChat', lambda x: self.chatScreen.answer_chats(x))

    def init_user(self):
        self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
        self.informScreen.LogBrowser.append('Соединение с сервером установлено!')
        secret = self.db_user.cur.execute('SELECT private_key FROM crypto_user').fetchall()
        if secret:
            self.user_secret = int(secret[0][0])

            self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
            self.informScreen.LogBrowser.append('Извлечение закрытого ключа из базы:')
            self.informScreen.LogBrowser.setTextColor(QColor(255, 0, 0))
            self.informScreen.LogBrowser.append('\n' + str(self.user_secret) + '\n')

            self.init_key()
        elif not self.authScreen.NeedRegistration:
            self.authScreen.errorText.setStyleSheet("color: #7F0000;")
            self.authScreen.errorText.setText('Необходима регистрация!')
        else:
            self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
            self.informScreen.LogBrowser.append('Проверка аутентичности сервера. Отправляем сообщение init')
            self.send_message({'method': 'init', 'data': 'Need server auth!'})

    def init_key(self):
        self.user_secret_sign = IBC_SK.private_key_extract('sign', self.master_public_sign, self.user_secret)
        self.user_secret_enc = IBC_SK.private_key_extract('encrypt', self.master_public_enc, self.user_secret)
        if not self.authScreen.NeedRegistration:
            self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
            self.informScreen.LogBrowser.append('Отправляем серверу запрос на осуществление ключевого обмена! \n')

            self.send_message({'method': 'init_key', 'data': {'message': 'Need session key!',
                                                              'username': self.name}})
        else:
            self.authScreen.errorText.setStyleSheet("color: #7F0000;")
            self.authScreen.errorText.setText('Вы уже зарегестрированы!')

    def start_crypto(self, r):

        self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
        self.informScreen.LogBrowser.append('Получение ответа от сервера. \nЭП (h,S), где \n\nh :')
        self.informScreen.LogBrowser.setTextColor(QColor(255, 0, 0))
        self.informScreen.LogBrowser.append(str(r['sign_1']) + '\n')
        self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
        self.informScreen.LogBrowser.append('S :')
        self.informScreen.LogBrowser.setTextColor(QColor(255, 0, 0))
        self.informScreen.LogBrowser.append(str(r['sign_2']) + str(r['sign_3']) + str(r['sign_4']) + '\n')
        self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
        self.informScreen.LogBrowser.append('Само сообщение: ' + str(r['rand_s'].encode('mbcs')))

        sign = (r['sign_1'], (IBC_SK.ec.FQ2(r['sign_2']), IBC_SK.ec.FQ2(r['sign_3']), IBC_SK.ec.FQ2(r['sign_4'])))
        server_r = r['rand_s']
        if IBC_SK.verify(self.master_public_sign, self.server_name, server_r, sign):

            self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
            self.informScreen.LogBrowser.append('\nПроверка ЭП прошла успешно. Сервер идентифицирован!\n')
            self.authScreen.errorText.setText('Сервер идентифицирован!')

            if not self.authScreen.NeedRegistration:
                self.authScreen.errorText.setStyleSheet("color: #7F0000;")
                self.authScreen.errorText.setText('Необходима регистрация!')
            else:
                self.test_chiphr = bytes(os.urandom(32)).decode('mbcs')

                self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
                self.informScreen.LogBrowser.append('Генерируем рандомную строку бит: ')
                self.informScreen.LogBrowser.setTextColor(QColor(255, 0, 0))
                self.informScreen.LogBrowser.append(str(self.test_chiphr.encode('mbcs')) + '\n')

                C, self.server_session_key = IBC_SK.kem_dem_enc(self.master_public_enc, self.server_name,
                                                                self.test_chiphr + self.name, 32)

                self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
                self.informScreen.LogBrowser.append(
                    'Шифруем ее при помощи идентификатора сервера. Полученный шифртекст: \n')
                self.informScreen.LogBrowser.setTextColor(QColor(255, 0, 0))
                self.informScreen.LogBrowser.append(
                    json.dumps({'chiphr_C1_1': C[0][0].coeffs,
                                'chiphr_C1_2': C[0][1].coeffs,
                                'chiphr_C1_3': C[0][2].coeffs,
                                'chiphr_C2': str(C[1]),
                                'chiphr_C3': C[2]}))

                self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
                self.informScreen.LogBrowser.append('\nИзвлекаем сессионый ключ: ')
                self.informScreen.LogBrowser.setTextColor(QColor(255, 0, 0))
                self.informScreen.LogBrowser.append(self.server_session_key)

                self.send_message({'method': 'start_secure', 'data': {'chiphr_C1_1': C[0][0].coeffs,
                                                                      'chiphr_C1_2': C[0][1].coeffs,
                                                                      'chiphr_C1_3': C[0][2].coeffs,
                                                                      'chiphr_C2': C[1].decode('mbcs'),
                                                                      'chiphr_C3': C[2]}})
                self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
                self.informScreen.LogBrowser.append('\nОтправляем полученный шифртекст.')

        else:
            self.authScreen.errorText.setStyleSheet("color: #7F0000;")
            self.authScreen.errorText.setText('Ошибка идентификации сервера')

    def crypto(self, r):

        self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
        self.informScreen.LogBrowser.append('\n' + 'Получаем ответ от сервера: ')
        self.informScreen.LogBrowser.setTextColor(QColor(255, 0, 0))
        self.informScreen.LogBrowser.append(str(r['ct'].encode('mbcs')))

        pt = IBC_SK.sym_decr(self.server_session_key, r['ct'].encode('mbcs'))

        self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
        self.informScreen.LogBrowser.append('\nРасшифровываем: \n')
        self.informScreen.LogBrowser.setTextColor(QColor(255, 0, 0))
        self.informScreen.LogBrowser.append(str(pt[:32]) + " || " + str(pt[32:]))

        if self.test_chiphr.encode('mbcs') == pt[:32]:

            self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
            self.informScreen.LogBrowser.append('\nСравниваем отправленную и полученную случайную строку бит!')

            self.user_secret = int(pt[32:].decode('mbcs'))
            self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
            self.informScreen.LogBrowser.append('\nИзвлекаем закрытый ключ:\n')
            self.informScreen.LogBrowser.setTextColor(QColor(255, 0, 0))
            self.informScreen.LogBrowser.append(str(self.user_secret))

            self.authScreen.errorText.setText('Защищенное соединение установлено!\n')

            self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
            self.informScreen.LogBrowser.append('\nЗащищенное соединение установлено!')

            self.db_user.cur.execute(
                'INSERT INTO crypto_user(private_key) VALUES (?)',
                [str(self.user_secret)])
            self.db_user.con.commit()
            self.user_secret_sign = IBC_SK.private_key_extract('sign', self.master_public_sign, self.user_secret)
            self.user_secret_enc = IBC_SK.private_key_extract('encrypt', self.master_public_enc, self.user_secret)
            self.sendAuth()
        else:
            self.authScreen.errorText.setText('Передача закрытого ключа завершилась ошибкой!')

    def sendAuth(self):
        data = str(self.authScreen.NeedRegistration) + '||' + self.name + '||' + self.password
        data_encode = IBC_SK.sym_encr(self.server_session_key, data).decode('mbcs')

        self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
        self.informScreen.LogBrowser.append('\nОтправляем на сервер пароль в зашифрованном виде:')
        self.informScreen.LogBrowser.setTextColor(QColor(255, 0, 0))
        self.informScreen.LogBrowser.append('\n' + str(data_encode.encode('mbcs')) + '\n')

        self.send_message({'method': 'auth', 'data': data_encode})

    def round_key(self, r):

        self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
        self.informScreen.LogBrowser.append('Получаем от сервера открытый парметр генерации сессионного ключа, RS:')
        self.informScreen.LogBrowser.setTextColor(QColor(255, 0, 0))
        self.informScreen.LogBrowser.append('\n' + json.dumps(r) + '\n')

        serv_rs = (IBC_SK.ec.FQ2(r['serv_rs_1']), IBC_SK.ec.FQ2(r['serv_rs_2']), IBC_SK.ec.FQ2(r['serv_rs_3']))

        user_xu, user_ru = IBC_SK.generate_ephemeral(self.master_public_enc, self.server_name)

        self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
        self.informScreen.LogBrowser.append(
            'Вычисляем пользовательский открытый и закрытый параметры генерации сессионного ключа:\n XU: ')
        self.informScreen.LogBrowser.setTextColor(QColor(255, 0, 0))
        self.informScreen.LogBrowser.append(str(user_xu) + '\n')
        self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
        self.informScreen.LogBrowser.append('RU: ')
        self.informScreen.LogBrowser.setTextColor(QColor(255, 0, 0))
        self.informScreen.LogBrowser.append(json.dumps({'user_ru_1': user_ru[0].coeffs,
                                                        'user_ru_2': user_ru[1].coeffs,
                                                        'user_ru_3': user_ru[2].coeffs
                                                        }) + '\n')

        self.server_session_key = IBC_SK.generate_session_key(
            self.server_name, self.name, serv_rs, user_ru, self.user_secret_enc, user_xu, self.master_public_enc, 'B',
            32)

        self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
        self.informScreen.LogBrowser.append(
            'Вычисляем сессионный ключ:\n')
        self.informScreen.LogBrowser.setTextColor(QColor(255, 0, 0))
        self.informScreen.LogBrowser.append(self.server_session_key + '\n')

        self.send_message({'method': 'roundkey', 'data': {'user_ru_1': user_ru[0].coeffs,
                                                          'user_ru_2': user_ru[1].coeffs,
                                                          'user_ru_3': user_ru[2].coeffs,
                                                          }})

    def test_round_key(self, r):

        self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
        self.informScreen.LogBrowser.append(
            'Получаем от сервера тестовую зашифрованную строку:\n')
        self.informScreen.LogBrowser.setTextColor(QColor(255, 0, 0))
        self.informScreen.LogBrowser.append(str(r['ct'].encode('mbcs')) + '\n')

        pt = IBC_SK.sym_decr(self.server_session_key, r['ct'].encode('mbcs'))

        self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
        self.informScreen.LogBrowser.append(
            'Расшифровываем зашифрованную строку:\n')
        self.informScreen.LogBrowser.setTextColor(QColor(255, 0, 0))
        self.informScreen.LogBrowser.append(str(pt) + '\n')

        self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
        self.informScreen.LogBrowser.append('Ищем вхождение идентификатора клиента.:\n')

        if self.name == pt[:-10].decode('mbcs'):

            self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
            self.informScreen.LogBrowser.append('Вхождение найдено! Защищенное соединение установлено!\n')

            self.authScreen.errorText.setText('Защищенное соединение установлено!')
            self.sendAuth()
        else:
            self.authScreen.errorText.setText('Передача закрытого ключа завершилась ошибкой!')

    def round_key_user_A(self, username):
        self.user_xa, self.user_ra = IBC_SK.generate_ephemeral(self.master_public_enc, username)

        self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
        self.informScreen.LogBrowser.append(
            'Вычисляем открытый и закрытый параметры генерации сессионного ключа для диалога с пользователем ' + username + '.\nXA: ')
        self.informScreen.LogBrowser.setTextColor(QColor(255, 0, 0))
        self.informScreen.LogBrowser.append(str(self.user_xa) + '\n')
        self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
        self.informScreen.LogBrowser.append('RA: ')
        self.informScreen.LogBrowser.setTextColor(QColor(255, 0, 0))
        self.informScreen.LogBrowser.append(json.dumps({'user_r_1': self.user_ra[0].coeffs,
                                                        'user_r_2': self.user_ra[1].coeffs,
                                                        'user_r_3': self.user_ra[2].coeffs
                                                        }) + '\n')
        self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
        self.informScreen.LogBrowser.append(
            'Отправляем открытый параметр пользователю ' + username)

        self.send_message_crypto({'method': 'roundkey_user', 'data': {'user_r_1': self.user_ra[0].coeffs,
                                                                      'user_r_2': self.user_ra[1].coeffs,
                                                                      'user_r_3': self.user_ra[2].coeffs,
                                                                      'usernameB': username,
                                                                      'usernameA': self.name,
                                                                      'username_send': username}})

    def round_key_user(self, r):


        user_r = (IBC_SK.ec.FQ2(r['user_r_1']), IBC_SK.ec.FQ2(r['user_r_2']), IBC_SK.ec.FQ2(r['user_r_3']))

        if self.name == r['usernameB']:
            self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
            self.informScreen.LogBrowser.append(
                'Получаем от пользователя ' + r['usernameA'] + ' параметр для генерации ключа диалога:')
            self.informScreen.LogBrowser.setTextColor(QColor(255, 0, 0))
            self.informScreen.LogBrowser.append('\n' + json.dumps(r) + '\n')

            user_xb, user_rb = IBC_SK.generate_ephemeral(self.master_public_enc, r['usernameA'])

            session_key = IBC_SK.generate_session_key(
                r['usernameA'], self.name, user_r, user_rb, self.user_secret_enc, user_xb, self.master_public_enc, 'B',
                32)
            chatname = r['usernameA'] + ' || ' + self.name
            self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
            self.informScreen.LogBrowser.append(
                'Вычисляем открытый и закрытый параметры генерации сессионного ключа для диалога с пользователем ' + r['usernameA'] + '.\nXB: ')
            self.informScreen.LogBrowser.setTextColor(QColor(255, 0, 0))
            self.informScreen.LogBrowser.append(str(user_xb) + '\n')
            self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
            self.informScreen.LogBrowser.append('RB: ')
            self.informScreen.LogBrowser.setTextColor(QColor(255, 0, 0))
            self.informScreen.LogBrowser.append(json.dumps({'user_r_1': user_rb[0].coeffs,
                                                            'user_r_2': user_rb[1].coeffs,
                                                            'user_r_3': user_rb[2].coeffs
                                                            }) + '\n')
            self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
            self.informScreen.LogBrowser.append(
                'Отправляем открытый параметр пользователю ' + r['usernameA'])

            self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
            self.informScreen.LogBrowser.append(
                'Вычисляем сессионный ключ диалога ' + chatname + ' :\n ')
            self.informScreen.LogBrowser.setTextColor(QColor(255, 0, 0))
            self.informScreen.LogBrowser.append(session_key + '\n')

            self.send_message_crypto({'method': 'roundkey_user', 'data': {'user_r_1': user_rb[0].coeffs,
                                                                          'user_r_2': user_rb[1].coeffs,
                                                                          'user_r_3': user_rb[2].coeffs,
                                                                          'usernameB': self.name,
                                                                          'usernameA': r['usernameA'],
                                                                          'username_send': r['usernameA']}})
        else:
            self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
            self.informScreen.LogBrowser.append(
                'Получаем от пользователя ' + r['usernameB'] + ' параметр для генерации ключа диалога:')
            self.informScreen.LogBrowser.setTextColor(QColor(255, 0, 0))
            self.informScreen.LogBrowser.append('\n' + json.dumps(r) + '\n')

            session_key = IBC_SK.generate_session_key(
                self.name, r['usernameB'], self.user_ra, user_r, self.user_secret_enc, self.user_xa,
                self.master_public_enc, 'A', 32)
            chatname = self.name + ' || ' + r['usernameB']

            self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
            self.informScreen.LogBrowser.append(
                'Вычисляем сессионный ключ диалога ' + chatname + ' :\n ')
            self.informScreen.LogBrowser.setTextColor(QColor(255, 0, 0))
            self.informScreen.LogBrowser.append(session_key + '\n')

        self.db_user.cur.execute(
            'INSERT INTO crypto_chat(chat_name, chat_pass) VALUES (?, ?)',
            [chatname, session_key])
        self.db_user.con.commit()

    def auth_handler(self, r):

        if r['success'] == ['Registration', 'False']:
            self.authScreen.errorText.setStyleSheet("color: #7F0000;")
            self.authScreen.errorText.setText('Данный идентификатор занят')
        elif r['success'] == ['Auth', 'False']:
            self.authScreen.errorText.setStyleSheet("color: #7F0000;")
            self.authScreen.errorText.setText('Неверный логин или пароль')
        elif r['success'] == ['Secure', 'False']:
            self.authScreen.errorText.setStyleSheet("color: #7F0000;")
            self.authScreen.errorText.setText('Ошибка при установке защищенного соединения')
        elif r['success'] == ['RoundKey', 'False']:
            self.authScreen.errorText.setStyleSheet("color: #7F0000;")
            self.authScreen.errorText.setText('Ошибка генерации сессионного ключа')
        else:
            # Открываем экран чата
            self.id = r['data']['id']
            self.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
            self.informScreen.LogBrowser.append('\nАвторизация на сервере успешно пройдена!')

            self.chatScreen.Form.setWindowTitle(f'Чат - Пользователь {self.name}')
            self.authScreen.errorText.setText('')
            self.authScreen.close()
            self.chatScreen.show()

    def do_ping(self):
        logging.debug('[Out]: Ping')
        self.ws.ping(b"foo")

    def on_pong(self, elapsedTime, payload):
        logging.debug('[In]: Pong')
        print("onPong - time: {} ; payload: {}".format(elapsedTime, payload))

    def error(self, error_code):
        logging.critical("Websocket error code: {}".format(error_code))
        logging.critical("Websocket status: {}".format(self.ws.errorString()))

        self.authScreen.errorText.setStyleSheet("color: #7F0000;")
        if int(error_code) == 1:
            self.authScreen.errorText.setText('Потеряно соединение с сервером')
            self.chatScreen.close()
            self.authScreen.show()
        elif int(error_code) == 0:
            self.authScreen.errorText.setText('Сервер не отвечает')
        elif int(error_code) == 2:
            self.authScreen.errorText.setText('Хост не найден')
        else:
            self.authScreen.errorText.setText(self.ws.errorString())
