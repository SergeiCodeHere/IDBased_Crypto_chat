from PyQt5.QtWidgets import QMainWindow
from Server_Window import *
from database import Database
from objects.User import User
from PyQt5.QtWidgets import QTableWidgetItem
from objects.Clients import Clients
from IBСCrypto import IBC_SK

import sys
import logging
import asyncio
import websockets


class PKG:
    def __init__(self, db):
        self.db = db
        self.master_secret = None
        self.master_public_enc = None
        self.master_public_sign = None
        self.server_name = None
        self.server_secret = None
        self.server_secret_sign = None
        self.server_secret_enc = None

    def setup(self):
        try:
            secret = self.db.cur.execute('SELECT server_name, master_secret, server_secret FROM SERVER_CONF').fetchall()
        except:
            logging.info('Ошибка инициализации сервера!')
            return False

        if not secret:
            logging.info('Ошибка инициализации сервера!')
            return False
        else:
            self.server_name = secret[0][0]
            self.master_secret = int(secret[0][1])
            self.server_secret = int(secret[0][2])

        self.master_public_enc = IBC_SK.gen_pub_g('encrypt', IBC_SK.setup('encrypt', self.master_secret))
        self.master_public_sign = IBC_SK.gen_pub_g('sign', IBC_SK.setup('sign', self.master_secret))
        self.server_secret_sign = IBC_SK.private_key_extract('sign', self.master_public_sign, self.server_secret)
        self.server_secret_enc = IBC_SK.private_key_extract('encrypt', self.master_public_enc, self.server_secret)
        return True


class Server_Win_Class(QMainWindow, Ui_Dialog_Server):
    def __init__(self, parent=None):
        QtWidgets.QWidget.__init__(self, parent)
        super().__init__(parent)
        self.ui = Ui_Dialog_Server()
        self.ui.setupUiServer(self)

    def in_table(self):
        user = db_user.cur.execute('SELECT name, url_txt, status_online FROM users').fetchall()[1:]
        if user is not None:
            count = 0
            for i in user:
                self.ui.User_Table.setRowCount(count)
                rowPosition = self.ui.User_Table.rowCount()
                self.ui.User_Table.insertRow(rowPosition)
                count += 1
                self.ui.User_Table.setItem(rowPosition, 0, QTableWidgetItem(i[0]))
                self.ui.User_Table.setItem(rowPosition, 1, QTableWidgetItem(i[1]))
                self.ui.User_Table.setItem(rowPosition, 2, QTableWidgetItem(i[2]))

        self.ui.User_Table.resizeColumnsToContents()

    def logs_txt(self, logs):
        self.ui.Text_Log.append(str(logs))


FORMAT = '[%(asctime)-15s] [%(levelname)s] - %(message)s'
logging.basicConfig(format=FORMAT, level=logging.DEBUG)

IP = '0.0.0.0'
PORT = 4180

logging.info('Запуск сервера...')

db_user = Database('db_user.sqlite')
db_konf = Database('db_konf_s.sqlite')
db_user.setup()
if not db_konf.setup():
    logging.info('Ошибка инициализации сервера!')
else:

    pkg = PKG(db_konf)

    if not pkg.setup():
        logging.info('Ошибка инициализации сервера!')
    else:

        clients = Clients()

        db_user.cur.execute('UPDATE users SET status_online = ?', ['No'])

        app = QtWidgets.QApplication(sys.argv)
        myapp = Server_Win_Class()
        myapp.show()
        myapp.in_table()


        async def qt_loop():
            while True:
                app.processEvents()  # асинхронно обновляем графический интерфейс
                await asyncio.sleep(0)


        qt_loop_task = asyncio.ensure_future(qt_loop())


        async def ws_handler(websocket, path):
            user = User(websocket, db_user, pkg, myapp, clients)
            await user.listen_messages()


        evt_loop = asyncio.get_event_loop()
        start_server = websockets.serve(ws_handler, IP, PORT)

        logging.info(f'Запущен WebSocket сервер. {IP}:{PORT}')

        myapp.logs_txt(f'Запущен WebSocket сервер. {IP}:{PORT}')
        myapp.logs_txt('Установлено подключение к SQLite')

        evt_loop.run_until_complete(start_server)
        evt_loop.run_forever()
