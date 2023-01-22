from PyQt5 import QtCore
from PyQt5.QtWidgets import QMainWindow, QListWidgetItem
from PyQt5.QtGui import QFont, QColor
from ui.chat import Ui_Form
from ui.createChat import Ui_CreateChat
from ui.joinChat import Ui_JoinChat
from IBСCrypto import IBC_SK


class CreateChatModal(QMainWindow, Ui_CreateChat):
    def __init__(self, parent):
        super(CreateChatModal, self).__init__(parent)
        self.ws = parent.ws
        self.setupUi(self)
        self.errorText.setText('')
        self.createButton.clicked.connect(self.create_chat)
        self.createButton.setEnabled(True)

    def create_chat(self):
        self.createButton.setEnabled(False)
        name = self.chatTitle.text()
        self.ws.subscribe('createChat', self.response_handler)
        self.ws.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
        self.ws.informScreen.LogBrowser.append('\nОтправляем запрос на создание чата с ' + name)
        self.ws.send_message_crypto({'method': 'createChat', 'data': {'name': name}})

    def response_handler(self, r):
        if r['success']:
            self.errorText.setStyleSheet("color: #007F00;")
            self.errorText.setText('Чат успешно создан')
            self.createButton.setEnabled(True)
        else:
            self.errorText.setStyleSheet("color: #7F0000;")
            self.errorText.setText(r['text'])
            self.createButton.setEnabled(True)


class JoinChatModal(QMainWindow, Ui_JoinChat):
    def __init__(self, parent, username):
        super(JoinChatModal, self).__init__(parent)
        self.ws = parent.ws
        self.username = username
        self.setupUi(self)
        self.joinButton.clicked.connect(self.join_chat)
        self.cancelButton.clicked.connect(self.cancel_chat)
        self.setWindowFlag(QtCore.Qt.WindowCloseButtonHint, False)
        self.UserName.setText('Запрос на создание чата с ' + self.username)
        self.ws.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
        self.ws.informScreen.LogBrowser.append('\nЗапрос на создание чата с  ' + self.username)

    def join_chat(self):
        self.ws.subscribe('joinChat', self.response_handler)
        self.ws.send_message_crypto({'method': 'joinChat', 'data': {'Answer': 'Yes', 'name': self.username}})
        self.ws.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
        self.ws.informScreen.LogBrowser.append('\nЗапрос на создание чата с  ' + self.username + ' принят. Запущена процедура генерации ключа шифрования диалога!')
        self.ws.round_key_user_A(self.username)

    def cancel_chat(self):
        self.ws.subscribe('joinChat', self.response_handler)
        self.ws.send_message_crypto({'method': 'joinChat', 'data': {'Answer': 'No', 'name': self.username}})
        self.ws.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
        self.ws.informScreen.LogBrowser.append('\nЗапрос на создание чата с  ' + self.username + ' отказан.')

    def response_handler(self, r):
        if r['success']:
            self.errorText.setStyleSheet("color: #007F00;")
            self.errorText.setText('Чат')
        else:
            self.errorText.setStyleSheet("color: #7F0000;")
            self.errorText.setText(r['text'])


class ChatScreen(QMainWindow, Ui_Form):
    def __init__(self, ws=None):
        super(ChatScreen, self).__init__(ws)

        self.ws = ws
        self.selectedChat = None
        self.messages_by_chat = {}
        self.chats_list = {}
        self.need_render = False

        self.setupUi(self)
        self.createChatModal = CreateChatModal(self)
        self.joinChatModal = None
        self.register_handlers()

    def register_handlers(self):
        self.ws.subscribe('newMessage', self.newMessage_handler)
        self.userChats.itemClicked.connect(self.onclick_chat)

        # Обработчики для кнопки создания чата
        self.createChat_button.clicked.connect(lambda: [
            self.createChatModal.errorText.setText(''),
            self.createChatModal.show()
        ])

        # Enter и кнопка отправки сообщения
        self.sendButton.clicked.connect(self.send_message)
        self.messageInput.returnPressed.connect(self.send_message)

    def join_chats(self, r):

        # Обработчик при поступлении запроса на создание чата
        username = r['data']
        self.joinChatModal = JoinChatModal(self, username)
        self.joinChatModal.errorText.setText('')
        self.joinChatModal.show()

    def answer_chats(self, r):

        if r['success']:
            self.joinChatModal.close()

    def render_chats(self, r):
        # Отображение списка всех чатов
        chats = r['data']
        self.userChats.clear()
        for chat in chats:
            self.chats_list[chat['id']] = chat['name']
            item = QListWidgetItem()
            font = QFont()
            font.setPointSize(12)
            item.setFont(font)
            tmp = chat['name'].split(' || ')
            if tmp[0] == self.ws.name:
                item.setText(tmp[1])
            else:
                item.setText(tmp[0])
            item.setWhatsThis(str(chat['id']))
            self.userChats.addItem(item)

    def newMessage_handler(self, r):
        chat_id = r['data'][1]
        if chat_id not in self.messages_by_chat.keys():
            # Если мы ещё не выгружали историю чата, то выгружаем сейчас
            self.get_history(chat_id)
            self.need_render = self.selectedChat == chat_id
            return


        temp = self.chats_list[chat_id].split(' || ')[1] + ' || ' + self.chats_list[chat_id].split(' || ')[0]
        session_key = self.ws.db_user.cur.execute('SELECT chat_pass FROM crypto_chat WHERE chat_name = ? or chat_name = ?',
                                                  [self.chats_list[chat_id], temp]).fetchall()[0][0]
        self.ws.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
        self.ws.informScreen.LogBrowser.append(
            'Новое сообщение в диалоге ' + self.chats_list[chat_id] + '.\nПринято в виде  ' +  str(r['data'][4].encode('mbcs')) +'.\nРасшифровываем: ')
        self.ws.informScreen.LogBrowser.setTextColor(QColor(255, 0, 0))
        message_decr = IBC_SK.sym_decr(session_key, r['data'][4].encode('mbcs')).decode('mbcs')
        self.ws.informScreen.LogBrowser.append(str(message_decr) + '\n')


        # Добавляем сообщение к общему списку
        self.messages_by_chat[chat_id].append(r['data'])

        # Если на данный момент у пользователя открыт этот чат,
        # то делаем ререндер сообщений в нём
        if self.selectedChat == chat_id:
            self.render_messages(chat_id)

    def get_messages(self, r):

        chat_id = int(r['data'][0][1])
        self.messages_by_chat[chat_id] = r['data']
        if self.need_render:
            self.render_messages(chat_id)

    def render_messages(self, chat_id):
        # Рендеринг всех сообщений

        if chat_id not in self.messages_by_chat.keys():
            # Если мы ещё не выгружали историю чата, то выгружаем сейчас
            self.get_history(chat_id)
            self.need_render = True
            return
        temp = self.chats_list[chat_id].split(' || ')[1] + ' || ' + self.chats_list[chat_id].split(' || ')[0]
        session_key = self.ws.db_user.cur.execute('SELECT chat_pass FROM crypto_chat WHERE chat_name = ? or chat_name = ?',[self.chats_list[chat_id], temp]).fetchall()[0][0]

        messages = self.messages_by_chat[chat_id]
        result = ''

        for msg in messages:
            if msg[3] != 'System':
                message_decr = IBC_SK.sym_decr(session_key, msg[4].encode('mbcs')).decode('mbcs')
            else:
                message_decr = msg[4]
            date = msg[2].split(" ")[1]
            result += f'[{date}] <{msg[3]}>: {message_decr}\n'

        # Обновляем браузер и скроллим его в самый низ
        self.chatBrowser.setText(result)
        scroll = self.chatBrowser.verticalScrollBar()
        scroll.setValue(scroll.maximum())
        self.need_render = False

    def get_history(self, chat_id):
        self.ws.subscribe('messages', self.get_messages)
        self.ws.send_message_crypto({'method': 'messages', 'chat_id': chat_id})

    def onclick_chat(self, item):
        self.selectedChat = int(item.whatsThis())
        self.render_messages(self.selectedChat)

    def send_message(self):
        if self.selectedChat and self.messageInput.text():
            temp = self.chats_list[self.selectedChat].split(' || ')[1] + ' || ' + \
                   self.chats_list[self.selectedChat].split(' || ')[0]
            session_key = self.ws.db_user.cur.execute('SELECT chat_pass FROM crypto_chat WHERE chat_name = ? or chat_name = ?',
                                                      [self.chats_list[self.selectedChat], temp]).fetchall()[0][0]
            message_crypto = IBC_SK.sym_encr(session_key, self.messageInput.text()).decode('mbcs')

            self.ws.informScreen.LogBrowser.setTextColor(QColor(0, 0, 0))
            self.ws.informScreen.LogBrowser.append(
                'Отправка сообщения "' + self.messageInput.text() + '" из диалога ' + temp + '.\nШифруем сообщение перед отправкой: ')
            self.ws.informScreen.LogBrowser.setTextColor(QColor(255, 0, 0))
            self.ws.informScreen.LogBrowser.append(str(message_crypto.encode('mbcs')) + '\n')

            self.ws.send_message_crypto({'method': 'send', 'data': {
                'chat_id': self.selectedChat,
                'msg': message_crypto
            }})
            self.messageInput.setText('')
