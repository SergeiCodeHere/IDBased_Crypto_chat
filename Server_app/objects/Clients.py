from Server_app.objects import User
import json


class Clients:
    def __init__(self):
        self.clients_online = {}
        self.chats_online = {}

    def add_client(self, user: User):
        if user not in self.clients_online:
            self.clients_online[user.name] = user
        for chat in user.chats:
            x = self.chats_online.get(chat['id'], [])
            if user not in x:
                x.append(user)
                self.chats_online[chat['id']] = x

    def remove_client(self, user: User):
        if user in self.clients_online:
            self.clients_online.pop(user.name)
        for id in self.chats_online.keys():
            chat_users = self.chats_online[id]
            if user in chat_users:
                chat_users.remove(user)
                self.chats_online[id] = chat_users

    async def sync_message(self, chat_id, data):
        # Рассылка нового сообщения всем пользователям в чате
        for user in self.chats_online[int(chat_id)]:
            await user.send_crypto(json.dumps({'method': 'newMessage', 'data': data}))

    async def sync_invite(self, username, data):
        # Отправка запроса на создание чата пользователю
        user = self.clients_online[username]
        await user.send_crypto(json.dumps({'method': 'joinChat', 'data': data}))

    async def sync_roundkey(self, username, data):
        user = self.clients_online[username]
        await user.send_crypto(json.dumps({'method': 'roundkey_user', 'data': data}))
