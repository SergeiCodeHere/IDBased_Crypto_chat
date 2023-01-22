# В этом файле вся работа с SQLite

import sqlite3
import logging
from db_structure import QUERY


class Database:
    def __init__(self, filename):
        self.con = None
        self.cur = None
        self.filename = filename

    def setup(self):
        self.con = sqlite3.connect(self.filename)
        self.cur = self.con.cursor()
        logging.debug('Установлено подключение к SQLite')
        if not self.is_database_ready():
            if self.filename == 'db_konf_u.sqlite':
                return False
            self.create_structure()
        else:
            return True

    def is_database_ready(self):
        try:
            if self.filename == 'db_user.sqlite':
                self.cur.execute("SELECT id FROM users LIMIT 1")
                return True
        except:
                logging.warning('Пустой файл базы данных пользователей. Создание базовой структуры...')
                return False
        try:
            if self.filename == 'db_konf_u.sqlite':
                self.cur.execute("SELECT id FROM USER_CONF LIMIT 1")
                return True
        except:
                logging.warning('Пустой файл конфигурационной базы данных пользователей. Ошибка инициализации!')
                return False

    def create_structure(self):
        if self.filename == 'db_user.sqlite':
            self.cur.executescript(QUERY)
        self.con.commit()