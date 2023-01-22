import sys
import logging

from PyQt5.QtWidgets import QApplication
from wrapper import WebsocketWrapper
from database import Database
from os import environ, path

FORMAT = '[%(asctime)-15s] [%(levelname)s] - %(message)s'
logging.basicConfig(format=FORMAT, level=logging.DEBUG)


def suppress_qt_warnings():
    environ["QT_DEVICE_PIXEL_RATIO"] = "0"
    environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"
    environ["QT_SCREEN_SCALE_FACTORS"] = "1"
    environ["QT_SCALE_FACTOR"] = "1"

    environ['QT_QPA_PLATFORM_PLUGIN_PATH'] = path.join('lib', 'PyQt5', 'qt', 'plugins', 'platforms')


if __name__ == '__main__':
    suppress_qt_warnings()
    db_user = Database('db_user.sqlite')
    db_conf = Database('db_konf_u.sqlite')
    db_user.setup()
    if not db_conf.setup():
        logging.info('Ошибка инициализации!')
    else:
        app = QApplication(sys.argv)
        ws = WebsocketWrapper(db_user, db_conf)
        sys.exit(app.exec_())
