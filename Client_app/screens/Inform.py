from PyQt5.QtWidgets import QMainWindow
from ui.Information import Ui_Inform


class InformScreen(QMainWindow, Ui_Inform):
    def __init__(self, ws=None):
        super(InformScreen, self).__init__(ws)
        self.ws = ws
        self.setupUi(self)
        self.NeedRegistration = None

