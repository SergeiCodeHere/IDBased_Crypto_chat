from PyQt5 import QtCore, QtWidgets
from PyQt5.QtWidgets import QMessageBox, QGridLayout, QWidget
from PyQt5.QtCore import QSize, Qt

class Ui_Dialog_Server(object):

    def setupUiServer(self, Server_Win):
        Server_Win.setObjectName("Server_Win")
        Server_Win.setMinimumSize(QSize(500, 510))

        self.label1 = QtWidgets.QLabel(Server_Win)
        self.label1.setGeometry(QtCore.QRect(10, 10, 200, 10))
        self.label1.setObjectName("label1")
        self.label1.setText("Пользователи в системе:")

        self.User_Table = QtWidgets.QTableWidget(Server_Win)
        self.User_Table.setGeometry(QtCore.QRect(10, 30, 480, 200))
        self.User_Table.setObjectName("Table")

        self.Text_Log = QtWidgets.QTextEdit(Server_Win)
        self.Text_Log.setGeometry(QtCore.QRect(10, 240, 480, 260))
        self.Text_Log.setObjectName("Text_Log")

        self.retranslateUiAnal(Server_Win)
        QtCore.QMetaObject.connectSlotsByName(Server_Win)

    def retranslateUiAnal(self, Server_Win):
        _translate = QtCore.QCoreApplication.translate
        Server_Win.setWindowTitle("Сервер PKG")

        self.User_Table.setColumnCount(3)
        self.User_Table.setHorizontalHeaderLabels(["Идентификатор", "IP", "Online"])
        self.User_Table.resizeColumnsToContents()
        self.Text_Log.setReadOnly(True)