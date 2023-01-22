from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_Inform(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(1200, 600)
        Form.setFixedSize(1200, 600)
        self.Form = Form
        self.horizontalLayoutWidget = QtWidgets.QWidget(Form)
        self.horizontalLayoutWidget.setGeometry(QtCore.QRect(0, 0, 1200, 600))
        self.horizontalLayoutWidget.setObjectName("horizontalLayoutWidget")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout(self.horizontalLayoutWidget)
        self.horizontalLayout_2.setContentsMargins(3, 0, 0, 0)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout()
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.createChat_button = QtWidgets.QPushButton(self.horizontalLayoutWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.createChat_button.sizePolicy().hasHeightForWidth())
        self.verticalLayout = QtWidgets.QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.LogBrowser = QtWidgets.QTextBrowser(self.horizontalLayoutWidget)
        font = QtGui.QFont()
        font.setPointSize(14)
        self.LogBrowser.setFont(font)
        self.LogBrowser.setObjectName("LogBrowser")
        self.verticalLayout.addWidget(self.LogBrowser)
        self.horizontalLayout_2.addLayout(self.verticalLayout)

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Логи"))
