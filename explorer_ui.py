try:
    from burp import IBurpExtender
    from burp import IScannerCheck
    from burp import IExtensionStateListener
    from burp import ITab
    # from burp import IHttpRequestResponse
    # from burp import IScanIssue
    # from array import array
    # from time import sleep
    from java.io import PrintWriter
    from javax.swing import (JTable, JScrollPane, JSplitPane, JButton, JPanel,
                             JTextField, JLabel, SwingConstants)
    from javax.swing.table import AbstractTableModel
    from java.awt import GridLayout

except ImportError:
    print "Failed to load dependencies. This issue maybe caused by using an unstable Jython version."

VERSION = '0.1'


class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        print "Loading..."

        self._callbacks = callbacks
        self._callbacks.setExtensionName('Burp SPA Explorer')
        # self._callbacks.registerScannerCheck(self)
        # self._callbacks.registerExtensionStateListener(self)
        self._helpers = callbacks.getHelpers()

        # main split pane
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)

        self.setupPanel = JPanel(GridLayout(0, 2))

        self.hostField = JTextField('', 15)
        self.setupPanel.add(JLabel("Host:", SwingConstants.LEFT))
        self.setupPanel.add(self.hostField)

        self.regexField = JTextField('', 15)
        self.setupPanel.add(JLabel("Regex:", SwingConstants.LEFT))
        self.setupPanel.add(self.regexField)

        self.startButton = JButton(
            'Start crawling', actionPerformed=self.crawl)
        self.setupPanel.add(self.startButton)

        self._splitpane.setTopComponent(self.setupPanel)

        self.logger = Logger(["Hello", "World", "Burp", "SPA", "Explorer"])
        self.logTable = Table(self.logger)
        self.scrollPane = JScrollPane(self.logTable)
        self._splitpane.setBottomComponent(self.scrollPane)

        callbacks.customizeUiComponent(self.scrollPane)
        callbacks.customizeUiComponent(self.setupPanel)
        callbacks.addSuiteTab(self)
        print "Burp SPA Explorer loaded"

    # Implement ITab

    def getTabCaption(self):
        return "SPA Explorer"

    def getUiComponent(self):
        return self._splitpane

    def crawl(self, event):
        self.logger.addRow(self.hostField.text + " " + self.regexField.text)


class Logger(AbstractTableModel):

    # Implement AbstractTableModel

    def __init__(self, log):
        self.log = log

    def getRowCount(self):
        try:
            return len(self.log)
        except:
            return 0

    def getColumnCount(self):
        return 1

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "Test"
        return "Column " + columnIndex

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self.log[rowIndex]
        # if columnIndex == 0:
        #     return self._callbacks.getToolName(logEntry._tool)
        # if columnIndex == 1:
        #     return logEntry._url.toString()
        # return ""
        return str(logEntry)

    def addRow(self, row):
        self.log.append(row)
        self.fireTableRowsInserted(len(self.log) - 1, len(self.log) - 1)


class Table(JTable):
    def __init__(self, model):
        self.setModel(model)

    def changeSelection(self, row, col, toggle, extend):

        # show the log entry for the selected row
        # logEntry = self._extender.log[row]
        JTable.changeSelection(self, row, col, toggle, extend)