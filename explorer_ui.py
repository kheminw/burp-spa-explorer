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
    from java.lang import Runnable
    from javax.swing import (JTable, JScrollPane, JSplitPane, JButton, JPanel,
                             JTextField, JLabel, SwingConstants, JDialog,
                             JCheckBox, SwingUtilities, JOptionPane, BoxLayout)

    from javax.swing.border import EmptyBorder
    from javax.swing.table import AbstractTableModel
    from java.awt import (GridLayout, BorderLayout, FlowLayout, Dimension)
    from java.net import URL

    from threading import Thread, Event

    import re
    import hashlib

except ImportError:
    print "Failed to load dependencies. This issue maybe caused by using an unstable Jython version."

VERSION = '0.1'

regex = [
    ("WEB_FILE", r'"([^"\s]+\.(?:js|css|html|php)+)"', True),
    ("LINK", r'"([a-zA-Z]+://[^"\s]+)"', False),
    ("IMG", r'"([^"\s]+\.(?:png|jpg|gif))"', False),
    ("AJAX_GET", r'(?:href=|get\()"([^">\s]+\?[^"]+)"', True),
    ("AJAX_FUNC", r'(?:put|get|post|ajax)\(\s*"([^"\s]+)"\s*,[^\)]+\)',
     True),  # ajaxFunc    (    "..."
    ("PAGES", r'"(/[^">\s\.\?]+)"', True),
    ("URL", r'"(/[^">\s]+)"', True),
]


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
        self._splitpane.setBorder(EmptyBorder(20, 20, 20, 20))

        # sub split pane (top)

        self._topPanel = JPanel(BorderLayout(10, 10))
        self._topPanel.setBorder(EmptyBorder(0, 0, 10, 0))

        self.setupPanel = JPanel(FlowLayout(FlowLayout.LEADING, 10, 10))

        self.hostField = JTextField('', 50)
        self.setupPanel.add(
            JLabel("Target:", SwingConstants.LEFT), BorderLayout.LINE_START)
        self.setupPanel.add(self.hostField)

        self.crawlingEvent = Event()

        self.toggleButton = JButton(
            'Start crawling', actionPerformed=self.toggleCrawl)

        self.setupPanel.add(self.toggleButton)
        self._topPanel.add(self.setupPanel, BorderLayout.PAGE_START)

        self.optionsPanel = JPanel(GridLayout(0, 2))

        self.buttonOptionsPanel = JPanel()
        self.buttonOptionsPanel.setLayout(
            BoxLayout(self.buttonOptionsPanel, BoxLayout.PAGE_AXIS))
        self.addRegexButton = JButton('Add', actionPerformed=self.addRegex)
        self.editRegexButton = JButton('Edit', actionPerformed=self.editRegex)
        self.removeRegexButton = JButton(
            'Remove', actionPerformed=self.removeRegex)
        self.buttonOptionsPanel.add(self.addRegexButton)
        self.buttonOptionsPanel.add(self.editRegexButton)
        self.buttonOptionsPanel.add(self.removeRegexButton)

        self.optionsPanel.add(self.buttonOptionsPanel)

        self.regexTableModel = RegexTableModel([x for x in regex])
        self.regexTable = Table(self.regexTableModel)
        self.regexScrollPane = JScrollPane(self.regexTable)

        self.optionsPanel.add(self.regexScrollPane)

        self._topPanel.add(self.optionsPanel, BorderLayout.CENTER)

        self._splitpane.setTopComponent(self._topPanel)

        self.logger = Logger([])
        self.logTable = Table(self.logger)
        self.scrollPane = JScrollPane(self.logTable)
        self._splitpane.setBottomComponent(self.scrollPane)
        self._splitpane.setDividerLocation(300 +
                                           self._splitpane.getInsets().left)

        callbacks.customizeUiComponent(self.scrollPane)
        callbacks.customizeUiComponent(self.setupPanel)
        callbacks.customizeUiComponent(self.regexScrollPane)
        callbacks.addSuiteTab(self)
        print "Burp SPA Explorer loaded"

        #start_new_thread(self.crawl_thread,('192.168.142.10',3000))

    # Button Actions

    def addRegex(self, event):
        optionPane = JOptionPane()
        dialog = optionPane.createDialog(self._splitpane, "Add RegEx")

        panel = JPanel(GridLayout(0, 2))
        panel.setBorder(EmptyBorder(10, 10, 10, 10))

        nameField = JTextField('', 15)
        panel.add(JLabel("Name:", SwingConstants.LEFT))
        panel.add(nameField)

        regexField = JTextField('', 15)
        panel.add(JLabel("RegEx:", SwingConstants.LEFT))
        panel.add(regexField)

        crawlField = JCheckBox()
        panel.add(JLabel("Crawl:", SwingConstants.LEFT))
        panel.add(crawlField)

        def closeDialog(event):
            if len(nameField.text) == 0 or len(regexField.text) == 0 :
                JOptionPane.showMessageDialog(self._splitpane, "Name or RegEx can't be empty","Error",JOptionPane.ERROR_MESSAGE)
                return
            self.regexTableModel.addRow(
                [nameField.text, regexField.text,
                 crawlField.isSelected()])
            dialog.hide()

        addButton = JButton('Add', actionPerformed=closeDialog)
        panel.add(addButton)

        dialog.setSize(600, 200)
        dialog.setContentPane(panel)
        self._callbacks.customizeUiComponent(dialog)
        dialog.show()

        return True

    def editRegex(self, event):
        selectedRowIdx = self.regexTable.getSelectedRow()
        if selectedRowIdx == -1: return False
        selectedRow = self.regexTableModel.data[selectedRowIdx]

        optionPane = JOptionPane()
        dialog = optionPane.createDialog(self._splitpane, "Edit RegEx")

        panel = JPanel(GridLayout(0, 2))
        panel.setBorder(EmptyBorder(10, 10, 10, 10))

        nameField = JTextField('', 15)
        nameField.text = selectedRow[0]
        panel.add(JLabel("Name:", SwingConstants.LEFT))
        panel.add(nameField)

        regexField = JTextField('', 15)
        regexField.text = selectedRow[1]
        panel.add(JLabel("RegEx:", SwingConstants.LEFT))
        panel.add(regexField)

        crawlField = JCheckBox()
        crawlField.setSelected(selectedRow[2])
        panel.add(JLabel("Crawl:", SwingConstants.LEFT))
        panel.add(crawlField)

        def closeDialog(event):
            if len(nameField.text) == 0 or len(regexField.text) == 0 :
                JOptionPane.showMessageDialog(self._splitpane, "Name or RegEx can't be empty","Error",JOptionPane.ERROR_MESSAGE)
                return
            self.regexTableModel.editRow(
                selectedRowIdx,
                [nameField.text, regexField.text,
                 crawlField.isSelected()])
            dialog.hide()

        editButton = JButton('Edit', actionPerformed=closeDialog)
        panel.add(editButton)

        dialog.setSize(600, 200)
        dialog.setContentPane(panel)
        self._callbacks.customizeUiComponent(dialog)
        dialog.show()

        return True

    def removeRegex(self, event):
        idx = self.regexTable.getSelectedRows()
        print(idx)
        for i in sorted(idx)[::-1]:
            self.regexTableModel.removeRow(i)
        return True

    # Implement ITab

    def getTabCaption(self):
        return "SPA Explorer"

    def getUiComponent(self):
        return self._splitpane

    def crawl(self, event):
        print("Starting")
        self._callbacks.includeInScope(URL(self.hostField.text))

        self.crawlingEvent.set()
        self.crawlerThread = Thread(
            target=self.crawl_thread, args=(self.hostField.text, ))
        self.crawlerThread.start()
        print("Started")

    def stopCrawling(self, event):
        if (self.crawlerThread.is_alive()):
            print("Stopping...")
            self.crawlingEvent.clear()
            self.crawlerThread.join()
            print("Crawling stopped")

    def toggleCrawl(self, event):
        if (self.crawlingEvent.is_set()):
            self.stopCrawling(event)
            self.toggleButton.setText("Start crawling")
        else:
            self.crawl(event)
            self.toggleButton.setText("Stop crawling")

    def makeRequest(self, url):

        url = URL(url)

        if not self._callbacks.isInScope(url):
            self.logger.addRow(""+url.toString()+" is out of scope")
            raise ValueError("URL is out of scope")

        prot = url.getProtocol()
        host = url.getHost()
        port = url.getPort()

        httpService = self._helpers.buildHttpService(host, port, prot)

        #print("Request",prot,host,port)

        reqRes = self._callbacks.makeHttpRequest(
            httpService, self._helpers.buildHttpRequest(url))
        self._callbacks.addToSiteMap(reqRes)
        resp = reqRes.getResponse()
        respInfo = self._helpers.analyzeResponse(resp)

        respBody = self._helpers.bytesToString(resp[respInfo.getBodyOffset():])

        #resp = 'GG\r\n\r\n'
        #print("Response",respInfo.getStatusCode(),respBody)

        return respBody

    def crawl_thread(self, host):
        # print(self, host)
        print("Hello from thread")
        self.logger.addRow("Target: " + host)

        SwingUtilities.invokeLater(
            CrawlerRunnable(self.toggleButton.setText, ("Stop crawling", )))
        SwingUtilities.invokeLater(CrawlerRunnable(self.addRegexButton.setEnabled, (False, )))
        SwingUtilities.invokeLater(CrawlerRunnable(self.editRegexButton.setEnabled, (False, )))
        SwingUtilities.invokeLater(CrawlerRunnable(self.removeRegexButton.setEnabled, (False, )))

        pageType = {}  # url -> type

        pageContentHash = {}  # hash -> url list

        #self.logger.addRow(self.makeRequest(self.hostField.text,int(self.portField.text),'/'))

        # http://192.168.142.10:3000
        def concatURL(baseURL, link):
            return URL(URL(baseURL), link).toString()

        def matchRegex(baseURL, res):
            toRet = []
            for (name, regStr, ret) in self.regexTableModel.data:
                matchObj = re.findall(regStr, res, re.M | re.I)
                for i in matchObj:
                    try:
                        #
                        #url = concatURL(baseURL,i)
                        #url = concatURL(host,i)
                        if i.find('http://') == 0 or i.find('https://') == 0:
                            url = i
                        elif i[0] == '/':
                            url = host + i
                        else:
                            url = host + '/' + i
                        #print(host,i,url)
                        if url not in pageType:
                            pageType[url] = name
                            self.logger.addRow("Found [" + name + "] " + url)
                            if ret:
                                toRet.append(url)
                    except:
                        print("Some error happened ...")
            return toRet

        def getAllLink(url):
            toRet = []
            try:
                print("Making request", url)
                r = self.makeRequest(url)
                print("Done request", len(r))
                hash = hashlib.sha256(r.encode('utf-8')).hexdigest()
                #print(r.text)
                if hash in pageContentHash:
                    print("Content hash is the same as ",
                          pageContentHash[hash][0])
                    pageContentHash[hash].append(url)
                    return toRet
                else:
                    pageContentHash[hash] = [url]

                toRet += matchRegex(url, r)
            except BaseException as e :
                print("Error while making request to ", url,e)
            except :
                print("Error while making request to ", url, "[Unknown error]")
            return toRet

        crawledPage = [host]
        crawledNow = 0

        while crawledNow < len(crawledPage):
            if self.crawlingEvent.is_set():
                print("Crawling", crawledPage[crawledNow])
                self.logger.addRow("Crawling " + crawledPage[crawledNow])
                for i in getAllLink(crawledPage[crawledNow]):
                    if i not in crawledPage:
                        print("ADD:", i)
                        crawledPage.append(i)
                crawledNow += 1
            else:
                print("Stop Requested")
                break

        print(crawledNow, crawledPage)
        output = []

        # for i in pageType:
        #    output.append((pageType[i], i))

        # for i in sorted(output):
        #     self.logger.addRow(i[0] + " " + i[1])
        #     pass

        SwingUtilities.invokeLater(
            CrawlerRunnable(self.toggleButton.setText, ("Start crawling", )))
        SwingUtilities.invokeLater(CrawlerRunnable(self.addRegexButton.setEnabled, (True, )))
        SwingUtilities.invokeLater(CrawlerRunnable(self.editRegexButton.setEnabled, (True, )))
        SwingUtilities.invokeLater(CrawlerRunnable(self.removeRegexButton.setEnabled, (True, )))
        self.crawlingEvent.clear()
        self.logger.addRow("Completed")
        print("Completed")


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
            return "Result"
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

    def removeRow(self, row):
        self.log.pop(row)
        self.fireTableRowsDeleted(row, row)


class RegexTableModel(AbstractTableModel):
    def __init__(self, regex):
        self.data = regex

    def getRowCount(self):
        try:
            return len(self.data)
        except:
            return 0

    def getColumnCount(self):
        return 3

    def getColumnName(self, columnIndex):
        return ["Name", "RegEx", "Crawl"][columnIndex]

    def getValueAt(self, rowIndex, columnIndex):
        return self.data[rowIndex][columnIndex]

    def addRow(self, row):
        self.data.append(row)
        self.fireTableRowsInserted(len(self.data) - 1, len(self.data) - 1)

    def editRow(self, rowIdx, row):
        self.data[rowIdx] = row
        self.fireTableRowsUpdated(rowIdx, rowIdx)

    def removeRow(self, row):
        self.data.pop(row)
        self.fireTableRowsDeleted(row, row)


class Table(JTable):
    def __init__(self, model):
        self.setModel(model)

    def changeSelection(self, row, col, toggle, extend):

        # show the log entry for the selected row
        # logEntry = self._extender.log[row]
        JTable.changeSelection(self, row, col, toggle, extend)


class CrawlerRunnable(Runnable):
    def __init__(self, func, args):
        self.func = func
        self.args = args

    def run(self):
        self.func(*self.args)