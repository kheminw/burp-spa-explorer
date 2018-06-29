try:
    from burp import IBurpExtender
    from burp import IScannerCheck
    from burp import IExtensionStateListener
    from burp import ITab
    from burp import IContextMenuFactory
    from burp import IContextMenuInvocation
    from burp import IHttpRequestResponse
    # from burp import IScanIssue
    # from array import array
    # from time import sleep
    from java.io import PrintWriter
    from java.lang import Runnable
    from javax.swing import (JTable, JScrollPane, JSplitPane, JButton, JPanel,
                             JTextField, JLabel, SwingConstants, JDialog, Box,
                             JCheckBox, JMenuItem, SwingUtilities, JOptionPane,
                             BoxLayout)

    from javax.swing.border import EmptyBorder
    from javax.swing.table import AbstractTableModel
    from java.awt import (GridLayout, BorderLayout, FlowLayout, Dimension)
    from java.net import URL
    from java.util import ArrayList

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

        self.crawlingEvent = Event()
        self.crawlerThread = None

        # main split pane
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._splitpane.setBorder(EmptyBorder(20, 20, 20, 20))

        # sub split pane (top)
        self._topPanel = JPanel(BorderLayout(10, 10))
        self._topPanel.setBorder(EmptyBorder(0, 0, 10, 0))

        # Setup Panel :    [Target: ] [______________________] [START BUTTON]
        self.setupPanel = JPanel(FlowLayout(FlowLayout.LEADING, 10, 10))

        self.setupPanel.add(
            JLabel("Target:", SwingConstants.LEFT), BorderLayout.LINE_START)

        self.hostField = JTextField('', 50)
        self.setupPanel.add(self.hostField)

        self.toggleButton = JButton(
            'Start crawling', actionPerformed=self.toggleCrawl)
        self.setupPanel.add(self.toggleButton)

        self._topPanel.add(self.setupPanel, BorderLayout.PAGE_START)

        # Options Panel :    [Buttons]  [          RegEx           ]
        self.optionsPanel = JPanel()
        self.optionsPanel.setLayout(
            BoxLayout(self.optionsPanel, BoxLayout.LINE_AXIS))

        # Button options panel :    [Add][Edit][Up][Down][Remove]

        self.buttonOptionsPanel = JPanel()
        self.buttonOptionsPanel.setLayout(
            BoxLayout(self.buttonOptionsPanel, BoxLayout.PAGE_AXIS))

        self.addRegexButton = JButton('Add', actionPerformed=self.addRegex)
        self.buttonOptionsPanel.add(self.addRegexButton)

        self.editRegexButton = JButton('Edit', actionPerformed=self.editRegex)
        self.buttonOptionsPanel.add(self.editRegexButton)

        self.moveRegexUpButton = JButton('Move up', actionPerformed=self.moveRegexUp)
        self.buttonOptionsPanel.add(self.moveRegexUpButton)

        self.moveRegexDownButton = JButton('Move down', actionPerformed=self.moveRegexDown)
        self.buttonOptionsPanel.add(self.moveRegexDownButton)

        self.removeRegexButton = JButton('Remove', actionPerformed=self.removeRegex)
        self.buttonOptionsPanel.add(self.removeRegexButton)

        self.buttonOptionsPanel.add(Box.createVerticalGlue())

        self.optionsPanel.add(self.buttonOptionsPanel)

        self.optionsPanel.add(Box.createHorizontalStrut(20))

        self.regexTableModel = RegexTableModel([x for x in regex])
        self.regexTable = Table(self.regexTableModel)
        self.regexScrollPane = JScrollPane(self.regexTable)

        self.optionsPanel.add(self.regexScrollPane)

        self._topPanel.add(self.optionsPanel, BorderLayout.CENTER)
        self._splitpane.setTopComponent(self._topPanel)

        # Bottom Panel
        self._bottomPanel = JPanel(BorderLayout(10, 10))
        #self._bottomPanel.setLayout(BoxLayout(self._bottomPanel,BoxLayout.PAGE_AXIS))

        # Status bar
        self.crawlStatusPanel = JPanel(FlowLayout(FlowLayout.LEADING, 10, 10))

        self.crawlStatusPanel.add(JLabel("Status: ", SwingConstants.LEFT))

        self.crawlStatusLabel = JLabel("Ready to crawl", SwingConstants.LEFT)
        self.crawlStatusPanel.add(self.crawlStatusLabel)

        # Result Table
        self.resultTableModel = Result([])
        self.resultTable = Table(self.resultTableModel)
        self.resultTable.setAutoCreateRowSorter(True)
        self.resultScrollPane = JScrollPane(self.resultTable)

        self._bottomPanel.add(self.resultScrollPane, BorderLayout.CENTER)
        self._bottomPanel.add(self.crawlStatusPanel, BorderLayout.SOUTH)

        self._splitpane.setBottomComponent(self._bottomPanel)
        self._splitpane.setDividerLocation(300 +
                                           self._splitpane.getInsets().left)

        callbacks.customizeUiComponent(self._splitpane)

        callbacks.addSuiteTab(self)

        explorerMenu = ExplorerMenu(self)
        callbacks.registerContextMenuFactory(explorerMenu)
        print "SPA Explorer custom menu loaded"

        print "Burp SPA Explorer loaded"

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
            if len(nameField.text) == 0 or len(regexField.text) == 0:
                JOptionPane.showMessageDialog(
                    self._splitpane, "Name or RegEx can't be empty", "Error",
                    JOptionPane.ERROR_MESSAGE)
                return
            self.regexTableModel.addRow(
                [nameField.text, regexField.text,
                 crawlField.isSelected()])
            dialog.hide()

        addButton = JButton('OK', actionPerformed=closeDialog)
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
            if len(nameField.text) == 0 or len(regexField.text) == 0:
                JOptionPane.showMessageDialog(
                    self._splitpane, "Name or RegEx can't be empty", "Error",
                    JOptionPane.ERROR_MESSAGE)
                return
            self.regexTableModel.editRow(
                selectedRowIdx,
                [nameField.text, regexField.text,
                 crawlField.isSelected()])
            dialog.hide()

        editButton = JButton('OK', actionPerformed=closeDialog)
        panel.add(editButton)

        dialog.setSize(600, 200)
        dialog.setContentPane(panel)
        self._callbacks.customizeUiComponent(dialog)
        dialog.show()
        return True

    def moveRegexDown(self, event):
        idxs = self.regexTable.getSelectedRows()
        if self.regexTableModel.getRowCount()-1 in idxs : return False
        
        self.regexTable.clearSelection()
        for i in sorted(idxs)[::-1] :
            self.regexTableModel.moveDown(i)
            self.regexTable.addRowSelectionInterval(i+1,i+1)
        return True

    def moveRegexUp(self, event) :
        idxs = self.regexTable.getSelectedRows()
        if 0 in idxs : return False

        self.regexTable.clearSelection()
        for i in sorted(idxs) :
            self.regexTableModel.moveUp(i)
            self.regexTable.addRowSelectionInterval(i-1,i-1)
        return True

    def removeRegex(self, event):
        idx = self.regexTable.getSelectedRows()
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

        host = self.hostField.text

        if host.find("://") == -1:
            host = "http://" + host

        try:
            self._callbacks.includeInScope(URL(host))
        except:
            JOptionPane.showMessageDialog(self._splitpane,
                                          "Can't add host to scope", "Error",
                                          JOptionPane.ERROR_MESSAGE)
            return

        self.resultTableModel.clearAllRow()

        self.crawlingEvent.set()
        self.crawlerThread = Thread(target=self.crawl_thread, args=(host, ))
        self.crawlerThread.start()
        print("Started")

    def stopCrawling(self, event):
        print("Clear event")
        self.crawlingEvent.clear()

        # Disable button
        if self.toggleButton.text == "Stop crawling" : # If button is still "Stop crawling" (Thread still running), disable button
            self.toggleButton.setEnabled(False)

    def toggleCrawl(self, event):
        if (self.crawlerThread == None or not self.crawlerThread.is_alive()):
            self.crawl(event)
            #self.toggleButton.setText("Start crawling")
        else:
            self.stopCrawling(event)
            #self.toggleButton.setText("Stop crawling")

    def crawl_thread(self, host):
        # print(self, host)
        print("Crawl thread started")

        SwingUtilities.invokeLater(
            CrawlerRunnable(self.toggleButton.setText, ("Stop crawling", )))
        SwingUtilities.invokeLater(
            CrawlerRunnable(self.addRegexButton.setEnabled, (False, )))
        SwingUtilities.invokeLater(
            CrawlerRunnable(self.editRegexButton.setEnabled, (False, )))
        SwingUtilities.invokeLater(
            CrawlerRunnable(self.removeRegexButton.setEnabled, (False, )))

        pageType = {}  # url -> type
        pageContentHash = {}  # hash -> url list

        def concatURL(baseURL, link):
            return URL(URL(baseURL), link).toString()

        def makeRequest(url):
            url = URL(url)

            if not self._callbacks.isInScope(url):
                #self.logger.addRow(url.toString()+" is out of scope")
                raise ValueError("URL is out of scope")

            prot = url.getProtocol()
            host = url.getHost()
            port = url.getPort()
            if port == -1:
                port = 80 if prot == "http" else 443

            httpService = self._helpers.buildHttpService(host, port, prot)

            reqRes = self._callbacks.makeHttpRequest(
                httpService, self._helpers.buildHttpRequest(url))
            self._callbacks.addToSiteMap(reqRes)
            resp = reqRes.getResponse()
            respInfo = self._helpers.analyzeResponse(resp)

            respBody = self._helpers.bytesToString(
                resp[respInfo.getBodyOffset():])
            return respBody

        def matchRegex(baseURL, res):
            toRet = []
            for (name, regStr, ret) in self.regexTableModel.data:
                matchObj = re.findall(regStr, res, re.M | re.I)
                for i in matchObj:
                    try:
                        if i.find('http://') == 0 or i.find('https://') == 0:
                            url = i
                        elif i[0] == '/':
                            url = host + i
                        else:
                            url = host + '/' + i

                        if url not in pageType:
                            pageType[url] = name
                            SwingUtilities.invokeLater(
                                CrawlerRunnable(self.resultTableModel.addRow,
                                                ([name, url], )))

                            if ret:
                                toRet.append(url)
                    except:
                        print("Error when trying to save result ", i,
                              sys.exc_info()[0],
                              sys.exc_info()[1])
            return toRet

        def getAllLink(url):
            toRet = []
            try:
                print("Making request", url)
                r = makeRequest(url)
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
            except BaseException as e:
                print("Error while making request to ", url, e)
            except:
                print("Error while making request to ", url,
                      sys.exc_info()[0],
                      sys.exc_info()[1])
            return toRet

        crawledPage = [host]
        crawledNow = 0

        SwingUtilities.invokeLater(
            CrawlerRunnable(self.resultTableModel.addRow,
                            (["TARGET", host], )))

        while crawledNow < len(crawledPage):
            if self.crawlingEvent.is_set():
                print("Crawling", crawledPage[crawledNow])
                SwingUtilities.invokeLater(
                    CrawlerRunnable(self.crawlStatusLabel.setText,
                                    ("Crawling " + crawledPage[crawledNow], )))
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

        SwingUtilities.invokeLater(
            CrawlerRunnable(self.toggleButton.setText, ("Start crawling", )))
        SwingUtilities.invokeLater(
            CrawlerRunnable(self.toggleButton.setEnabled, (True, )))
        SwingUtilities.invokeLater(CrawlerRunnable(self.addRegexButton.setEnabled, (True, )))
        SwingUtilities.invokeLater(CrawlerRunnable(self.editRegexButton.setEnabled, (True, )))
        SwingUtilities.invokeLater(CrawlerRunnable(self.removeRegexButton.setEnabled, (True, )))

        SwingUtilities.invokeLater(
            CrawlerRunnable(self.crawlStatusLabel.setText,
                            ("Ready to crawl", )))

        self.crawlingEvent.clear()
        print("Completed")


class Result(AbstractTableModel):

    # Implement AbstractTableModel

    def __init__(self, result):
        self.data = result

    def getRowCount(self):
        try:
            return len(self.data)
        except:
            return 0

    def getColumnCount(self):
        return 2

    def getColumnName(self, columnIndex):
        return ["Name", "URL"][columnIndex]

    def getValueAt(self, rowIndex, columnIndex):
        return self.data[rowIndex][columnIndex]

    def addRow(self, row):
        self.data.append(row)
        self.fireTableRowsInserted(len(self.data) - 1, len(self.data) - 1)

    def editRow(self, rowIdx, row):
        self.data[rowIdx] = row
        self.fireTableRowsUpdated(rowIdx, rowIdx)

    def removeRow(self, rowIdx):
        self.data.pop(rowIdx)
        self.fireTableRowsDeleted(rowIdx, rowIdx)

    def clearAllRow(self):
        dataLen = len(self.data)
        if dataLen == 0:
            return
        self.data = []
        self.fireTableRowsDeleted(0, dataLen - 1)


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

    def removeRow(self, rowIdx):
        self.data.pop(rowIdx)
        self.fireTableRowsDeleted(rowIdx, rowIdx)
    
    def moveUp(self, idx):
        if idx == 0 : return False
        [self.data[idx], self.data[idx-1]] = [self.data[idx-1],self.data[idx]]
        self.fireTableRowsUpdated(idx-1,idx)

    def moveDown(self, idx):
        if idx == self.getRowCount()-1 : return False
        [self.data[idx], self.data[idx+1]] = [self.data[idx+1],self.data[idx]]
        self.fireTableRowsUpdated(idx,idx+1)


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


class ExplorerMenu(IContextMenuFactory):
    def __init__(self, explorerInstance):
        self.explorerInstance = explorerInstance

    def createMenuItems(self, contextMenuInvocation):
        self.contextMenuInvocation = contextMenuInvocation
        print "Creating Menu"
        sendToSPAExplorer = JMenuItem(
            "Send URL to SPA Explorer", actionPerformed=self.getSentUrl)
        menuItems = ArrayList()
        menuItems.add(sendToSPAExplorer)
        return menuItems

    def getSentUrl(self, event):
        for selectedMessage in self.contextMenuInvocation.getSelectedMessages(
        ):
            if (selectedMessage.getHttpService() != None):
                try:
                    url = self.explorerInstance._helpers.analyzeRequest(
                        selectedMessage.getHttpService(),
                        selectedMessage.getRequest()).getUrl()
                    print "URL: " + url.toString()
                    self.explorerInstance.hostField.setText(url.toString())
                except:
                    self.explorerInstance._callbacks.issueAlert(
                        "Cannot get URL from the currently selected message",
                        sys.exc_info()[0],
                        sys.exc_info()[1])
            else:
                self.explorerInstance._callbacks.issueAlert(
                    "The selected request is null.")
