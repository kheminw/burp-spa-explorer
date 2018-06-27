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

    from thread import start_new_thread

    import re
    import hashlib

except ImportError:
    print "Failed to load dependencies. This issue maybe caused by using an unstable Jython version."

VERSION = '0.1'

pageType = {} # url -> type

pageContentHash = {} # hash -> url list

regex = [
    ("LINK",r'"([a-zA-Z]+://[^"]+)"', -1, False),
    ("IMG",r'"([^"/]*/[^">]+\.(png|jpg|gif))"', 0, False),
    ("FILE",r'"([^"/]*/[^">]+\.[a-zA-Z0-9]+)"', -1, True),
    ("AJAX_GET",r'(href=|get\()"([^"]*\?[^"]+)"', 1, True),
    ("AJAX_FUNC",r'(put|get|post|ajax)\("([^"/]*/[^"]+)"', 1, True), # ajaxFunc    (    "..."
    ("PAGES",r'"(/[^">\.\?]+)"', -1, True),
    ("HREF",r'href="([^"]+)"', -1, False),
]

def matchRegex(res) :
    toRet = []
    for (name,regStr,groupNo, ret) in regex :
        matchObj =  re.findall( regStr, res, re.M|re.I)
        #print("MATCH",regStr,res[:40],matchObj)
        for i in matchObj :
            if not isinstance(i,unicode) :
                url = i[groupNo]
            else :
                url = i
            #print(url[:40],name)
            if url not in pageType :
                pageType[url] = name
                if ret :
                    toRet.append(url)
    return toRet


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
        
        self.portField = JTextField('', 15)
        self.setupPanel.add(JLabel("Port:", SwingConstants.LEFT))
        self.setupPanel.add(self.portField)

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
        
        #start_new_thread(self.crawl_thread,('192.168.142.10',3000))

    # Implement ITab

    def getTabCaption(self):
        return "SPA Explorer"

    def getUiComponent(self):
        return self._splitpane

    def crawl(self, event):
        start_new_thread(self.crawl_thread,(self.hostField.text,int(self.portField.text)))

    def makeRequest(self,host,port,page):
        
        #print("Request",host,port,page)

        page2 = page
        
        resp = self._callbacks.makeHttpRequest(host,port,False,bytearray((u"GET /"+page2+u" HTTP/1.1\r\n\r\n").encode('utf-8')))
        resp = self._helpers.bytesToString(resp)
        #resp = 'GG\r\n\r\n'
        #print("Response",resp)

        return resp[resp.find('\r\n\r\n')+4:]

    def crawl_thread(self,host,port):
        print("Thread begin")
        #self.logger.addRow(self.makeRequest(self.hostField.text,int(self.portField.text),'/'))
                
        def getAllLink(page) :
            toRet = []
            r = self.makeRequest(host,port,page)
            hash = hashlib.sha256(r.encode('utf-8')).hexdigest()
            #print(r.text)
            if hash in pageContentHash :
                #print("Content hash is the same as ",pageContentHash[hash][0])
                pageContentHash[hash].append(page)
            else :
                pageContentHash[hash] = [page]
            
            toRet += matchRegex(r)
            return toRet
                
        crawledPage = [u'/']
        crawledNow = 0
        

        while crawledNow < len(crawledPage) :
            print("Crawling %s",crawledPage[crawledNow])
            self.logger.addRow(crawledPage[crawledNow])
            for i in getAllLink(crawledPage[crawledNow]) :
                if i not in crawledPage :
                    print("ADD:",i)
                    crawledPage.append(i)
            crawledNow += 1
            #break
            
        print(crawledNow,crawledPage)
        output = []
            
        for i in pageType :
            output.append((pageType[i],i))

        for i in sorted(output) :
            #self.logger.addRow(i[0]+" "+i[1])
            pass



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