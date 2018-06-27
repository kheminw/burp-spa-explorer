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
    
    from java.net import URL
    
    from thread import start_new_thread

    import re
    import hashlib

except ImportError:
    print "Failed to load dependencies. This issue maybe caused by using an unstable Jython version."

VERSION = '0.1'

pageType = {} # url -> type

pageContentHash = {} # hash -> url list

regex = [
    ("WEB_FILE",r'"([^"\s]+\.(?:js|css|html|php)+)"', True),
    ("LINK",r'"([a-zA-Z]+://[^"\s]+)"', False),
    ("IMG",r'"([^"\s]+\.(?:png|jpg|gif))"', False),
    ("STATIC_FILE",r'"([^">\s]+\.[a-zA-Z0-9]+)"', False),
    ("AJAX_GET",r'(?:href=|get\()"([^">\s]+\?[^"]+)"', True),
    ("AJAX_FUNC",r'(?:put|get|post|ajax)\(\s*"([^"\s]+)"\s*,[^\)]+\)', True), # ajaxFunc    (    "..."
    ("PAGES",r'"(/[^">\s\.\?]+)"', True),
    ("URL",r'"(/[^">\s]+)"', True),
    ("HREF",r'href="([^>\s]+)"', True),
    ("SRC",r'src="([^>\s]+)"', True),
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

        self.setupPanel = JPanel(GridLayout(0, 2))

        self.hostField = JTextField('', 15)
        self.setupPanel.add(JLabel("Target:", SwingConstants.LEFT))
        self.setupPanel.add(self.hostField)

        self.regexField = JTextField('', 15)
        self.setupPanel.add(JLabel("Regex:", SwingConstants.LEFT))
        self.setupPanel.add(self.regexField)

        self.startButton = JButton(
            'Start crawling', actionPerformed=self.crawl)
        self.setupPanel.add(self.startButton)

        self._splitpane.setTopComponent(self.setupPanel)

        self.logger = Logger([])
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
        start_new_thread(self.crawl_thread,(self.hostField.text,))

    def makeRequest(self,url):
        
        url = URL(url)
        
        if not self._callbacks.isInScope(url) :
            raise ValueError("URL is out of scope")
        
        prot = url.getProtocol()
        host = url.getHost()
        port = url.getPort()
        
        httpService = self._helpers.buildHttpService(host,port,prot)
        
        
        
        #print("Request",prot,host,port)

        reqRes = self._callbacks.makeHttpRequest(httpService,self._helpers.buildHttpRequest(url))
        resp = reqRes.getResponse()
        respInfo = self._helpers.analyzeResponse(resp)
        
        respBody = self._helpers.bytesToString(resp[respInfo.getBodyOffset():])
        
        #resp = 'GG\r\n\r\n'
        #print("Response",respInfo.getStatusCode(),respBody)
        
        return respBody
    
    
    
    def crawl_thread(self,host):
        self.logger.addRow("Target: "+host)
        #self.logger.addRow(self.makeRequest(self.hostField.text,int(self.portField.text),'/'))
                
        # http://192.168.142.10:3000
        def concatURL(baseURL,link) :
            return URL(URL(baseURL),link).toString();
        
        def matchRegex(baseURL,res) :
            toRet = []
            for (name,regStr, ret) in regex :
                matchObj =  re.findall( regStr, res, re.M|re.I)
                for i in matchObj :
                    try :
                        # 
                        #url = concatURL(baseURL,i)
                        #url = concatURL(host,i)
                        url = host + i
                        #print(host,i,url)
                        if url not in pageType :
                            pageType[url] = name
                            if ret :
                                toRet.append(url)
                    except :
                        print("Some error happened ...")
            return toRet
        
        def getAllLink(url) :
            toRet = []
            try :
                r = self.makeRequest(url)
                hash = hashlib.sha256(r.encode('utf-8')).hexdigest()
                #print(r.text)
                if hash in pageContentHash :
                    print("Content hash is the same as ",pageContentHash[hash][0])
                    pageContentHash[hash].append(url)
                    return toRet
                else :
                    pageContentHash[hash] = [url]
                
                toRet += matchRegex(url,r)
            except Exception as e :
                print("Error while making request to ",url,e)
            return toRet
                
        crawledPage = [host]
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
            self.logger.addRow(i[0]+" "+i[1])
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