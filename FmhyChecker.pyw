import grequests
import requests
from fake_headers import Headers
import sys
import os
import re
from threading import Thread, Event
from contextlib import suppress
from pyperclip import copy
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import pyqtSignal
from PyQt5 import uic
from PyQt5.QtWidgets import QMainWindow
from requests.exceptions import ReadTimeout, ConnectionError
import time
import csv
import darkdetect
from base64 import b64decode
import ctypes as ct
from queue import Queue
from dataclasses import dataclass
from http.client import responses as status_codes
from typing import Union


# fake headers
headers = Headers()
# use Queue to limit number of concurrent requests
dist_cnxns = Queue(maxsize=3)
# check for dark mode
DARK_MODE = darkdetect.isDark()

def resource_path(relative_path):
    # wrapper to retrieve the absolute path from a relative path
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.dirname(__file__)
    return os.path.join(base_path, relative_path)


@dataclass
class StatusResp:
    url: str
    status_code: Union[int, str]
    reason: str
    history: list


class LinkTest:
    chunk_size = 50  # number of links to test at once
    statusapi_url = b64decode('aHR0cHM6Ly9iYWNrZW5kLmh0dHBzdGF0dXMuaW8vYXBp').decode()
    statusapi_headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.5',
        # 'Accept-Encoding': 'gzip, deflate, br',
        'Referer': b64decode('aHR0cHM6Ly9odHRwc3RhdHVzLmlvLw==').decode(),
        'Content-Type': 'application/json;charset=utf-8',
        'Origin': b64decode('aHR0cHM6Ly9odHRwc3RhdHVzLmlv').decode(),
        'DNT': '1',
        'Connection': 'keep-alive',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-site',
    }
    statusapi_data = {
        'urls': None,
        'userAgent': 'browser',
        'userName': '', 'passWord': '', 'headerName': '', 'headerValue': '',
        'strictSSL': True,
        'canonicalDomain': False,
        'additionalSubdomains': ['www',],
        'followRedirect': True,
        'throttleRequests': 100,
        'escapeCharacters': False,
    }

    @staticmethod
    def handle_req(urls, items, callback, error_sig):
        # process the request & send back to main event loop
        dist_cnxns.put(1)  # wait for when <40 requests are running. blocks if full
        for item in items:
            item.setText(2, 'Testing...')
        try:
            resp = requests.post(
                LinkTest.statusapi_url,
                headers={**LinkTest.statusapi_headers, **headers.generate()},
                json={**LinkTest.statusapi_data, 'urls': urls},
            )
            data = resp.json()
        except (ReadTimeout, ConnectionError):
            error_sig('Connection timed out. Please check your internet connection and try again.')
        except Exception as e:
            error_sig(f'An unknown error occurred. Please try again.\n\n{e}')
        for (item, url, resp) in zip(items, urls, data):
            try:
                callback(item, LinkTest.build_status_resp(resp, url))
            except Exception as e:
                print('Error:', e, resp)
        dist_cnxns.get()  # release next in queue

    @staticmethod
    def build_status_resp(resp, url=None) -> StatusResp:
        return StatusResp(
            url          = url or resp.get('url', 'Failed'),
            status_code  = resp['statusCode'] if type(resp.get('statusCode')) is int else 0,
            reason       = resp.get('errorMessage') or status_codes[resp['statusCode']],
            history      = [LinkTest.build_status_resp(r)
                            for r in resp.get('fullRedirectChain', [])],
        )

    @staticmethod
    def async_request(*args):
        thread = Thread(target=LinkTest.handle_req, args=args, daemon=True)
        # spawn thread to handle request
        thread.start()


class UI(QMainWindow):
    checkLinks_callback = pyqtSignal()  # signal to callback checkLinks if it was called but already running
    finish_test_sig = pyqtSignal(object, StatusResp)  # signal to call finishTest
    error_sig = pyqtSignal(str)  # signal to call error_msg
    # regex for slicing links into groups ( <protocol://> <domain/path> <?leading info> )
    # i only check if group 1 is in the wiki to determine if the link is unique, then add the full link
    grouped_wiki_regex = re.compile(r'((?:https?|ftp|file):\/\/(?:ww(?:w|\d+)\.)?)((?:[\w_-]+(?:\.[\w_-]+)+)[\w.,@?^=%&:\/~+#-]*[\w@?^=%&~+-])')
    
    def __init__(self):
        super(UI, self).__init__()
        uic.loadUi(resource_path('MainWindow.ui'), self)
        
        self.setWindowIcon(QtGui.QIcon(resource_path('assets/icon.ico')))
        # palette coloring
        if DARK_MODE:
            self._highlight_col = QtGui.QColor(157, 93, 24)
            dark_palette()
            dark_title_bar(int(self.winId()))
            self.outputTree.setFont(self.inputBox.font())
        else:
            self._highlight_col = QtGui.QColor(255, 128, 0)
        
        # set up main window (hide elements, set column widths, etc.)
        self.checkSelected.setVisible(False)
        self.progressBarFrame.setVisible(False)
        self.outputTree.header().setSectionsMovable(False)
        self.outputTree.setColumnWidth(0, 50)
        self.outputTree.setColumnWidth(1, 180)
        # allow multiple selection
        self.outputTree.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        
        # status code font
        self.status_font = QtGui.QFont()
        self.status_font.setFamily("Calibri")
        self.status_font.setPointSize(10)
        
        # status code colors
        self.status_colors = {
            range(200, 300): '#31cd64',
            range(300, 400): '#33a7ff',
            range(400, 500): '#fda92a',
            range(500, 600): '#fc4f52',
        }
        self.reason_colors = {
            # default is #A12729
            'Forbidden': '#1D2870',
            'Blocked': '#1D2870',
            'Method Not Allowed': '#1D2870',
            'Timeout': '#781C1E'
        }
 
        # connections
        self.copyDupes.clicked.connect(lambda: copy('\n'.join(self.duped_links)))
        self.copyValid.clicked.connect(lambda: copy('\n'.join(self.valid_links)))
        self.copyTested.clicked.connect(lambda: copy('\n'.join(self.getTestedLinks())))
        self.exportCsv.clicked.connect(self.exportCsvDialog)
        self.checkSelected.clicked.connect(self.test_selected_links)
        self.inputBox.textChanged.connect(self.checkLinks)
        self.outputTree.itemSelectionChanged.connect(self.onSelection)
        # signals
        self.finish_test_sig.connect(self.finishTest)
        self.checkLinks_callback.connect(self.checkLinks)
        self.error_sig.connect(error_msg)
        
        self.testing_items = set()
        self.tested_items = {}
        self._is_free = Event()
        self._is_free.set()
        self.line_thread = None
        self._new_event = False
        
        self.retranslateUi()
        splash.hide()
        self.show()
    
    # csv exporting
    def exportCsvDialog(self):
        file_dialog = QtWidgets.QFileDialog()
        file_dialog.setAcceptMode(QtWidgets.QFileDialog.AcceptSave)
        file_dialog.setNameFilter("CSV (*.csv)")
        file_dialog.setDefaultSuffix("csv")
        # show dialog
        if not file_dialog.exec_():
            return
        file_path = file_dialog.selectedFiles()[0]
        links = re.findall(self.grouped_wiki_regex, self.inputBox.toPlainText())
        try:
            with open(file_path, 'w', newline='') as csvfile:
                self.writeCsvFile(csvfile, links)
        except PermissionError:
            QtWidgets.QMessageBox.critical(self.centralwidget, "Error", "File permission denied.")
    
    def writeCsvFile(self, csvfile, links):
        # write links to csv file
        writer = csv.writer(csvfile, dialect='excel', quoting=csv.QUOTE_MINIMAL)
        # csv header
        writer.writerow(['Request URL', 'Final URL', 'Unique?', '# Redirects', 'Status', 'Reason'])
        for link in links:
            full_link = ''.join(link)
            if full_link in self.tested_items:
                # if the response was a message
                if type(self.tested_items[full_link]) is str:
                    # set values to blank, and reason to message
                    final_url = redirects = status_code = ''
                    reason = self.tested_items[full_link]
                else:
                    # get the number of redirects
                    redirects = str(len(self.tested_items[full_link].history))
                    # get the reason for the status code
                    reason = self.tested_items[full_link].reason
                    # hyperlink status codes to the final url. chain together redirects with ' > '
                    status_code = '=CONCAT('+', " > ", '.join(
                        f'HYPERLINK("{r.url}", "{r.status_code}")'
                        for r in self.tested_items[full_link].history
                    )+')'
                    final_url = self.tested_items[full_link].url
            else:
                # if the link was not tested, set values to blank
                reason = redirects = final_url = status_code = ''
            # write row to csv
            writer.writerow([
                re.sub(r'[^\x00-\x7F]+', '?', full_link),  # remove non ascii characters
                final_url,
                redirects,
                'FALSE' if link[1] in wiki else 'TRUE',
                redirects,
                status_code,
                reason
            ])
    
    # return a list of unique links that have 200 status codes
    def getTestedLinks(self) -> list:
        return [
            l for l in self.tested_items
                # if link is valid and not a message
                if l in self.valid_links and type(self.tested_items[l]) is not str
                # and status code was OK
                and self.tested_items[l].status_code in range(200, 300)
            ]
    
    # add the status code chain to the tree
    def finishTest(self, item, resp):
        # remove from testing items, and add the resp to tested items
        if resp.url in self.testing_items:
            self.testing_items.remove(resp.url)
            self.tested_items[resp.url] = resp
            self.copyTested.setEnabled(True)
        # check if the tree item was deleted
        try:
            item.text(2)
        except RuntimeError:
            return  # item was deleted
        # create a new horizontal layout for the status code chain
        widget = QtWidgets.QWidget()
        widget.setLayout(layout := QtWidgets.QHBoxLayout())
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)
        layout.setAlignment(QtCore.Qt.AlignLeft)
        # add layout to the tree item
        self.outputTree.setItemWidget(item, 2, widget)
        item.setText(2, "")  # remove the loading text
        # add the status code chain
        for r in resp.history or (resp,):
            color = next((self.status_colors[k] for k in self.status_colors if r.status_code in k), '#781C1E')
            text = str(r.status_code) if r.status_code else 'Error'
            text2 = r.reason
            tooltip = f'{r.reason} | {r.url}'
            self.add_status_label(layout, text, text2, color, tooltip)
    
    def add_status_label(self, layout, text, text2, color, tooltip=None):
        # add label to the layout
        label = QtWidgets.QLabel(text)
        # create lighter color for hover
        light_color = QtGui.QColor(color).lighter().name()
        label.setStyleSheet(f'''
            * {{
                background-color: {color};
                color: white;
                border-radius: 6px;
                padding: 0px 2px;
            }}
            QLabel:hover:!pressed {{
                border: 2px solid {light_color};
            }}
            ''')
        label.setMouseTracking(True)
        # change text to text2 on hover
        label.enterEvent = lambda e: label.setText(text2)
        label.leaveEvent = lambda e: label.setText(text)
        label.setFont(self.status_font)
        if tooltip:
            label.setToolTip(tooltip)
            label.setToolTipDuration(-1)
        layout.addWidget(label)
                
    def test_selected_links(self):
        # get selected tree items
        selected = self.getRanItems()
        self.testing_items.update([i.text(1) for i in selected])  # remember tested items
        # set to "Queued"
        for item in selected:
            item.setText(2, "Queued")
        self.outputTree.clearSelection()
        self.checkSelected.setVisible(False)
        # send requests
        for index in range(0, len(selected), LinkTest.chunk_size):
            items = selected[index:index+LinkTest.chunk_size]
            urls = [item.text(1) for item in items]
            try:
                LinkTest.async_request(urls, items, self.finish_test_sig.emit, self.error_sig.emit)
            except RuntimeError:
                return  # item was deleted
            QtWidgets.QApplication.processEvents()  # allow GUI to update
        
    def getRanItems(self) -> list:
        # return a list of selected items that have not been tested
        return [i for i in self.outputTree.selectedItems()
                if i.text(1) not in {*self.tested_items, *self.testing_items}]
        
    def onSelection(self):
        # when an untested tree item is selected, show the "Test" button
        if selected := self.getRanItems():
            self.checkSelected.setText(QtCore.QCoreApplication.translate("MainWindow", f"Test ({len(selected)}) \U0001F50D"))
            self.checkSelected.setVisible(True)
        else:
            self.checkSelected.setVisible(False)
 
    def _waitForEvent(self):
        # if checkLinks was already running, wait for it to complete then call it back
        self._new_event = True
        self._is_free.wait()
        self.checkLinks_callback.emit()
 
    def checkLinks(self):
        # only allow one instance of checkLinks to run
        if not self._is_free.is_set():
            if self.line_thread and self.line_thread.is_alive():
                return
            self.line_thread = Thread(target=self._waitForEvent, daemon=True)
            self.line_thread.start()
            return
        self._is_free.clear()
        # get the text from the input box
        text = self.inputBox.toPlainText()
        if text:
            self.inputBox.setPlaceholderText('')
        else:
            self.inputBox.setPlaceholderText(self._placeholderText)
        self.outputTree.clear()
        # disable buttons while running
        self.copyValid.setEnabled(False)
        self.copyDupes.setEnabled(False)
        self.copyTested.setEnabled(False)
        self.exportCsv.setEnabled(False)
        self.checkSelected.setVisible(False)
        # get all links from the input text using regex
        links = re.findall(self.grouped_wiki_regex, text)
        self.valid_links, self.duped_links, self.tested_links = [], [], []
        # enable progress bar
        self.progressBar.setMaximum(len(links))
        self.progressBar.setValue(0)
        self.progressBarFrame.setVisible(True)
        self.outputTree.setVisible(False)  # hide the treeview while updating for performance
        # populate tree
        for n, link in enumerate(links):
            if self._new_event:
                self._new_event = False
                self._is_free.set()
                return
            # create new tree item
            item = QtWidgets.QTreeWidgetItem(self.outputTree)
            full_link = ''.join(link)
            item.setText(1, full_link)
            # process in chunks to allow for UI updates
            if len(links) > 100 and not n % 100:
                self.progressBar.setValue(n)
                QtWidgets.QApplication.processEvents()
            # add item to tree
            with suppress(RuntimeError):
                if full_link in self.tested_items:
                    # if the link was already tested, use the previous result
                    self.finishTest(item, self.tested_items[full_link])
                elif full_link in self.testing_items:
                    # if the link is currently being tested, indicate "Testing..."
                    item.setText(2, "Testing...")
                if link[1] in wiki:
                    # if link is in the wiki
                    item.setText(0, "\u274C")
                    for _ in range(3):
                        item.setBackground(_, self._highlight_col)
                    self.duped_links.append(full_link)
                else:
                    # if link is NOT in the wiki
                    item.setText(0, "\u2705")
                    self.valid_links.append(full_link)
        # show finished tree
        self.outputTree.setVisible(True)
        self.progressBarFrame.setVisible(False)
        # toggle buttons
        self.copyValid.setEnabled(bool(self.valid_links))
        self.copyDupes.setEnabled(bool(self.duped_links))
        self.copyTested.setEnabled(bool(self.getTestedLinks()))
        self.exportCsv.setEnabled(True)
        # free the next checkLinks call
        self._is_free.set()
 
    def retranslateUi(self):
        # set text (with translations)
        _translate = QtCore.QCoreApplication.translate
        self.setWindowTitle(_translate("MainWindow", "Dupe Checker v1.16.1"))
        self.label.setText(_translate("MainWindow", "FMHY Dupe Tester"))
        self.label_2.setText(_translate("MainWindow", "by cevoj"))
        self._placeholderText = _translate("MainWindow", "Paste a list of links here...")
        self.inputBox.setPlaceholderText(self._placeholderText)
        self.copyValid.setText(_translate("MainWindow", "Copy \u2705"))
        self.copyDupes.setText(_translate("MainWindow", "Copy \u274C"))
        self.copyTested.setText(_translate("MainWindow", "Copy \U0001F50D"))
        self.checkSelected.setText(_translate("MainWindow", "Test \U0001F50D"))
        self.outputTree.headerItem().setText(0, _translate("MainWindow", "Check"))
        self.outputTree.headerItem().setText(1, _translate("MainWindow", "Link"))
        self.outputTree.headerItem().setText(2, _translate("MainWindow", "Status"))


def dark_title_bar(hwnd):
    if (
        sys.platform != 'win32'
        or (version_num := sys.getwindowsversion()).major != 10
    ):
        return
    set_window_attribute = ct.windll.dwmapi.DwmSetWindowAttribute
    if version_num.build >= 22000: # windows 11
        color = ct.c_int(0x2d2319)
        set_window_attribute(hwnd, 35, ct.byref(color), ct.sizeof(color))
    else:
        rendering_policy = 19 if version_num.build < 19041 else 20 # 19 before 20h1
        value = ct.c_int(True)
        set_window_attribute(hwnd, rendering_policy, ct.byref(value), ct.sizeof(value))


def dark_palette():
    # create darker palette with Fusion style
    app.setStyle('Fusion')
    palette = QtGui.QPalette()
    palette.setColor(QtGui.QPalette.Window, QtGui.QColor(25,35,45))
    palette.setColor(QtGui.QPalette.Light, QtGui.QColor(39, 49, 58))
    palette.setColor(QtGui.QPalette.Dark, QtGui.QColor(39, 49, 58))
    palette.setColor(QtGui.QPalette.WindowText, QtCore.Qt.white)
    palette.setColor(QtGui.QPalette.Base, QtGui.QColor(39, 49, 58))
    palette.setColor(QtGui.QPalette.AlternateBase, QtGui.QColor(25,35,45))
    palette.setColor(QtGui.QPalette.ToolTipBase, QtCore.Qt.white)
    palette.setColor(QtGui.QPalette.ToolTipText, QtCore.Qt.white)
    palette.setColor(QtGui.QPalette.Text, QtCore.Qt.white)
    palette.setColor(QtGui.QPalette.Button, QtGui.QColor(25,35,45))
    palette.setColor(QtGui.QPalette.ButtonText, QtCore.Qt.white)
    palette.setColor(QtGui.QPalette.BrightText, QtCore.Qt.blue)
    palette.setColor(QtGui.QPalette.Highlight, QtGui.QColor(20, 129, 216))
    palette.setColor(QtGui.QPalette.HighlightedText, QtCore.Qt.white)
    app.setPalette(palette)


class WikiScraper:
    # regex for scraping links from wikis (links must include leading http(s)://)
    wiki_regex = re.compile(r'(?:https?|ftp|file):\/\/(?:ww(?:w|\d+)\.)?((?:[\w_-]+(?:\.[\w_-]+)+)[\w.,@?^=%&:\/~+#-]*[\w@?^=%&~+-])')
    # regex for scraping lists of urls (for links not including http(s)://)
    list_regex = re.compile(r'^[\w]*\.[\w.,@?^=%&:\/~+#-]*[\w@?^=%&~+-]', re.MULTILINE)
    # regex for scraping base64 encoded links
    b64_regex = re.compile(r'`aHR0(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/][AQgw]==|[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=)?`')
    
    '''
    FOR ANYONE IN THE FUTURE TRYING TO MAINTAIN THIS
    you can add new urls to scrape by adding new key-value pairs to the dict below
    <url> : <tuple of functions to handle the response text>
    '''
    def __init__(self):
        self.URLS = {
            'https://raw.githubusercontent.com/nbats/FMHYedit/main/single-page': (self.handle_wiki, self.handle_b64),
            'https://gitlab.com/nbatman_/deleted-links/-/raw/main/deleted-links': (self.handle_list,),
        }

    def build_wiki_set(self) -> set:
        elapsed = time.perf_counter()
        try:
            resps = grequests.map([grequests.get(l) for l in self.URLS], size=len(self.URLS))
        except ConnectionError:
            # show connection error
            splash.hide()
            self.error_msg("Could not connect to the internet. Please check your connection and try again.")
        wiki = set()
        for resp, funcs in zip(resps, self.URLS.values()):
            for func in funcs:
                wiki.update(func(resp.text))

        print(f'Wiki scraped in {time.perf_counter() - elapsed:0.4f} sec. Found {len(wiki)} links.')
        return wiki
    
    @staticmethod
    def from_regex(regex, text) -> set:
        return set(re.findall(regex, text))
    
    def handle_wiki(self, text) -> set:
        return self.from_regex(self.wiki_regex, text)
    
    def handle_list(self, text) -> set:
        return self.from_regex(self.list_regex, text)
    
    def handle_b64(self, text) -> set:
        data = '\n'.join(
            b64decode(m.strip('`')).decode()
            for m in re.findall(self.b64_regex, text)
        )
        return self.handle_list(data)

def error_msg(text):
    # build error message
    msg = QtWidgets.QMessageBox()
    msg.setIcon(QtWidgets.QMessageBox.Critical)
    msg.setText(text)
    msg.setWindowIcon(QtGui.QIcon(resource_path('assets/icon.ico')))
    msg.setWindowTitle("Connection Error")
    if DARK_MODE:
        dark_title_bar(int(msg.winId()))
    msg.exec_()
    exit(1)


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)

    # set splash screen
    splash_icon = QtGui.QPixmap(resource_path('assets/splash.svg'))
    splash = QtWidgets.QSplashScreen(splash_icon, QtCore.Qt.WindowStaysOnTopHint)
    splash.show()
    wiki = WikiScraper().build_wiki_set()

    fonts_dir = resource_path('assets/fonts')
    for f in os.listdir(fonts_dir):
        QtGui.QFontDatabase.addApplicationFont(os.path.join(fonts_dir, f))
    MainWindow = QMainWindow()
    window = UI()
    sys.exit(app.exec_())
 