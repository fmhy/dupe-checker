import grequests
import requests
from fake_headers import Headers
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


# fake headers
headers = Headers(headers=True)
# use queues to keep track of connection pools
dist_cnxns = Queue(maxsize=50)


def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.dirname(__file__)
    return os.path.join(base_path, relative_path)

def handle_req(url, item, callback):
    dist_cnxns.put(1)
    item.setText(2, 'Testing...')
    try:
        resp = requests.head(url, headers=headers.generate(), timeout=10, allow_redirects=True)
        if resp is None: resp = 'Failed'
    except ReadTimeout:
        callback(url, 'Timeout', item)
    except ConnectionError:
        callback(url, 'Error', item)
    except Exception as e:
        callback(url, str(e), item)
    else:
        if resp.status_code != 200:
            resp = resp.reason or 'Unknown'
        callback(url, resp, item)
    dist_cnxns.get()

def async_request(*args):
    thread = Thread(target=handle_req, args=args, daemon=True)
    thread.start()


class UI(QMainWindow):
    group_url_regex = re.compile(r'((?:https?|ftp|file):\/\/(?:ww(?:w|\d+)\.)?)((?:[\w_-]+(?:\.[\w_-]+)+)[\w.,@?^=%&:\/~+#-]*[\w@?^=%&~+-])')
    call_back_checkLinks = pyqtSignal()
    http_test_sig = pyqtSignal(str, object, object)
    
    def __init__(self):
        super(UI, self).__init__()
        uic.loadUi(resource_path('MainWindow.ui'), self)
        
        self.setWindowIcon(QtGui.QIcon(resource_path('assets\\icon.ico')))
        if darkdetect.isDark():
            self._highlight_col = QtGui.QColor(157, 93, 24)
            dark_palette()
            dark_title_bar(int(self.winId()))
            self.outputTree.setFont(self.inputBox.font())
        else:
            self._highlight_col = QtGui.QColor(255, 128, 0)
        
        self.checkSelected.setVisible(False)
        self.progressBarFrame.setVisible(False)
        self.outputTree.header().setSectionsMovable(False)
        self.outputTree.setColumnWidth(0, 50)
        self.outputTree.setColumnWidth(1, 180)
        
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
        self.checkSelected.clicked.connect(self._testSelectedLinks)
        self.inputBox.textChanged.connect(self.checkLinks)
        self.outputTree.itemSelectionChanged.connect(self.onSelection)
        self.http_test_sig.connect(self.finishTest)
        self.call_back_checkLinks.connect(self.checkLinks)
        
        self.testing_items = set()
        self.tested_items = {}
        self._is_free = Event()
        self._is_free.set()
        self.line_thread = None
        self._new_event = False
 
        self.retranslateUi()
        splash.hide()
        self.show()
    
    def exportCsvDialog(self):
        file_dialog = QtWidgets.QFileDialog()
        file_dialog.setAcceptMode(QtWidgets.QFileDialog.AcceptSave)
        file_dialog.setNameFilter("CSV (*.csv)")
        file_dialog.setDefaultSuffix("csv")
        # show dialog
        if not file_dialog.exec_():
            return
        file_path = file_dialog.selectedFiles()[0]
        links = re.findall(self.group_url_regex, self.inputBox.toPlainText())
        try:
            with open(file_path, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile, dialect='excel', quoting=csv.QUOTE_MINIMAL)
                writer.writerow(['Request URL', 'Final URL', 'Unique?', '# Redirects', 'Status', 'Reason'])
                for link in links:
                    full_link = ''.join(link)
                    if full_link in self.tested_items:
                        if type(self.tested_items[full_link]) is str:
                            redirects = status_code = ''
                            reason = self.tested_items[full_link]
                            final_url = ''
                        else:
                            redirects = str(len(self.tested_items[full_link].history))
                            reason = self.tested_items[full_link].reason
                            status_code = '=CONCAT('+', " > ", '.join(
                                f'HYPERLINK("{r.url}", "{r.status_code}")'
                                for r in (
                                    *self.tested_items[full_link].history,
                                    self.tested_items[full_link])
                            )+')'
                            final_url = self.tested_items[full_link].url
                    else:
                        reason = redirects = final_url = status_code = ''
                    writer.writerow([
                        re.sub(r'[^\x00-\x7F]+', '?', full_link),  # remove non ascii characters
                        final_url,
                        redirects,
                        'FALSE' if link[1] in wiki else 'TRUE',
                        redirects,
                        status_code,
                        reason
                    ])
        except PermissionError:
            QtWidgets.QMessageBox.critical(self.centralwidget, "Error", "File permission denied.")
    
    def getTestedLinks(self):
        return [
            l for l in self.tested_items
                if l in self.valid_links and type(self.tested_items[l]) is not str
                and self.tested_items[l].status_code in range(200, 300)
            ]
    
    def finishTest(self, url, resp, item):
        if url in self.testing_items:
            self.testing_items.remove(url)
            self.tested_items[url] = resp
            self.copyTested.setEnabled(True)
        try:
            item.text(2)
        except RuntimeError:
            return  # item was deleted
        widget = QtWidgets.QWidget()
        widget.setLayout(layout := QtWidgets.QHBoxLayout())
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)
        layout.setAlignment(QtCore.Qt.AlignLeft)
        self.outputTree.setItemWidget(item, 2, widget)
        item.setText(2, "")
        if type(resp) is str:
            label = QtWidgets.QLabel(f' {resp} ')
            label.setFont(self.status_font)
            color = self.reason_colors.get(resp, '#A12729')
            label.setStyleSheet(f'background-color: {color}; color: white; border-radius: 6px;')
            layout.addWidget(label)
            return
        for r in (*resp.history, resp):
            label = QtWidgets.QLabel(f" {r.status_code} ")
            color = next((self.status_colors[k] for k in self.status_colors if r.status_code in k), '#000000')
            label.setStyleSheet(f'background-color: {color}; color: white; border-radius: 6px;')
            label.setToolTip(r.url)
            label.setToolTipDuration(-1)
            label.setFont(self.status_font)
            layout.addWidget(label)
    
    def _testSelectedLinks(self):
        selected = self.getRanItems()
        self.testing_items.update([i.text(1) for i in selected])  # remember tested items
        for item in selected:
            item.setText(2, "Queued")
        self.outputTree.clearSelection()
        self.checkSelected.setVisible(False)
        for item in selected:
            async_request(item.text(1), item, self.http_test_sig.emit)
            QtWidgets.QApplication.processEvents()  # allow GUI to update
        
    def getRanItems(self):
        return [i for i in self.outputTree.selectedItems()
                if i.text(1) not in {*self.tested_items, *self.testing_items}]
        
    def onSelection(self):
        if selected := self.getRanItems():
            self.checkSelected.setText(QtCore.QCoreApplication.translate("MainWindow", f"Test ({len(selected)}) \U0001F50D"))
            self.checkSelected.setVisible(True)
        else:
            self.checkSelected.setVisible(False)
 
    def _waitForEvent(self):
        self._new_event = True
        self._is_free.wait()
        self.call_back_checkLinks.emit()
 
    def checkLinks(self):
        if not self._is_free.is_set():
            if self.line_thread and self.line_thread.is_alive():
                return
            self.line_thread = Thread(target=self._waitForEvent, daemon=True)
            self.line_thread.start()
            return
        self._is_free.clear()
        text = self.inputBox.toPlainText()
        if text:
            self.inputBox.setPlaceholderText('')
        else:
            self.inputBox.setPlaceholderText(self._placeholderText)
        self.outputTree.clear()
        self.copyValid.setEnabled(False)
        self.copyDupes.setEnabled(False)
        self.copyTested.setEnabled(False)
        self.exportCsv.setEnabled(False)
        self.checkSelected.setVisible(False)
        
        links = re.findall(self.group_url_regex, text)
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
            item = QtWidgets.QTreeWidgetItem(self.outputTree)
            full_link = ''.join(link)
            item.setText(1, full_link)
            if len(links) > 100 and not n % 100:
                # process in chunks to allow for UI updates
                self.progressBar.setValue(n)
                QtWidgets.QApplication.processEvents()
            with suppress(RuntimeError):
                if full_link in self.tested_items:
                    self.finishTest(full_link, self.tested_items[full_link], item)
                elif full_link in self.testing_items:
                    item.setText(2, "Testing...")
                if link[1] in wiki:
                    item.setText(0, "\u274C")
                    for _ in range(3):
                        item.setBackground(_, self._highlight_col)
                    self.duped_links.append(full_link)
                else:
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
        # handle copy buttons
        self._is_free.set()
 
    def retranslateUi(self):
        # Set text (with translations)
        _translate = QtCore.QCoreApplication.translate
        self.setWindowTitle(_translate("MainWindow", "Dupe Checker v1.14"))
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


def build_wiki_set():
    # scrape wiki
    elapsed = time.perf_counter()
    try:
        resps = grequests.map([grequests.get(l) for l in URLS], size=len(URLS))
    except ConnectionError:
        # show connection error
        msg = QtWidgets.QMessageBox()
        msg.setIcon(QtWidgets.QMessageBox.Critical)
        msg.setText("Could not connect to the internet. Please check your connection and try again.")
        msg.setWindowTitle("Connection Error")
        splash.hide()
        msg.exec_()
        exit(1)
    wiki = set()
    for resp, exps in zip(resps, URLS.values()):
        for exp in exps:
            if exp is b64_regex:
                wiki.update(handle_b64(resp.text))
            else:
                wiki.update(set(re.findall(exp, resp.text)))

    print(f'Wiki scraped in {time.perf_counter() - elapsed:0.4f} sec. Found {len(wiki)} links.')
    return wiki


def handle_b64(content):
    data = '\n'.join(
        b64decode(m.strip('`')).decode()
        for m in re.findall(b64_regex, content)
    )
    return set(re.findall(url_regex, data))


# regex for scraping links from wikis (links must include leading http(s)://)
url_regex = re.compile(r'(?:https?|ftp|file):\/\/(?:ww(?:w|\d+)\.)?((?:[\w_-]+(?:\.[\w_-]+)+)[\w.,@?^=%&:\/~+#-]*[\w@?^=%&~+-])')
# regex for scraping lists of urls (for links not including http(s)://)
list_regex = re.compile(r'^[\w]*\.[\w.,@?^=%&:\/~+#-]*[\w@?^=%&~+-]', re.MULTILINE)
# regex for scraping base64 encoded links
b64_regex = re.compile(r'`aHR0(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/][AQgw]==|[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=)?`')

'''
FOR ANYONE IN THE FUTURE TRYING TO MAINTAIN THIS
you can add a wikis to scrape by adding new key-value pairs to the dict below
the key is the url of the wiki, and the value is a tuple of regexes to use for scraping
'''
URLS = {
    'https://gitlab.com/nbatman_/deleted-links/-/raw/main/deleted-links': (list_regex,),
    'https://raw.githubusercontent.com/nbats/FMHYedit/main/single-page': (url_regex, b64_regex),
}


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)

    # set splash screen
    splash_icon = QtGui.QPixmap(resource_path('assets/splash.svg'))
    splash = QtWidgets.QSplashScreen(splash_icon, QtCore.Qt.WindowStaysOnTopHint)
    splash.show()
    wiki = build_wiki_set()
    

    fonts_dir = resource_path('assets/fonts')
    for f in os.listdir(fonts_dir):
        QtGui.QFontDatabase.addApplicationFont(os.path.join(fonts_dir, f))
    MainWindow = QMainWindow()
    window = UI()
    sys.exit(app.exec_())
 