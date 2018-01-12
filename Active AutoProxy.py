from burp import IBurpExtender
from burp import IContextMenuFactory # add menu support when right clicking requests and responses
from burp import IHttpRequestResponse # for rebuilding requests when restoring state and importing csv into log table
from burp import ITab
from burp import IProxyListener
from burp import IMessageEditorController
from datetime import datetime # for time columns in log table and host table in AutoProxy
from java import lang # for checkboxes in host table in AutoProxy
from java.awt import BorderLayout # for object position within JPanels in AutoProxy and AutoTest
from java.awt import Color # for highlighting regex errors in AutoProxy and AutoTest
from java.awt import Component # for components
from java.awt import GridBagLayout # for AutoConfig AutoCopy button positioning
from java.awt import GridLayout # for AutoConfig AutoCopy button positioning
from java.awt.event import FocusEvent # for removing regex error highlights on focus in AutoProxy and AutoTest
from java.awt.event import FocusListener # for removing regex error highlights on focus in AutoProxy and AutoTest
from java.awt.event import ItemListener # for filtering the log table
from java.awt.event import KeyEvent # for allowing tab key to change focus instead of inserting tab into text input in AutoProxy and AutoTest
from java.beans import PropertyChangeEvent # for keeping split panes the same height in AutoTest
from java.beans import PropertyChangeListener # for keeping split panes the same height in AutoTest
from java.lang import Runnable # for inserting/deleting to/from the log table
from java.net import URL # for downloading block lists
from java.util import ArrayList # for log table in AutoProxy
from javax.swing import BorderFactory # for creating borders around the AutoConfig and AutoBlock panels
from javax.swing import JButton # for buttons in AutoProxy and AutoTest
from javax.swing import JCheckBox # for filtering the log table and saving/restoring the state
from javax.swing import JFileChooser # for AutoConfig and AutoBlock dialog boxes
from javax.swing import JFrame # for AutoConfig and AutoBlock dialog boxes
from javax.swing import JLabel # for labels in JPanels in AutoProxy and AutoTest
from javax.swing import JOptionPane # for message box showing regex errors in AutoProxy and AutoTest
from javax.swing import JPanel # for panels within split panes in AutoProxy and AutoTest
from javax.swing import JScrollPane # for scrollable text areas and tables in AutoProxy and AutoTest
from javax.swing import JSplitPane # for split panes in AutoProxy and AutoTest
from javax.swing import JTabbedPane # for tabs in AutoProxy
from javax.swing import JTable # for log table and host table in AutoProxy
from javax.swing import JTextArea # for text areas in AutoProxy and AutoTest
from javax.swing import JTextPane # for html text area
from javax.swing import RowFilter # for filtering the log table
from javax.swing import SortOrder # for setting AutoProxy log table sort order ascending descending unsorted
from javax.swing import SwingUtilities # for swing utilities
from javax.swing.event import DocumentListener # for filtering log table by host and method
from javax.swing.filechooser import FileNameExtensionFilter # for AutoConfig and AutoBlock dialog boxes
from javax.swing.table import AbstractTableModel # for log table in AutoProxy
from javax.swing.table import DefaultTableModel # for host table in AutoProxy
from javax.swing.table import TableCellRenderer # for aligning column headers in AutoProxy host table
from javax.swing.table import TableRowSorter # for sorting and filtering the log table
from javax.swing.text import DefaultHighlighter # for highlighting regex errors in AutoProxy and AutoTest
from thread import start_new_thread # for downloading block lists
from threading import Lock # for logging in AutoProxy
import base64 # for requests when saving/restoring state and exporting/importing log table
import csv # for exporting/importing log table to/from csv
import httplib # for testing connections when downloading AutoBlock files
import json # for saving/restoring state
import os # for splitting the file name and file extension in AutoConfig and AutoBlock and for checking file vs directory in AutoBlock
import Queue # to get return value from new thread
import re # for regex support in AutoProxy and AutoTest


#
# Burp extender main class
#

class BurpExtender(IBurpExtender, ITab, IProxyListener, IMessageEditorController, AbstractTableModel, IContextMenuFactory):

	#
	# implement IBurpExtender when the extension is loaded
	#

	def registerExtenderCallbacks(self, callbacks):

		# keep reference to callbacks object
		self._callbacks = callbacks

		# obtain extension helpers object
		self._helpers = callbacks.getHelpers()

		# set the extension name
		self._EXTENSION_NAME = "Proxy Action Rules"

		# set the extension version
		self._EXTENSION_VERSION = "1.0"

		# set extension name
		callbacks.setExtensionName(self._EXTENSION_NAME)

		# create log and lock to synchronize when adding log entries
		self._log = ArrayList()
		self._lock = Lock()

		# create an option to automatically clear the log table
		self._autoClearLogTable = False

		# set the auto clear amount
		self._autoClearLogTableAmount = 0

		#
		# AutoProxy Tab - Start
		#

		##### AutoProxy Tab - Top Section - Start #####

		# create label for AutoProxy forward input 
		self._labelAutoProxyForwardHostsInput = JLabel("AutoForward Hosts", JLabel.CENTER)

		# create custom text area
		self._textAreaAutoProxyForwardHostsInput = CustomJTextArea()

		# add focus listener to text area to remove regex error highlights on focus
		self._textAreaAutoProxyForwardHostsInput.addFocusListener(CustomFocusListener(self._textAreaAutoProxyForwardHostsInput))

		# create scroll pane
		self._scrollPaneAutoProxyForwardHostsInput = JScrollPane(self._textAreaAutoProxyForwardHostsInput)

		# create panel
		self._panelAutoProxyForwardHostsInput = JPanel()

		# set layout
		self._panelAutoProxyForwardHostsInput.setLayout(BorderLayout())

		# add label and scroll pane to panel
		self._panelAutoProxyForwardHostsInput.add(self._labelAutoProxyForwardHostsInput, BorderLayout.NORTH)
		self._panelAutoProxyForwardHostsInput.add(self._scrollPaneAutoProxyForwardHostsInput, BorderLayout.CENTER)

		# create label for AutoProxy intercept input
		self._labelAutoProxyInterceptHostsInput = JLabel("AutoIntercept Hosts", JLabel.CENTER)
		# create custom text area
		self._textAreaAutoProxyInterceptHostsInput = CustomJTextArea()

		# add focus listener to text area to remove regex error highlights on focus
		self._textAreaAutoProxyInterceptHostsInput.addFocusListener(CustomFocusListener(self._textAreaAutoProxyInterceptHostsInput))

		# create scroll pane
		self._scrollPaneAutoProxyInterceptHostsInput = JScrollPane(self._textAreaAutoProxyInterceptHostsInput)

		# create panel
		self._panelAutoProxyInterceptHostsInput = JPanel()

		# set layout
		self._panelAutoProxyInterceptHostsInput.setLayout(BorderLayout())

		# add label and scroll pane to panel
		self._panelAutoProxyInterceptHostsInput.add(self._labelAutoProxyInterceptHostsInput, BorderLayout.NORTH)
		self._panelAutoProxyInterceptHostsInput.add(self._scrollPaneAutoProxyInterceptHostsInput, BorderLayout.CENTER)

		# create label for AutoProxy drop input
		self._labelAutoProxyDropHostsInput = JLabel("AutoDrop Hosts", JLabel.CENTER)

		# create custom text area
		self._textAreaAutoProxyDropHostsInput = CustomJTextArea()

		# add focus listener to text area to remove regex error highlights on focus
		self._textAreaAutoProxyDropHostsInput.addFocusListener(CustomFocusListener(self._textAreaAutoProxyDropHostsInput))

		# create scroll pane
		self._scrollPaneAutoProxyDropHostsInput = JScrollPane(self._textAreaAutoProxyDropHostsInput)

		# create panel
		self._panelAutoProxyDropHostsInput = JPanel()

		# set layout
		self._panelAutoProxyDropHostsInput.setLayout(BorderLayout())

		# add label and scroll pane to panel
		self._panelAutoProxyDropHostsInput.add(self._labelAutoProxyDropHostsInput, BorderLayout.NORTH)
		self._panelAutoProxyDropHostsInput.add(self._scrollPaneAutoProxyDropHostsInput, BorderLayout.CENTER)

		# create primary AutoProxy split pane for top section
		self._splitpaneAutoProxyHorizontal1 = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
		self._splitpaneAutoProxyHorizontal1.setResizeWeight(0.3)
		self._splitpaneAutoProxyHorizontal1.setDividerLocation(0.3)

		# create secondary AutoProxy split pane for top section
		self._splitpaneAutoProxyHorizontal2 = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
		self._splitpaneAutoProxyHorizontal2.setResizeWeight(0.5)
		self._splitpaneAutoProxyHorizontal2.setDividerLocation(0.5)

		# set top left pane to forward hosts input 
		self._splitpaneAutoProxyHorizontal1.setLeftComponent(self._panelAutoProxyForwardHostsInput)

		# set right pane to secondary split pane
		self._splitpaneAutoProxyHorizontal1.setRightComponent(self._splitpaneAutoProxyHorizontal2)

		# set top middle pane to intercept hosts input
		self._splitpaneAutoProxyHorizontal2.setLeftComponent(self._panelAutoProxyInterceptHostsInput)

		# set top right pane to drop hosts input
		self._splitpaneAutoProxyHorizontal2.setRightComponent(self._panelAutoProxyDropHostsInput)

		##### AutoProxy Tab - Top Section - End #####

		##### AutoProxy Tab - Middle Section - Log Table - Start #####

		# create lock to not update request viewer when clearing the log table
		self._customJTableLogsTableChangeLock = False

		# create custom JTable for logs
		self._tableAutoProxyLogs = CustomJTableLogs(self)

		# set minimum column widths for log table
		self._tableAutoProxyLogs.getColumnModel().getColumn(0).setMinWidth(10)
		self._tableAutoProxyLogs.getColumnModel().getColumn(1).setMinWidth(10)
		self._tableAutoProxyLogs.getColumnModel().getColumn(2).setMinWidth(10)
		self._tableAutoProxyLogs.getColumnModel().getColumn(3).setMinWidth(10)
		self._tableAutoProxyLogs.getColumnModel().getColumn(4).setMinWidth(10)
		self._tableAutoProxyLogs.getColumnModel().getColumn(5).setMinWidth(10)
		self._tableAutoProxyLogs.getColumnModel().getColumn(6).setMinWidth(10)
		self._tableAutoProxyLogs.getColumnModel().getColumn(7).setMinWidth(10)
		self._tableAutoProxyLogs.getColumnModel().getColumn(8).setMinWidth(10)
		self._tableAutoProxyLogs.getColumnModel().getColumn(9).setMinWidth(10)

		# set preferred column widths for log table
		self._tableAutoProxyLogs.getColumnModel().getColumn(0).setPreferredWidth(110)
		self._tableAutoProxyLogs.getColumnModel().getColumn(1).setPreferredWidth(80)
		self._tableAutoProxyLogs.getColumnModel().getColumn(2).setPreferredWidth(80)
		self._tableAutoProxyLogs.getColumnModel().getColumn(3).setPreferredWidth(60)
		self._tableAutoProxyLogs.getColumnModel().getColumn(4).setPreferredWidth(220)
		self._tableAutoProxyLogs.getColumnModel().getColumn(5).setPreferredWidth(80)
		self._tableAutoProxyLogs.getColumnModel().getColumn(6).setPreferredWidth(150)
		self._tableAutoProxyLogs.getColumnModel().getColumn(7).setPreferredWidth(100)
		self._tableAutoProxyLogs.getColumnModel().getColumn(8).setPreferredWidth(60)
		self._tableAutoProxyLogs.getColumnModel().getColumn(9).setPreferredWidth(60)

		# create scroll pane for log table
		self._scrollPaneAutoProxyLogTable = JScrollPane(self._tableAutoProxyLogs)

		# create variable to mark if restoring/importing log table to help with duplicate log entries when restoring/importing
		self._autoConfigRestoreOrImportLogTableFlag = False

		# create variable to store a current filter value to help with duplicate log entries when restoring/importing
		self._autoConfigRestoreOrImportLogTableFilterValue = False

		# set the last selected row to -1
		self._currentlySelectedLogTableRow = -1

		##### AutoProxy Tab - Middle Section - Log Table - End #####

		##### AutoProxy Tab - Middle Section - Host Table - Start #####

		# create headers for host table
		headersHostTable = ["First Time Logged", "Host", "AutoForward", "AutoIntercept", "AutoDrop"]

		# create custom DefaultTableModel for host table tab
		self._tableModelAutoProxyAutoAction = CustomDefaultTableModelHosts(None, headersHostTable)

		# create custom JTable for host table tab
		self._tableAutoProxyAutoAction = CustomJTableHosts(self._tableModelAutoProxyAutoAction, self._textAreaAutoProxyForwardHostsInput, self._textAreaAutoProxyInterceptHostsInput, self._textAreaAutoProxyDropHostsInput)

		# get header row for host table
		headerRowHostTable = self._tableAutoProxyAutoAction.getTableHeader()

		# get default renderer for host table
		defaultRendererHostTable = headerRowHostTable.getDefaultRenderer()

		# get custom table cell renderer for host table
		customTableCellRendererHostTable = CustomTableCellRendererHostTable(defaultRendererHostTable)

		# align columns in header row for host table
		headerRowHostTable.setDefaultRenderer(customTableCellRendererHostTable)

		# set minimum column widths for host table
		self._tableAutoProxyAutoAction.getColumnModel().getColumn(0).setMinWidth(80)
		self._tableAutoProxyAutoAction.getColumnModel().getColumn(1).setMinWidth(100)
		self._tableAutoProxyAutoAction.getColumnModel().getColumn(2).setMinWidth(55)
		self._tableAutoProxyAutoAction.getColumnModel().getColumn(3).setMinWidth(55)
		self._tableAutoProxyAutoAction.getColumnModel().getColumn(4).setMinWidth(55)

		# set preferred column widths for host table
		self._tableAutoProxyAutoAction.getColumnModel().getColumn(0).setPreferredWidth(180)
		self._tableAutoProxyAutoAction.getColumnModel().getColumn(1).setPreferredWidth(400)
		self._tableAutoProxyAutoAction.getColumnModel().getColumn(2).setPreferredWidth(145)
		self._tableAutoProxyAutoAction.getColumnModel().getColumn(3).setPreferredWidth(150)
		self._tableAutoProxyAutoAction.getColumnModel().getColumn(4).setPreferredWidth(125)

		# create custom table row sorter that can unsort
		self._tableRowSorterAutoProxyAutoAction = CustomTableRowSorter(self._tableAutoProxyAutoAction.getModel())

		# set row sorter
		self._tableAutoProxyAutoAction.setRowSorter(self._tableRowSorterAutoProxyAutoAction)

		# create scroll pane for host table
		self._scrollPaneAutoProxyHostTable = JScrollPane(self._tableAutoProxyAutoAction)

		##### AutoProxy - Middle Section - Host Table - End #####

		##### AutoProxy - Middle Section - Host List Regex Format - Start #####

		# create text editors for list of unique hosts in regex format
		self._textEditorAutoProxyHostListRegexFormat = callbacks.createTextEditor()

		# set text area to read only
		self._textEditorAutoProxyHostListRegexFormat.setEditable(False)

		##### AutoProxy Tab - Middle Section - Host List Regex Format - End #####

		##### AutoProxy Tab - Middle Section - Host List Text Format - Start #####

		# create text editors for list of unique hosts in text format
		self._textEditorAutoProxyHostListTextFormat = callbacks.createTextEditor()

		# set text area to read only
		self._textEditorAutoProxyHostListTextFormat.setEditable(False)

		##### AutoProxy Tab - Middle Section - Host List Text Format - End #####

		##### AutoProxy Tab - Middle Section - Help - Start #####

		# create JTextPane
		textPaneHelp = JTextPane()

		# set editable to false
		textPaneHelp.setEditable(False)

		# set content type to html
		textPaneHelp.setContentType("text/html")

		# implicitly joined string
		textPaneHelp.setText(""
		"<html>"
		"<body>"
		"<b style='font-size: 150%;'>" + "<u>" + self._EXTENSION_NAME + "</u>" + "</b>" + "<br>"
		"<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "This extension can automatically forward, intercept, and drop proxy requests while actively displaying proxy log information and centralizing list management." + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "This extension can also block ads, tracking sites, malware sites, etc." + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "The state of the extension including the settings, filters, and data can easily be exported and imported." + "<br>"
		"<br>"
		"<br>"
		"<b style='font-size: 150%;'>" + "<u>" + "Main Features" + "</u>" + "</b>" + "<br>"
		"<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "Automatically drop specific requests while browsing the web. (Proxy Intercept turned off.)" + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "Automatically drop specific requests while intercepting requests to all other hosts. (Proxy Intercept turned on.)" + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "Automatically forward specific requests while intercepting all other hosts. (Proxy Intercept turned on.)" + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "Automatically intercept specific requests while browsing the web. (Proxy Intercept turned off.)" + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "Automatically block specific requests to hosts that are known for ads, tracking, malware, etc." + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "Automatically flag specific requests for later review if they match the specified criteria." + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "Centralize the location of the lists that have to be managed to drop, forward, and intercept requests." + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "Actively view information from the proxy logs." + "<br>"
		"<br>"
		"<br>"
		"<b style='font-size: 150%;'>" + "<u>" + "Matching Options for the Main Features (To AutoForward, AutoIntercept, & AutoDrop Requests)" + "</u>" + "</b>" + "<br>"
		"<br>"
		"Requests can automatically be forwarded, intercepted, or dropped using a variety of matching options.  Case insensitive, regex matching on the host name is used by default. Enter one host per line to use the default matching option." + "<br>"
		"<br>"
		"The order of precedence if from left to right. The forward action takes precedence of the intercept action. The intercept action takes precedence of the drop action. The drop action takes precedence of the block action. Within the forward, intercept, and drop sections, the order of precedence if from top to bottom." + "<br>"
		"<br>"
		"Other matching options are listed below. Enter one matching option per line. There should be one space after each semicolon, followed by a regex search string." + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "<b>" + "Method:" + "</b>" + "&nbsp;" + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "<b>" + "Protocol:" + "</b>" + "&nbsp;" + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "<b>" + "Port:" + "</b>" + "&nbsp;" + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "<b>" + "Host:" + "</b>" + "&nbsp;" + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "<b>" + "Referer:" + "</b>" + "&nbsp;" + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "<b>" + "URL:" + "</b>" + "&nbsp;" + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "<b>" + "Path:" + "</b>" + "&nbsp;" + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "<b>" + "Body:" + "</b>" + "&nbsp;" + "<br>"
		"<br>"
		"<i>" + "<b>" + "Note: " + "</b>" + "The 'Protocol: ' and 'Port: ' options use starting and ending anchors '^$' with the matching string in between. This is so 'Port: 80' will only match port 80, but regex can still be used to make it match any port that contains 80. The 'Body: ' option does not search the URL row, Host row, or Referer row within the request body. The URL, Host, and Referer options can be used to match these fields. The URL field will not include the port if the protocol/port is http/80 or https/443." + "</i>" + "<br>"
		"<br>"
		"<br>"
		"<b style='font-size: 150%;'>" + "<u>" + "Whitelisting Requests from Being AutoBlocked" + "</u>" + "</b>" + "<br>"
		"<br>"
		"If a block list is imported from the AutoBlock tab, any requests to matching hosts will be blocked. Entering hosts in the AutoForward Hosts section can act like a whitelist by allowing traffic to the specified hosts even if they are in a block list. Some websites require tracking to function properly." + "<br>"
		"<br>"
		"<br>"
		"<b style='font-size: 150%;'>" + "<u>" + "Matching Examples" + "</u>" + "</b>" + "<br>"
		"<br>"
		"The bullets below could be entered in the AutoForward, AutoIntercept, or AutoDrop sections to match the corresponding URL." + "<br>"
		"<br>"
		"In the examples below, notice the following:" + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "The word 'ampl' can be typed in a row by itself and it would match any host containing ampl such as example.com." + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "Regex can be used to match any sites that use https on port 8443." + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "Specific words can be searched within the url, path, body, etc." + "<br>"
		"<br>"
		"Below are matching examples for " + "<b>" + "http://www.example.com/path/resource?a=b&c=d" + "</b>" + "." + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "example" + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "<b>" + "Method: " + "</b>" + "get" + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "<b>" + "Protocol: " + "</b>" + "http" + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "<b>" + "Port: " + "</b>" + "80" + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "<b>" + "Host: " + "</b>" + "www\.example\.com" + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "<b>" + "Referer: " + "</b>" + "Referer_Domain_Name_Here" + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "<b>" + "URL: " + "</b>" + "http://www.example.com/path/resource?a=b&c=d" + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "<b>" + "Path: " + "</b>" + "/path/resource?a=b&c=d" + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "<b>" + "Body: " + "</b>" + "Text_String_Within_The_Request_Body_Here" + "<br>"
		"<br>"
		"Below are some additional examples for " + "<b>" + "https://example.com:8443/path/file.asp?name=test&a=b" + "</b>" + "." + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "ampl" + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "<b>" + "Protocol: " + "</b>" + "https" + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "<b>" + "Port: " + "</b>" + "8443" + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "<b>" + "Host: " + "</b>" + "example.com" + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "<b>" + "Host: " + "</b>" + "ampl" + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "<b>" + "URL: " + "</b>" + "https://example.com:8443/path/file.asp?name=test&a=b" + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "<b>" + "URL: " + "</b>" + "https.*example.*8443" + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "<b>" + "URL: " + "</b>" + "^https.*8443" + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "<b>" + "Path: " + "</b>" + "/path/file.asp?name=test&a=b" + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "<b>" + "Path: " + "</b>" + "file.asp" + "<br>"
		"<br>"
		"<br>"
		"<b style='font-size: 150%;'>" + "<u>" + "Filtering the Log Table" + "</u>" + "</b>" + "<br>"
		"<br>"
		"The log table can be filtered using a variety of case insensitive filters. Enter one filter string per line." + "<br>"
		"<br>"
		"The Protocol and Port filters use an exact match. The Request filter does not search the URL row, Host row, or Referer row within the request body. The URL, Host, or Referer filters can be used to search these fields. The URL field will not include the port if the protocol/port is http/80 or https/443." + "<br>"
		"<br>"
		"Case sensitive searching can be performed on the request and the response by using the filter option listed below. There should be one space after the semicolon, followed by a regex filter string." + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "<b>" + "Case Sensitive:" + "</b>" + "&nbsp;" + "<br>"
		"<br>"
		"Starting a row with a hyphen '-' will filter out matches. If you need to filter something with a hyphen in the filter string, put another character before the hyphen. The hyphen works for all filters except the request and response filters. The request and response filters will search for the string with the hyphen in it." + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "<b>" + "-" + "</b>" + "<br>"
		"<br>"
		"<br>"
		"<b style='font-size: 150%;'>" + "<u>" + "Clearing the Log Table" + "</u>" + "</b>" + "<br>"
		"<br>"
		"The log table can be cleared automatically if the size reaches 100 or 1000 rows. The AutoClear button is located near the log table filters within the main AutoProxy tab." + "<br>"
		"The log table can also be cleared completely from the AutoConfig tab." + "<br>"
		"<br>"
		"<br>"
		"<b style='font-size: 150%;'>" + "<u>" + "Other Tabs" + "</u>" + "</b>" + "<br>"
		"<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "<b>" + "AutoTest: " + "</b>" + "Test the default AutoProxy host matching option, without visiting any hosts." + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "<b>" + "AutoConfig: " + "</b>" + "Save, restore, copy, and clear data." + "<br>"
		"&nbsp;" + u"\u2022" + "&nbsp;" + "<b>" + "AutoBlock: " + "</b>" + "Download and import lists of hosts to block traffic to. Ads, tracking sites, malware, and more can be blocked." + "<br>"
		"<br>"
		"<br>"
		"</body>"
		"</html>")

		# create scroll pane
		scrollPaneAutoProxyHelp = JScrollPane(textPaneHelp)

		##### AutoProxy Tab - Middle Section - Help - End #####

		##### AutoProxy Tab - Bottom Section - Request Viewer and Log Table Filter - Start #####

		# create request viewer for bottom tabs
		self._requestViewerAutoProxy = callbacks.createMessageEditor(self, False)

		# create response viewer for bottom tabs
		self._responseViewerAutoProxy = callbacks.createMessageEditor(self, False)
		
		# create label for AutoAction filter
		self._labelAutoProxyAutoFilterAction = JLabel("AutoAction", JLabel.CENTER)

		# create checkboxes for filter
		self._checkboxAutoProxyAutoFilterActionNo = JCheckBox("No")
		self._checkboxAutoProxyAutoFilterActionForwarded = JCheckBox("Forwarded")
		self._checkboxAutoProxyAutoFilterActionIntercepted = JCheckBox("Intercepted")
		self._checkboxAutoProxyAutoFilterActionDropped = JCheckBox("Dropped")
		self._checkboxAutoProxyAutoFilterActionBlocked = JCheckBox("Blocked")

		# set checkboxes to true
		self._checkboxAutoProxyAutoFilterActionNo.setSelected(True)
		self._checkboxAutoProxyAutoFilterActionForwarded.setSelected(True)
		self._checkboxAutoProxyAutoFilterActionIntercepted.setSelected(True)
		self._checkboxAutoProxyAutoFilterActionDropped.setSelected(True)
		self._checkboxAutoProxyAutoFilterActionBlocked.setSelected(True)

		# add listener to checkboxes
		self._checkboxAutoProxyAutoFilterActionNo.addItemListener(CustomItemListener(self))
		self._checkboxAutoProxyAutoFilterActionForwarded.addItemListener(CustomItemListener(self))
		self._checkboxAutoProxyAutoFilterActionIntercepted.addItemListener(CustomItemListener(self))
		self._checkboxAutoProxyAutoFilterActionDropped.addItemListener(CustomItemListener(self))
		self._checkboxAutoProxyAutoFilterActionBlocked.addItemListener(CustomItemListener(self))

		# create panels for checkboxes
		self._panelAutoProxyAutoFilterActionCheckboxes1 = JPanel()
		self._panelAutoProxyAutoFilterActionCheckboxes2 = JPanel()
		self._panelAutoProxyAutoFilterActionCheckboxes3 = JPanel()
		self._panelAutoProxyAutoFilterActionCheckboxes4 = JPanel()
		self._panelAutoProxyAutoFilterActionCheckboxes5 = JPanel()

		# set layout
		self._panelAutoProxyAutoFilterActionCheckboxes1.setLayout(GridBagLayout())
		self._panelAutoProxyAutoFilterActionCheckboxes2.setLayout(GridBagLayout())
		self._panelAutoProxyAutoFilterActionCheckboxes3.setLayout(GridBagLayout())
		self._panelAutoProxyAutoFilterActionCheckboxes4.setLayout(GridBagLayout())
		self._panelAutoProxyAutoFilterActionCheckboxes5.setLayout(GridBagLayout())

		# add checkboxes to panels
		self._panelAutoProxyAutoFilterActionCheckboxes1.add(self._checkboxAutoProxyAutoFilterActionNo)
		self._panelAutoProxyAutoFilterActionCheckboxes2.add(self._checkboxAutoProxyAutoFilterActionForwarded)
		self._panelAutoProxyAutoFilterActionCheckboxes3.add(self._checkboxAutoProxyAutoFilterActionIntercepted)
		self._panelAutoProxyAutoFilterActionCheckboxes4.add(self._checkboxAutoProxyAutoFilterActionDropped)
		self._panelAutoProxyAutoFilterActionCheckboxes5.add(self._checkboxAutoProxyAutoFilterActionBlocked)

		# create main panel for checkboxes
		self._panelAutoProxyAutoFilterActionCheckboxesMain = JPanel()

		# set layout
		self._panelAutoProxyAutoFilterActionCheckboxesMain.setLayout(GridLayout(5, 1))

		# add checkbox panels to main panel
		self._panelAutoProxyAutoFilterActionCheckboxesMain.add(self._panelAutoProxyAutoFilterActionCheckboxes1)
		self._panelAutoProxyAutoFilterActionCheckboxesMain.add(self._panelAutoProxyAutoFilterActionCheckboxes2)
		self._panelAutoProxyAutoFilterActionCheckboxesMain.add(self._panelAutoProxyAutoFilterActionCheckboxes3)
		self._panelAutoProxyAutoFilterActionCheckboxesMain.add(self._panelAutoProxyAutoFilterActionCheckboxes4)
		self._panelAutoProxyAutoFilterActionCheckboxesMain.add(self._panelAutoProxyAutoFilterActionCheckboxes5)

		# create scroll pane to allow split pane to close more
		self._scrollPaneAutoProxyAutoFilterCheckboxes = JScrollPane(self._panelAutoProxyAutoFilterActionCheckboxesMain)

		# create panel
		self._panelAutoProxyAutoFilterAction = JPanel()

		# set layout
		self._panelAutoProxyAutoFilterAction.setLayout(BorderLayout())

		# add label and pane to panel
		self._panelAutoProxyAutoFilterAction.add(self._labelAutoProxyAutoFilterAction, BorderLayout.NORTH)
		self._panelAutoProxyAutoFilterAction.add(self._scrollPaneAutoProxyAutoFilterCheckboxes, BorderLayout.CENTER)

		# create label for AutoAction method filter
		self._labelAutoProxyAutoFilterMethod = JLabel("Method", JLabel.CENTER)

		# create custom text area
		self._textAreaAutoProxyAutoFilterMethodInput = CustomJTextArea()

		# add listener to text area to filter when text area changes
		self._textAreaAutoProxyAutoFilterMethodInput.getDocument().addDocumentListener(CustomDocumentListener(self))

		# create scroll pane for text area
		self._scrollPaneAutoProxyAutoFilterMethodInput = JScrollPane(self._textAreaAutoProxyAutoFilterMethodInput)

		# create panel
		self._panelAutoProxyAutoFilterMethod = JPanel()

		# set layout
		self._panelAutoProxyAutoFilterMethod.setLayout(BorderLayout())

		# add label and scroll pane to panel
		self._panelAutoProxyAutoFilterMethod.add(self._labelAutoProxyAutoFilterMethod, BorderLayout.NORTH)
		self._panelAutoProxyAutoFilterMethod.add(self._scrollPaneAutoProxyAutoFilterMethodInput, BorderLayout.CENTER)

		# create label for AutoAction protocol filter
		self._labelAutoProxyAutoFilterProtocol = JLabel("Protocol", JLabel.CENTER)

		# create custom text area
		self._textAreaAutoProxyAutoFilterProtocolInput = CustomJTextArea()

		# add listener to text area to filter when text area changes
		self._textAreaAutoProxyAutoFilterProtocolInput.getDocument().addDocumentListener(CustomDocumentListener(self))

		# create scroll pane for text area
		self._scrollPaneAutoProxyAutoFilterProtocolInput = JScrollPane(self._textAreaAutoProxyAutoFilterProtocolInput)

		# create panel
		self._panelAutoProxyAutoFilterProtocol = JPanel()

		# set layout
		self._panelAutoProxyAutoFilterProtocol.setLayout(BorderLayout())

		# add label and scroll pane to panel
		self._panelAutoProxyAutoFilterProtocol.add(self._labelAutoProxyAutoFilterProtocol, BorderLayout.NORTH)
		self._panelAutoProxyAutoFilterProtocol.add(self._scrollPaneAutoProxyAutoFilterProtocolInput, BorderLayout.CENTER)

		# create label for AutoAction port filter
		self._labelAutoProxyAutoFilterPort = JLabel("   Port   ", JLabel.CENTER)

		# create custom text area
		self._textAreaAutoProxyAutoFilterPortInput = CustomJTextArea()

		# add listener to text area to filter when text area changes
		self._textAreaAutoProxyAutoFilterPortInput.getDocument().addDocumentListener(CustomDocumentListener(self))

		# create scroll pane for text area
		self._scrollPaneAutoProxyAutoFilterPortInput = JScrollPane(self._textAreaAutoProxyAutoFilterPortInput)

		# create panel
		self._panelAutoProxyAutoFilterPort = JPanel()

		# set layout
		self._panelAutoProxyAutoFilterPort.setLayout(BorderLayout())

		# add label and scroll pane to panel
		self._panelAutoProxyAutoFilterPort.add(self._labelAutoProxyAutoFilterPort, BorderLayout.NORTH)
		self._panelAutoProxyAutoFilterPort.add(self._scrollPaneAutoProxyAutoFilterPortInput, BorderLayout.CENTER)

		# create label for AutoAction host filter
		self._labelAutoProxyAutoFilterHost = JLabel("   Host   ", JLabel.CENTER)

		# create custom text area
		self._textAreaAutoProxyAutoFilterHostInput = CustomJTextArea()

		# add listener to text area to filter when text area changes
		self._textAreaAutoProxyAutoFilterHostInput.getDocument().addDocumentListener(CustomDocumentListener(self))

		# create scroll pane for text area
		self._scrollPaneAutoProxyAutoFilterHostInput = JScrollPane(self._textAreaAutoProxyAutoFilterHostInput)

		# create panel
		self._panelAutoProxyAutoFilterHost = JPanel()

		# set layout
		self._panelAutoProxyAutoFilterHost.setLayout(BorderLayout())

		# add label and scroll pane to panel
		self._panelAutoProxyAutoFilterHost.add(self._labelAutoProxyAutoFilterHost, BorderLayout.NORTH)
		self._panelAutoProxyAutoFilterHost.add(self._scrollPaneAutoProxyAutoFilterHostInput, BorderLayout.CENTER)

		# create label for AutoAction referer filter
		self._labelAutoProxyAutoFilterReferer = JLabel("Referer", JLabel.CENTER)

		# create custom text area
		self._textAreaAutoProxyAutoFilterRefererInput = CustomJTextArea()

		# add listener to text area to filter when text area changes
		self._textAreaAutoProxyAutoFilterRefererInput.getDocument().addDocumentListener(CustomDocumentListener(self))

		# create scroll pane for text area
		self._scrollPaneAutoProxyAutoFilterRefererInput = JScrollPane(self._textAreaAutoProxyAutoFilterRefererInput)

		# create panel
		self._panelAutoProxyAutoFilterReferer = JPanel()

		# set layout
		self._panelAutoProxyAutoFilterReferer.setLayout(BorderLayout())

		# add label and scroll pane to panel
		self._panelAutoProxyAutoFilterReferer.add(self._labelAutoProxyAutoFilterReferer, BorderLayout.NORTH)
		self._panelAutoProxyAutoFilterReferer.add(self._scrollPaneAutoProxyAutoFilterRefererInput, BorderLayout.CENTER)

		# create label for AutoAction url filter
		self._labelAutoProxyAutoFilterUrl = JLabel("   URL   ", JLabel.CENTER)

		# create custom text area
		self._textAreaAutoProxyAutoFilterUrlInput = CustomJTextArea()

		# add listener to text area to filter when text area changes
		self._textAreaAutoProxyAutoFilterUrlInput.getDocument().addDocumentListener(CustomDocumentListener(self))

		# create scroll pane for text area
		self._scrollPaneAutoProxyAutoFilterUrlInput = JScrollPane(self._textAreaAutoProxyAutoFilterUrlInput)

		# create panel
		self._panelAutoProxyAutoFilterUrl = JPanel()

		# set layout
		self._panelAutoProxyAutoFilterUrl.setLayout(BorderLayout())

		# add label and scroll pane to panel
		self._panelAutoProxyAutoFilterUrl.add(self._labelAutoProxyAutoFilterUrl, BorderLayout.NORTH)
		self._panelAutoProxyAutoFilterUrl.add(self._scrollPaneAutoProxyAutoFilterUrlInput, BorderLayout.CENTER)

		# create label for AutoAction path filter
		self._labelAutoProxyAutoFilterPath = JLabel("   Path   ", JLabel.CENTER)

		# create custom text area
		self._textAreaAutoProxyAutoFilterPathInput = CustomJTextArea()

		# add listener to text area to filter when text area changes
		self._textAreaAutoProxyAutoFilterPathInput.getDocument().addDocumentListener(CustomDocumentListener(self))

		# create scroll pane for text area
		self._scrollPaneAutoProxyAutoFilterPathInput = JScrollPane(self._textAreaAutoProxyAutoFilterPathInput)

		# create panel
		self._panelAutoProxyAutoFilterPath = JPanel()

		# set layout
		self._panelAutoProxyAutoFilterPath.setLayout(BorderLayout())

		# add label and scroll pane to panel
		self._panelAutoProxyAutoFilterPath.add(self._labelAutoProxyAutoFilterPath, BorderLayout.NORTH)
		self._panelAutoProxyAutoFilterPath.add(self._scrollPaneAutoProxyAutoFilterPathInput, BorderLayout.CENTER)

		# create label for AutoAction request filter
		self._labelAutoProxyAutoFilterRequest = JLabel("Request", JLabel.CENTER)

		# create custom text area
		self._textAreaAutoProxyAutoFilterRequestInput = CustomJTextArea()

		# add listener to text area to filter when text area changes
		self._textAreaAutoProxyAutoFilterRequestInput.getDocument().addDocumentListener(CustomDocumentListener(self))

		# create scroll pane for text area
		self._scrollPaneAutoProxyAutoFilterRequestInput = JScrollPane(self._textAreaAutoProxyAutoFilterRequestInput)

		# create panel
		self._panelAutoProxyAutoFilterRequest = JPanel()

		# set layout
		self._panelAutoProxyAutoFilterRequest.setLayout(BorderLayout())

		# add label and scroll pane to panel
		self._panelAutoProxyAutoFilterRequest.add(self._labelAutoProxyAutoFilterRequest, BorderLayout.NORTH)
		self._panelAutoProxyAutoFilterRequest.add(self._scrollPaneAutoProxyAutoFilterRequestInput, BorderLayout.CENTER)

		# create label for AutoAction response filter
		self._labelAutoProxyAutoFilterResponse = JLabel("Response", JLabel.CENTER)

		# create custom text area
		self._textAreaAutoProxyAutoFilterResponseInput = CustomJTextArea()

		# add listener to text area to filter when text area changes
		self._textAreaAutoProxyAutoFilterResponseInput.getDocument().addDocumentListener(CustomDocumentListener(self))

		# create scroll pane for text area
		self._scrollPaneAutoProxyAutoFilterResponseInput = JScrollPane(self._textAreaAutoProxyAutoFilterResponseInput)

		# create panel
		self._panelAutoProxyAutoFilterResponse = JPanel()

		# set layout
		self._panelAutoProxyAutoFilterResponse.setLayout(BorderLayout())

		# add label and scroll pane to panel
		self._panelAutoProxyAutoFilterResponse.add(self._labelAutoProxyAutoFilterResponse, BorderLayout.NORTH)
		self._panelAutoProxyAutoFilterResponse.add(self._scrollPaneAutoProxyAutoFilterResponseInput, BorderLayout.CENTER)

		# create label for AutoAction auto clear
		self._labelAutoProxyAutoClear = JLabel("AutoClear", JLabel.CENTER)

		# create button
		self._buttonAutoProxyAutoClear = JButton("Off", actionPerformed=self.buttonActionAutoProxyAutoClear)

		# create panel
		self._panelAutoProxyAutoClear = JPanel()

		# set layout
		self._panelAutoProxyAutoClear.setLayout(BorderLayout())

		# add label and scroll pane to panel
		self._panelAutoProxyAutoClear.add(self._labelAutoProxyAutoClear, BorderLayout.NORTH)
		self._panelAutoProxyAutoClear.add(self._buttonAutoProxyAutoClear, BorderLayout.CENTER)

		# create first AutoFilter split pane
		self._splitpaneAutoProxyAutoFilterHorizontal1 = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
		self._splitpaneAutoProxyAutoFilterHorizontal1.setResizeWeight(0.636)
		self._splitpaneAutoProxyAutoFilterHorizontal1.setDividerLocation(0.65)

		# create second AutoFilter split pane
		self._splitpaneAutoProxyAutoFilterHorizontal2 = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
		self._splitpaneAutoProxyAutoFilterHorizontal2.setResizeWeight(0.571)
		self._splitpaneAutoProxyAutoFilterHorizontal2.setDividerLocation(0.571)

		# create third AutoFilter split pane
		self._splitpaneAutoProxyAutoFilterHorizontal3 = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
		self._splitpaneAutoProxyAutoFilterHorizontal3.setResizeWeight(0.5)
		self._splitpaneAutoProxyAutoFilterHorizontal3.setDividerLocation(0.5)

		# create fourth AutoFilter split pane
		self._splitpaneAutoProxyAutoFilterHorizontal4 = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
		self._splitpaneAutoProxyAutoFilterHorizontal4.setResizeWeight(0.5)
		self._splitpaneAutoProxyAutoFilterHorizontal4.setDividerLocation(0.5)

		# create fifth AutoFilter split pane
		self._splitpaneAutoProxyAutoFilterHorizontal5 = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
		self._splitpaneAutoProxyAutoFilterHorizontal5.setResizeWeight(0.667)
		self._splitpaneAutoProxyAutoFilterHorizontal5.setDividerLocation(0.667)

		# create sixth AutoFilter split pane
		self._splitpaneAutoProxyAutoFilterHorizontal6 = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
		self._splitpaneAutoProxyAutoFilterHorizontal6.setResizeWeight(0.5)
		self._splitpaneAutoProxyAutoFilterHorizontal6.setDividerLocation(0.5)

		# create seventh AutoFilter split pane
		self._splitpaneAutoProxyAutoFilterHorizontal7 = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
		self._splitpaneAutoProxyAutoFilterHorizontal7.setResizeWeight(0.5)
		self._splitpaneAutoProxyAutoFilterHorizontal7.setDividerLocation(0.4)

		# create eighth AutoFilter split pane
		self._splitpaneAutoProxyAutoFilterHorizontal8 = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
		self._splitpaneAutoProxyAutoFilterHorizontal8.setResizeWeight(0.5)
		self._splitpaneAutoProxyAutoFilterHorizontal8.setDividerLocation(0.5)

		# create ninth AutoFilter split pane
		self._splitpaneAutoProxyAutoFilterHorizontal9 = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
		self._splitpaneAutoProxyAutoFilterHorizontal9.setResizeWeight(0.5)
		self._splitpaneAutoProxyAutoFilterHorizontal9.setDividerLocation(0.5)

		# create tenth AutoFilter split pane
		self._splitpaneAutoProxyAutoFilterHorizontal10 = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
		self._splitpaneAutoProxyAutoFilterHorizontal10.setResizeWeight(0.5)
		self._splitpaneAutoProxyAutoFilterHorizontal10.setDividerLocation(0.5)

		# set left side of first pane
		self._splitpaneAutoProxyAutoFilterHorizontal1.setLeftComponent(self._splitpaneAutoProxyAutoFilterHorizontal2)

		# set right side of first pane
		self._splitpaneAutoProxyAutoFilterHorizontal1.setRightComponent(self._splitpaneAutoProxyAutoFilterHorizontal3)

		# set left side second pane
		self._splitpaneAutoProxyAutoFilterHorizontal2.setLeftComponent(self._splitpaneAutoProxyAutoFilterHorizontal4)

		# set right side of second pane
		self._splitpaneAutoProxyAutoFilterHorizontal2.setRightComponent(self._splitpaneAutoProxyAutoFilterHorizontal5)

		# set left side of third pane
		self._splitpaneAutoProxyAutoFilterHorizontal3.setLeftComponent(self._splitpaneAutoProxyAutoFilterHorizontal6)

		# set right side of third pane
		self._splitpaneAutoProxyAutoFilterHorizontal3.setRightComponent(self._splitpaneAutoProxyAutoFilterHorizontal7)

		# set left side of fourth pane
		self._splitpaneAutoProxyAutoFilterHorizontal4.setLeftComponent(self._splitpaneAutoProxyAutoFilterHorizontal8)

		# set right side of fourth pane
		self._splitpaneAutoProxyAutoFilterHorizontal4.setRightComponent(self._splitpaneAutoProxyAutoFilterHorizontal9)

		# set left side of fifth pane
		self._splitpaneAutoProxyAutoFilterHorizontal5.setLeftComponent(self._splitpaneAutoProxyAutoFilterHorizontal10)

		# set right side of fifth pane
		self._splitpaneAutoProxyAutoFilterHorizontal5.setRightComponent(self._panelAutoProxyAutoFilterUrl)

		# set left side of sixth pane
		self._splitpaneAutoProxyAutoFilterHorizontal6.setLeftComponent(self._panelAutoProxyAutoFilterPath)

		# set right side of sixth pane
		self._splitpaneAutoProxyAutoFilterHorizontal6.setRightComponent(self._panelAutoProxyAutoFilterRequest)

		# set left side of seventh pane
		self._splitpaneAutoProxyAutoFilterHorizontal7.setLeftComponent(self._panelAutoProxyAutoFilterResponse)

		# set right side of seventh pane
		self._splitpaneAutoProxyAutoFilterHorizontal7.setRightComponent(self._panelAutoProxyAutoClear)

		# set left side of eighth pane
		self._splitpaneAutoProxyAutoFilterHorizontal8.setLeftComponent(self._panelAutoProxyAutoFilterAction)

		# set right side of eighth pane
		self._splitpaneAutoProxyAutoFilterHorizontal8.setRightComponent(self._panelAutoProxyAutoFilterMethod)

		# set left side of ninth pane
		self._splitpaneAutoProxyAutoFilterHorizontal9.setLeftComponent(self._panelAutoProxyAutoFilterProtocol)

		# set right side of ninth pane
		self._splitpaneAutoProxyAutoFilterHorizontal9.setRightComponent(self._panelAutoProxyAutoFilterPort)

		# set left side of tenth pane
		self._splitpaneAutoProxyAutoFilterHorizontal10.setLeftComponent(self._panelAutoProxyAutoFilterHost)

		# set right side of tenth pane
		self._splitpaneAutoProxyAutoFilterHorizontal10.setRightComponent(self._panelAutoProxyAutoFilterReferer)

		# create custom table row sorter that can unsort
		self._tableRowSorterAutoProxyLogs = CustomTableRowSorter(self)

		# create custom row filter
		self._filterAutoAction = CustomRowFilter(self) 

		# set row filter
		self._tableRowSorterAutoProxyLogs.setRowFilter(self._filterAutoAction)

		# set row sorter
		self._tableAutoProxyLogs.setRowSorter(self._tableRowSorterAutoProxyLogs)

		##### AutoProxy Tab - Bottom Section - Request Viewer and Log Table Filter - End #####

		##### AutoProxy Tab - Main Split Panes and Tabs - Start #####

		# create main split pane for hosts inputs and middle tabs
		self._splitpaneAutoProxyVertical1 = JSplitPane(JSplitPane.VERTICAL_SPLIT)
		self._splitpaneAutoProxyVertical1.setResizeWeight(0.25)
		self._splitpaneAutoProxyVertical1.setDividerLocation(0.25)

		# create second split pane for log table and request details
		self._splitpaneAutoProxyVertical2 = JSplitPane(JSplitPane.VERTICAL_SPLIT)
		self._splitpaneAutoProxyVertical2.setResizeWeight(0.75)
		self._splitpaneAutoProxyVertical2.setDividerLocation(0.75)

		# create middle tabs
		self._tabbedPaneAutoProxyMiddle = JTabbedPane()
		self._tabbedPaneAutoProxyMiddle.addTab("AutoProxy Logs", self._splitpaneAutoProxyVertical2)
		self._tabbedPaneAutoProxyMiddle.addTab("AutoAction Hosts", self._scrollPaneAutoProxyHostTable)
		self._tabbedPaneAutoProxyMiddle.addTab("AutoRegex Hosts", self._textEditorAutoProxyHostListRegexFormat.getComponent())
		self._tabbedPaneAutoProxyMiddle.addTab("AutoText Hosts", self._textEditorAutoProxyHostListTextFormat.getComponent())
		self._tabbedPaneAutoProxyMiddle.addTab("AutoProxy Details", scrollPaneAutoProxyHelp)

		# set top pane main horizontal split pane
		self._splitpaneAutoProxyVertical1.setLeftComponent(self._splitpaneAutoProxyHorizontal1)

		# set bottom pane to middle tabs
		self._splitpaneAutoProxyVertical1.setRightComponent(self._tabbedPaneAutoProxyMiddle)

		# create bottom tabs for request details and filter
		self._tabbedPaneAutoProxyBottom = JTabbedPane()
		self._tabbedPaneAutoProxyBottom.addTab("AutoFilter Logs", self._splitpaneAutoProxyAutoFilterHorizontal1)
		self._tabbedPaneAutoProxyBottom.addTab("Request Details", self._requestViewerAutoProxy.getComponent())
		self._tabbedPaneAutoProxyBottom.addTab("Response Details", self._responseViewerAutoProxy.getComponent())

		# when using three bottom sections instead of four, keep them the same size as the top three sections
		# self._tabbedPaneAutoProxyBottom.addChangeListener(self.propertyChangeAutoProxyBottomTabs)

		# set top of second split pane to log table
		self._splitpaneAutoProxyVertical2.setLeftComponent(self._scrollPaneAutoProxyLogTable)

		# set bottom of second split pane to bottom tabs
		self._splitpaneAutoProxyVertical2.setRightComponent(self._tabbedPaneAutoProxyBottom)

		##### AutoProxy Tab - Main Split Panes and Tabs - End #####

		#
		# AutoTest Tab - Start
		#

		##### AutoTest Tab - Top Section - Start #####

		# create label for AutoTest hosts input
		self._labelAutoTestHostsInput = JLabel("AutoTest Hosts", JLabel.CENTER)

		# create button
		self._buttonAutoTest = JButton("Start AutoTest", actionPerformed=self.buttonActionAutoTest)

		# create custom text area
		self._textAreaAutoTestHostsInput = CustomJTextArea()

		# create scroll pane
		self._scrollPaneAutoTestHostsInput = JScrollPane(self._textAreaAutoTestHostsInput)

		# create panel
		self._panelAutoTestHostsInput = JPanel()

		# set layout
		self._panelAutoTestHostsInput.setLayout(BorderLayout())

		# add label and scroll pane and button to panel
		self._panelAutoTestHostsInput.add(self._labelAutoTestHostsInput, BorderLayout.NORTH)
		self._panelAutoTestHostsInput.add(self._scrollPaneAutoTestHostsInput, BorderLayout.CENTER)
		self._panelAutoTestHostsInput.add(self._buttonAutoTest, BorderLayout.SOUTH)

		# create section for AutoTest forward input
		self._labelAutoTestForwardHostsInput = JLabel("AutoForward Hosts", JLabel.CENTER)

		# create custom text area
		self._textAreaAutoTestForwardHostsInput = CustomJTextArea()

		# add focus listener to text area to remove regex error highlights on focus
		self._textAreaAutoTestForwardHostsInput.addFocusListener(CustomFocusListener(self._textAreaAutoTestForwardHostsInput))

		# create scroll pane
		self._scrollPaneAutoTestForwardHostsInput = JScrollPane(self._textAreaAutoTestForwardHostsInput)

		# create panel
		self._panelAutoTestForwardHostsInput = JPanel()

		# set layout
		self._panelAutoTestForwardHostsInput.setLayout(BorderLayout())

		# add label and scroll pane to panel
		self._panelAutoTestForwardHostsInput.add(self._labelAutoTestForwardHostsInput, BorderLayout.NORTH)
		self._panelAutoTestForwardHostsInput.add(self._scrollPaneAutoTestForwardHostsInput, BorderLayout.CENTER)

		# create label for AutoTest intercept input
		self._labelAutoTestInterceptHostsInput = JLabel("AutoIntercept Hosts", JLabel.CENTER)

		# create custom text area
		self._textAreaAutoTestInterceptHostsInput = CustomJTextArea()

		# add focus listener to text area to remove regex error highlights on focus
		self._textAreaAutoTestInterceptHostsInput.addFocusListener(CustomFocusListener(self._textAreaAutoTestInterceptHostsInput))

		# create scroll pane
		self._scrollPaneAutoTestInterceptHostsInput = JScrollPane(self._textAreaAutoTestInterceptHostsInput)

		# create panel
		self._panelAutoTestInterceptHostsInput = JPanel()

		# set layout
		self._panelAutoTestInterceptHostsInput.setLayout(BorderLayout())

		# add label and scroll pane to panel
		self._panelAutoTestInterceptHostsInput.add(self._labelAutoTestInterceptHostsInput, BorderLayout.NORTH)
		self._panelAutoTestInterceptHostsInput.add(self._scrollPaneAutoTestInterceptHostsInput, BorderLayout.CENTER)

		# create label for AutoTest drop input
		self._labelAutoTestDropHostsInput = JLabel("AutoDrop Hosts", JLabel.CENTER)

		# create custom text area
		self._textAreaAutoTestDropHostsInput = CustomJTextArea()

		# add focus listener to text area to remove regex error highlights on focus
		self._textAreaAutoTestDropHostsInput.addFocusListener(CustomFocusListener(self._textAreaAutoTestDropHostsInput))

		# create scroll pane
		self._scrollPaneAutoTestDropHostsInput = JScrollPane(self._textAreaAutoTestDropHostsInput)

		# create panel
		self._panelAutoTestDropHostsInput = JPanel()

		# set layout
		self._panelAutoTestDropHostsInput.setLayout(BorderLayout())

		# add label and scroll pane to panel
		self._panelAutoTestDropHostsInput.add(self._labelAutoTestDropHostsInput, BorderLayout.NORTH)
		self._panelAutoTestDropHostsInput.add(self._scrollPaneAutoTestDropHostsInput, BorderLayout.CENTER)

		##### AutoTest Tab - Top Section - End #####

		##### AutoTest Tab - Bottom Section - Start #####

		# create label for AutoTest no action output
		self._labelAutoTestNoActionHostsOutput = JLabel("NoAction", JLabel.CENTER)

		# create text area
		self._textAreaAutoTestNoActionHostsOutput = JTextArea()

		# set text area to read only
		self._textAreaAutoTestNoActionHostsOutput.setEditable(False)

		# create scroll pane
		self._scrollPaneAutoTestNoActionHostsOutput = JScrollPane(self._textAreaAutoTestNoActionHostsOutput)

		# create panel
		self._panelAutoTestNoActionHostsOutput = JPanel()

		# set layout
		self._panelAutoTestNoActionHostsOutput.setLayout(BorderLayout())

		# add label and scroll pane to panel
		self._panelAutoTestNoActionHostsOutput.add(self._labelAutoTestNoActionHostsOutput, BorderLayout.NORTH)
		self._panelAutoTestNoActionHostsOutput.add(self._scrollPaneAutoTestNoActionHostsOutput, BorderLayout.CENTER)

		# create label for AutoTest forward output
		self._labelAutoTestForwardHostsOutput = JLabel("AutoForwarded", JLabel.CENTER)

		# create text area
		self._textAreaAutoTestForwardHostsOutput = JTextArea()

		# set text area to read only
		self._textAreaAutoTestForwardHostsOutput.setEditable(False)

		# create scroll pane
		self._scrollPaneAutoTestForwardHostsOutput = JScrollPane(self._textAreaAutoTestForwardHostsOutput)

		# create panel
		self._panelAutoTestForwardHostsOutput = JPanel()

		# set layout
		self._panelAutoTestForwardHostsOutput.setLayout(BorderLayout())

		# add label and scroll pane to panel
		self._panelAutoTestForwardHostsOutput.add(self._labelAutoTestForwardHostsOutput, BorderLayout.NORTH)
		self._panelAutoTestForwardHostsOutput.add(self._scrollPaneAutoTestForwardHostsOutput, BorderLayout.CENTER)

		# create label for AutoTest intercept output
		self._labelAutoTestInterceptHostsOutput = JLabel("AutoIntercepted", JLabel.CENTER)

		# create text area
		self._textAreaAutoTestInterceptHostsOutput = JTextArea()

		# set text area to read only
		self._textAreaAutoTestInterceptHostsOutput.setEditable(False)

		# create scroll pane
		self._scrollPaneAutoTestInterceptHostsOutput = JScrollPane(self._textAreaAutoTestInterceptHostsOutput)

		# create panel
		self._panelAutoTestInterceptHostsOutput = JPanel()

		# set layout
		self._panelAutoTestInterceptHostsOutput.setLayout(BorderLayout())

		# add label and scroll pane to panel
		self._panelAutoTestInterceptHostsOutput.add(self._labelAutoTestInterceptHostsOutput, BorderLayout.NORTH)
		self._panelAutoTestInterceptHostsOutput.add(self._scrollPaneAutoTestInterceptHostsOutput, BorderLayout.CENTER)

		# create label for AutoTest drop output
		self._labelAutoTestDropHostsOutput = JLabel("AutoDropped", JLabel.CENTER)

		# create text area
		self._textAreaAutoTestDropHostsOutput = JTextArea()

		# set text area to read only
		self._textAreaAutoTestDropHostsOutput.setEditable(False)

		# create scroll pane
		self._scrollPaneAutoTestDropHostsOutput = JScrollPane(self._textAreaAutoTestDropHostsOutput)

		# create panel
		self._panelAutoTestDropHostsOutput = JPanel()

		# set layout
		self._panelAutoTestDropHostsOutput.setLayout(BorderLayout())

		# add label and scroll pane to panel
		self._panelAutoTestDropHostsOutput.add(self._labelAutoTestDropHostsOutput, BorderLayout.NORTH)
		self._panelAutoTestDropHostsOutput.add(self._scrollPaneAutoTestDropHostsOutput, BorderLayout.CENTER)

		##### AutoTest Tab - Bottom Section - End #####

		##### AutoTest Tab - Split Panes - Start #####

		# create primary split pane for first column 
		self._splitpaneAutoTestHorizontal1 = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
		self._splitpaneAutoTestHorizontal1.setResizeWeight(0.25)
		self._splitpaneAutoTestHorizontal1.setDividerLocation(0.25)

		# create secondary split pane for second column
		self._splitpaneAutoTestHorizontal2 = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
		self._splitpaneAutoTestHorizontal2.setResizeWeight(0.33)
		self._splitpaneAutoTestHorizontal2.setDividerLocation(0.33)

		# create tertiary split pane for third and fourth columns
		self._splitpaneAutoTestHorizontal3 = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
		self._splitpaneAutoTestHorizontal3.setResizeWeight(0.5)
		self._splitpaneAutoTestHorizontal3.setDividerLocation(0.5)

		# create vertical section top/bottom 1 of 4
		self._splitpaneAutoTestVertical1 = JSplitPane(JSplitPane.VERTICAL_SPLIT)
		self._splitpaneAutoTestVertical1.setResizeWeight(0.5)
		self._splitpaneAutoTestVertical1.setDividerLocation(0.5)
		self._splitpaneAutoTestVertical1.addPropertyChangeListener(JSplitPane.DIVIDER_LOCATION_PROPERTY, self.propertyChangeAutoTest1)

		# create vertical section top/bottom 2 of 4
		self._splitpaneAutoTestVertical2 = JSplitPane(JSplitPane.VERTICAL_SPLIT)
		self._splitpaneAutoTestVertical2.setResizeWeight(0.5)
		self._splitpaneAutoTestVertical2.setDividerLocation(0.5)
		self._splitpaneAutoTestVertical2.addPropertyChangeListener(JSplitPane.DIVIDER_LOCATION_PROPERTY, self.propertyChangeAutoTest2)

		# create vertical section top/bottom 3 of 4
		self._splitpaneAutoTestVertical3 = JSplitPane(JSplitPane.VERTICAL_SPLIT)
		self._splitpaneAutoTestVertical3.setResizeWeight(0.5)
		self._splitpaneAutoTestVertical3.setDividerLocation(0.5)
		self._splitpaneAutoTestVertical3.addPropertyChangeListener(JSplitPane.DIVIDER_LOCATION_PROPERTY, self.propertyChangeAutoTest3)

		# create vertical section top/bottom 4 of 4
		self._splitpaneAutoTestVertical4 = JSplitPane(JSplitPane.VERTICAL_SPLIT)
		self._splitpaneAutoTestVertical4.setResizeWeight(0.5)
		self._splitpaneAutoTestVertical4.setDividerLocation(0.5)
		self._splitpaneAutoTestVertical4.addPropertyChangeListener(JSplitPane.DIVIDER_LOCATION_PROPERTY, self.propertyChangeAutoTest4)

		# set vertical section top/bottom 1 of 4
		self._splitpaneAutoTestVertical1.setLeftComponent(self._panelAutoTestHostsInput)
		self._splitpaneAutoTestVertical1.setRightComponent(self._panelAutoTestNoActionHostsOutput)

		# set vertical section top/bottom 2 of 4
		self._splitpaneAutoTestVertical2.setLeftComponent(self._panelAutoTestForwardHostsInput)
		self._splitpaneAutoTestVertical2.setRightComponent(self._panelAutoTestForwardHostsOutput)

		# set vertical section top/bottom 3 of 4
		self._splitpaneAutoTestVertical3.setLeftComponent(self._panelAutoTestInterceptHostsInput)
		self._splitpaneAutoTestVertical3.setRightComponent(self._panelAutoTestInterceptHostsOutput)

		# set vertical section top/bottom 4 of 4
		self._splitpaneAutoTestVertical4.setLeftComponent(self._panelAutoTestDropHostsInput)
		self._splitpaneAutoTestVertical4.setRightComponent(self._panelAutoTestDropHostsOutput)

		# set primary split pane for first column
		self._splitpaneAutoTestHorizontal1.setLeftComponent(self._splitpaneAutoTestVertical1)
		self._splitpaneAutoTestHorizontal1.setRightComponent(self._splitpaneAutoTestHorizontal2)

		# set secondary split pane for second column
		self._splitpaneAutoTestHorizontal2.setLeftComponent(self._splitpaneAutoTestVertical2)
		self._splitpaneAutoTestHorizontal2.setRightComponent(self._splitpaneAutoTestHorizontal3)

		# set tertiary split pane for third and fourth columns
		self._splitpaneAutoTestHorizontal3.setLeftComponent(self._splitpaneAutoTestVertical3)
		self._splitpaneAutoTestHorizontal3.setRightComponent(self._splitpaneAutoTestVertical4)

		##### AutoTest Tab - Split Panes - End #####

		#
		# AutoConfig Tab - Start
		#

		##### AutoConfig Tab - Save State - Start #####

		# create checkboxes
		self._checkboxAutoConfigSaveState1 = JCheckBox("AutoProxy Settings   ")
		self._checkboxAutoConfigSaveState2 = JCheckBox("AutoProxy Logs/Data")
		self._checkboxAutoConfigSaveState3 = JCheckBox("AutoProxy Filters     ")
		self._checkboxAutoConfigSaveState4 = JCheckBox("AutoTest Settings    ")

		# set checkboxes to true
		self._checkboxAutoConfigSaveState1.setSelected(True)
		self._checkboxAutoConfigSaveState2.setSelected(True)
		self._checkboxAutoConfigSaveState3.setSelected(True)
		self._checkboxAutoConfigSaveState4.setSelected(True)

		# create checkbox panels
		self._panelAutoConfigSaveStateCheckbox1 = JPanel()
		self._panelAutoConfigSaveStateCheckbox2 = JPanel()
		self._panelAutoConfigSaveStateCheckbox3 = JPanel()
		self._panelAutoConfigSaveStateCheckbox4 = JPanel()

		# center checkboxes vertically
		self._panelAutoConfigSaveStateCheckbox1.setLayout(GridBagLayout())
		self._panelAutoConfigSaveStateCheckbox2.setLayout(GridBagLayout())
		self._panelAutoConfigSaveStateCheckbox3.setLayout(GridBagLayout())
		self._panelAutoConfigSaveStateCheckbox4.setLayout(GridBagLayout())

		# add checkboxes to checkbox panels
		self._panelAutoConfigSaveStateCheckbox1.add(self._checkboxAutoConfigSaveState1)
		self._panelAutoConfigSaveStateCheckbox2.add(self._checkboxAutoConfigSaveState2)
		self._panelAutoConfigSaveStateCheckbox3.add(self._checkboxAutoConfigSaveState3)
		self._panelAutoConfigSaveStateCheckbox4.add(self._checkboxAutoConfigSaveState4)

		# create button
		self._buttonAutoConfigSaveState = JButton("Save State", actionPerformed=self.buttonActionAutoConfigSaveState)

		# create button panel
		self._panelAutoConfigSaveStateButton = JPanel()

		# center button vertically
		self._panelAutoConfigSaveStateButton.setLayout(GridBagLayout())

		# add button to button panel
		self._panelAutoConfigSaveStateButton.add(self._buttonAutoConfigSaveState)

		##### AutoConfig Tab - Save State - End #####

		##### AutoConfig Tab - Restore State - Start #####

		# create checkboxes
		self._checkboxAutoConfigRestoreState1 = JCheckBox("AutoProxy Settings  ")
		self._checkboxAutoConfigRestoreState2 = JCheckBox("AutoProxy Logs/Data")
		self._checkboxAutoConfigRestoreState3 = JCheckBox("AutoProxy Filters     ")
		self._checkboxAutoConfigRestoreState4 = JCheckBox("AutoTest Settings    ")

		# set checkboxes to true
		self._checkboxAutoConfigRestoreState1.setSelected(True)
		self._checkboxAutoConfigRestoreState2.setSelected(True)
		self._checkboxAutoConfigRestoreState3.setSelected(True)
		self._checkboxAutoConfigRestoreState4.setSelected(True)

		# create checkbox panels
		self._panelAutoConfigRestoreStateCheckbox1 = JPanel()
		self._panelAutoConfigRestoreStateCheckbox2 = JPanel()
		self._panelAutoConfigRestoreStateCheckbox3 = JPanel()
		self._panelAutoConfigRestoreStateCheckbox4 = JPanel()

		# center checkboxes vertically
		self._panelAutoConfigRestoreStateCheckbox1.setLayout(GridBagLayout())
		self._panelAutoConfigRestoreStateCheckbox2.setLayout(GridBagLayout())
		self._panelAutoConfigRestoreStateCheckbox3.setLayout(GridBagLayout())
		self._panelAutoConfigRestoreStateCheckbox4.setLayout(GridBagLayout())

		# add checkboxes to checkbox panels
		self._panelAutoConfigRestoreStateCheckbox1.add(self._checkboxAutoConfigRestoreState1)
		self._panelAutoConfigRestoreStateCheckbox2.add(self._checkboxAutoConfigRestoreState2)
		self._panelAutoConfigRestoreStateCheckbox3.add(self._checkboxAutoConfigRestoreState3)
		self._panelAutoConfigRestoreStateCheckbox4.add(self._checkboxAutoConfigRestoreState4)

		# create button
		self._buttonAutoConfigRestoreState = JButton("Restore State", actionPerformed=self.buttonActionAutoConfigRestoreState)

		# create button panel
		self._panelAutoConfigRestoreStateButton = JPanel()

		# center button vertically
		self._panelAutoConfigRestoreStateButton.setLayout(GridBagLayout())

		# add button to button panel
		self._panelAutoConfigRestoreStateButton.add(self._buttonAutoConfigRestoreState)

		##### AutoConfig Tab - Restore State - End #####

		##### AutoConfig Tab - Export Log Table To CSV - Start #####

		# create button
		self._buttonAutoConfigExportCsv = JButton("Export Log Table To CSV", actionPerformed=self.buttonActionAutoConfigExportCsv)

		#  create button panel
		self._panelAutoConfigExportCsvButton = JPanel()

		# center button vertically
		self._panelAutoConfigExportCsvButton.setLayout(GridBagLayout())

		# add button to button panel
		self._panelAutoConfigExportCsvButton.add(self._buttonAutoConfigExportCsv)

		##### AutoConfig Tab - Export Log Table To CSV - End #####

		##### AutoConfig Tab - Import Log Table From CSV - Start #####

		# create button
		self._buttonAutoConfigImportCsv = JButton("Import Log Table From CSV", actionPerformed=self.buttonActionAutoConfigImportCsv)

		# create button panel
		self._panelAutoConfigImportCsvButton = JPanel()

		# center button vertically
		self._panelAutoConfigImportCsvButton.setLayout(GridBagLayout())

		# add button to button panel
		self._panelAutoConfigImportCsvButton.add(self._buttonAutoConfigImportCsv)

		##### AutoConfig Tab - Import Log Table From CSV - End #####

		##### AutoConfig Tab - AutoCopy - Start #####

		# create buttons
		self._buttonAutoConfigAutoCopy1 = JButton("Copy AutoProxy Settings To AutoTest", actionPerformed=self.buttonActionAutoConfigAutoCopy1)
		self._buttonAutoConfigAutoCopy2 = JButton("Copy AutoTest Settings To AutoProxy", actionPerformed=self.buttonActionAutoConfigAutoCopy2)
		self._buttonAutoConfigAutoCopy3 = JButton("Copy AutoText Hosts To AutoTest Hosts", actionPerformed=self.buttonActionAutoConfigAutoCopy3)

		# create button panels
		self._panelAutoConfigAutoCopyButton1 = JPanel()
		self._panelAutoConfigAutoCopyButton2 = JPanel()
		self._panelAutoConfigAutoCopyButton3 = JPanel()

		# center buttons vertically
		self._panelAutoConfigAutoCopyButton1.setLayout(GridBagLayout())
		self._panelAutoConfigAutoCopyButton2.setLayout(GridBagLayout())
		self._panelAutoConfigAutoCopyButton3.setLayout(GridBagLayout())

		# add buttons to button panels
		self._panelAutoConfigAutoCopyButton1.add(self._buttonAutoConfigAutoCopy1)
		self._panelAutoConfigAutoCopyButton2.add(self._buttonAutoConfigAutoCopy2)
		self._panelAutoConfigAutoCopyButton3.add(self._buttonAutoConfigAutoCopy3)

		##### AutoConfig Tab - AutoCopy - End #####

		##### AutoConfig Tab - AutoClear - Start #####

		# create buttons
		self._buttonAutoConfigAutoClear1 = JButton("Clear AutoProxy Logs/Data", actionPerformed=self.buttonActionAutoConfigAutoClear1)
		self._buttonAutoConfigAutoClear2 = JButton("Clear AutoProxy/AutoTest Settings & Filters", actionPerformed=self.buttonActionAutoConfigAutoClear2)
		self._buttonAutoConfigAutoClear3 = JButton("Undo Clear AutoProxy/AutoTest Settings & Filters", actionPerformed=self.buttonActionAutoConfigAutoClear3)

		# create panels for buttons
		self._panelAutoConfigAutoClear1 = JPanel()
		self._panelAutoConfigAutoClear2 = JPanel()
		self._panelAutoConfigAutoClear3 = JPanel()

		# center buttons vertically
		self._panelAutoConfigAutoClear1.setLayout(GridBagLayout())
		self._panelAutoConfigAutoClear2.setLayout(GridBagLayout())
		self._panelAutoConfigAutoClear3.setLayout(GridBagLayout())

		# add buttons to button panels
		self._panelAutoConfigAutoClear1.add(self._buttonAutoConfigAutoClear1)
		self._panelAutoConfigAutoClear2.add(self._buttonAutoConfigAutoClear2)
		self._panelAutoConfigAutoClear3.add(self._buttonAutoConfigAutoClear3)

		# create variables for undo clear AutoProxy settings
		self._textAreaAutoProxyForwardHostsInputUndo = ""
		self._textAreaAutoProxyInterceptHostsInputUndo = ""
		self._textAreaAutoProxyDropHostsInputUndo = ""

		# create variables for undo clear AutoTest settings
		self._textAreaAutoTestHostsInputUndo = ""
		self._textAreaAutoTestForwardHostsInputUndo = ""
		self._textAreaAutoTestInterceptHostsInputUndo = ""
		self._textAreaAutoTestDropHostsInputUndo = ""

		# create variables for undo clear AutoProxy filters
		self._textAreaAutoProxyAutoFilterMethodInputUndo = ""
		self._textAreaAutoProxyAutoFilterProtocolInputUndo = ""
		self._textAreaAutoProxyAutoFilterPortInputUndo = ""
		self._textAreaAutoProxyAutoFilterHostInputUndo = ""
		self._textAreaAutoProxyAutoFilterRefererInputUndo = ""
		self._textAreaAutoProxyAutoFilterUrlInputUndo = ""
		self._textAreaAutoProxyAutoFilterPathInputUndo = ""
		self._textAreaAutoProxyAutoFilterRequestInputUndo = ""
		self._textAreaAutoProxyAutoFilterResponseInputUndo = ""

		# create variables for undo clear AutoProxy checkbox filters
		self._checkboxAutoProxyAutoFilterActionNoUndo = ""
		self._checkboxAutoProxyAutoFilterActionForwardedUndo = ""
		self._checkboxAutoProxyAutoFilterActionInterceptedUndo = ""
		self._checkboxAutoProxyAutoFilterActionDroppedUndo = ""
		self._checkboxAutoProxyAutoFilterActionBlockedUndo = ""

		##### AutoConfig Tab - AutoClear - End #####

		##### AutoConfig Tab - Size Buttons - Start #####

		# get the preferred size of the widest in top section
		self._buttonSizeAutoConfigTop = self._buttonAutoConfigRestoreState.getPreferredSize()

		# get the preferred size of the widest in middle section
		self._buttonSizeAutoConfigMiddle = self._buttonAutoConfigImportCsv.getPreferredSize()

		# get the preferred size of the widest in bottom section
		self._buttonSizeAutoConfigBottom = self._buttonAutoConfigAutoClear3.getPreferredSize()

		# set preferred button size to set all buttons to the same width in top section
		self._buttonAutoConfigSaveState.setPreferredSize(self._buttonSizeAutoConfigTop)
		self._buttonAutoConfigRestoreState.setPreferredSize(self._buttonSizeAutoConfigTop)

		# set preferred button size to set all buttons to the same width in middle section
		self._buttonAutoConfigExportCsv.setPreferredSize(self._buttonSizeAutoConfigMiddle)
		self._buttonAutoConfigImportCsv.setPreferredSize(self._buttonSizeAutoConfigMiddle)

		# set preferred button size to set all buttons to the same width in bottom section
		self._buttonAutoConfigAutoCopy1.setPreferredSize(self._buttonSizeAutoConfigBottom)
		self._buttonAutoConfigAutoCopy2.setPreferredSize(self._buttonSizeAutoConfigBottom)
		self._buttonAutoConfigAutoCopy3.setPreferredSize(self._buttonSizeAutoConfigBottom)
		self._buttonAutoConfigAutoClear1.setPreferredSize(self._buttonSizeAutoConfigBottom)
		self._buttonAutoConfigAutoClear2.setPreferredSize(self._buttonSizeAutoConfigBottom)
		self._buttonAutoConfigAutoClear3.setPreferredSize(self._buttonSizeAutoConfigBottom)

		# set minimum button size to keep buttons the same size when the window shrinks in top section
		self._buttonAutoConfigSaveState.setMinimumSize(self._buttonSizeAutoConfigTop)
		self._buttonAutoConfigRestoreState.setMinimumSize(self._buttonSizeAutoConfigTop)

		# set minimum button size to keep buttons the same size when the window shrinks in middle section
		self._buttonAutoConfigExportCsv.setMinimumSize(self._buttonSizeAutoConfigMiddle)
		self._buttonAutoConfigImportCsv.setMinimumSize(self._buttonSizeAutoConfigMiddle)

		# set minimum button size to keep buttons the same size when the window shrinks in bottom section
		self._buttonAutoConfigAutoCopy1.setMinimumSize(self._buttonSizeAutoConfigBottom)
		self._buttonAutoConfigAutoCopy2.setMinimumSize(self._buttonSizeAutoConfigBottom)
		self._buttonAutoConfigAutoCopy3.setMinimumSize(self._buttonSizeAutoConfigBottom)
		self._buttonAutoConfigAutoClear1.setMinimumSize(self._buttonSizeAutoConfigBottom)
		self._buttonAutoConfigAutoClear2.setMinimumSize(self._buttonSizeAutoConfigBottom)
		self._buttonAutoConfigAutoClear3.setMinimumSize(self._buttonSizeAutoConfigBottom)

		##### AutoConfig Tab - Size Buttons - End #####

		##### AutoConfig Tab - Main - Start #####

		# create main panel for AutoConfig
		self._panelAutoConfigMain = JPanel()

		# set panel layout
		self._panelAutoConfigMain.setLayout(GridLayout(15, 2))

		# create a dictionary of blank panels to help with spacing
		dictionaryOfBlankPanels = dict()

		# create 12 blank JPanels to help with spacing
		for i in range(1, 13):

			# create panel and add to dictionary
			dictionaryOfBlankPanels[i] = JPanel()

			# check if the index is even to set left border on all panels in the right column
			if i % 2 == 0:

				# check if the index is 6
				if i == 6:

					# set top and left borders
					dictionaryOfBlankPanels[i].setBorder(BorderFactory.createMatteBorder(1, 1, 0, 0, Color.BLACK))

				# check if the index is 8
				elif i == 8:

					# set left and bottom borders
					dictionaryOfBlankPanels[i].setBorder(BorderFactory.createMatteBorder(0, 1, 1, 0, Color.BLACK))

				# index is even but not 6 or 8
				else:

					# set left border
					dictionaryOfBlankPanels[i].setBorder(BorderFactory.createMatteBorder(0, 1, 0, 0, Color.BLACK))

			# check if the index is 5
			elif i == 5:

				# set top border
				dictionaryOfBlankPanels[i].setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, Color.BLACK))

			# check if the index is 7
			elif i == 7:

				# set bottom border
				dictionaryOfBlankPanels[i].setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Color.BLACK))

		# set left border on all panels in the right column
		self._panelAutoConfigRestoreStateCheckbox1.setBorder(BorderFactory.createMatteBorder(0, 1, 0, 0, Color.BLACK))
		self._panelAutoConfigRestoreStateCheckbox2.setBorder(BorderFactory.createMatteBorder(0, 1, 0, 0, Color.BLACK))
		self._panelAutoConfigRestoreStateCheckbox3.setBorder(BorderFactory.createMatteBorder(0, 1, 0, 0, Color.BLACK))
		self._panelAutoConfigRestoreStateCheckbox4.setBorder(BorderFactory.createMatteBorder(0, 1, 0, 0, Color.BLACK))
		self._panelAutoConfigRestoreStateButton.setBorder(BorderFactory.createMatteBorder(0, 1, 0, 0, Color.BLACK))
		self._panelAutoConfigImportCsvButton.setBorder(BorderFactory.createMatteBorder(0, 1, 0, 0, Color.BLACK))
		self._panelAutoConfigAutoClear1.setBorder(BorderFactory.createMatteBorder(0, 1, 0, 0, Color.BLACK))
		self._panelAutoConfigAutoClear2.setBorder(BorderFactory.createMatteBorder(0, 1, 0, 0, Color.BLACK))
		self._panelAutoConfigAutoClear3.setBorder(BorderFactory.createMatteBorder(0, 1, 0, 0, Color.BLACK))

		# set row 1 of AutoConfig tab
		self._panelAutoConfigMain.add(dictionaryOfBlankPanels[1])
		self._panelAutoConfigMain.add(dictionaryOfBlankPanels[2])

		# set row 2 of AutoConfig tab
		self._panelAutoConfigMain.add(self._panelAutoConfigSaveStateCheckbox1)
		self._panelAutoConfigMain.add(self._panelAutoConfigRestoreStateCheckbox1)

		# set row 3 of AutoConfig tab
		self._panelAutoConfigMain.add(self._panelAutoConfigSaveStateCheckbox2)
		self._panelAutoConfigMain.add(self._panelAutoConfigRestoreStateCheckbox2)

		# set row 4 of AutoConfig tab
		self._panelAutoConfigMain.add(self._panelAutoConfigSaveStateCheckbox3)
		self._panelAutoConfigMain.add(self._panelAutoConfigRestoreStateCheckbox3)

		# set row 5 of AutoConfig tab
		self._panelAutoConfigMain.add(self._panelAutoConfigSaveStateCheckbox4)
		self._panelAutoConfigMain.add(self._panelAutoConfigRestoreStateCheckbox4)

		# set row 6 of AutoConfig tab
		self._panelAutoConfigMain.add(self._panelAutoConfigSaveStateButton)
		self._panelAutoConfigMain.add(self._panelAutoConfigRestoreStateButton)

		# set row 7 of AutoConfig tab
		self._panelAutoConfigMain.add(dictionaryOfBlankPanels[3])
		self._panelAutoConfigMain.add(dictionaryOfBlankPanels[4])

		# set row 8 of AutoConfig tab
		self._panelAutoConfigMain.add(dictionaryOfBlankPanels[5])
		self._panelAutoConfigMain.add(dictionaryOfBlankPanels[6])

		# set row 9 of AutoConfig tab
		self._panelAutoConfigMain.add(self._panelAutoConfigExportCsvButton)
		self._panelAutoConfigMain.add(self._panelAutoConfigImportCsvButton)

		# set row 10 of AutoConfig tab
		self._panelAutoConfigMain.add(dictionaryOfBlankPanels[7])
		self._panelAutoConfigMain.add(dictionaryOfBlankPanels[8])

		# set row 11 of AutoConfig tab
		self._panelAutoConfigMain.add(dictionaryOfBlankPanels[9])
		self._panelAutoConfigMain.add(dictionaryOfBlankPanels[10])

		# set row 12 of AutoConfig tab
		self._panelAutoConfigMain.add(self._panelAutoConfigAutoCopyButton1)
		self._panelAutoConfigMain.add(self._panelAutoConfigAutoClear1)

		# set row 13 of AutoConfig tab
		self._panelAutoConfigMain.add(self._panelAutoConfigAutoCopyButton2)
		self._panelAutoConfigMain.add(self._panelAutoConfigAutoClear2)

		# set row 14 of AutoConfig tab
		self._panelAutoConfigMain.add(self._panelAutoConfigAutoCopyButton3)
		self._panelAutoConfigMain.add(self._panelAutoConfigAutoClear3)

		# set row 15 of AutoConfig tab
		self._panelAutoConfigMain.add(dictionaryOfBlankPanels[11])
		self._panelAutoConfigMain.add(dictionaryOfBlankPanels[12])

		##### AutoConfig Tab - Main - End #####

		#
		# AutoBlock Tab - Start
		#

		##### AutoBlock Tab - Main - Start #####

		# set the number of panels
		self._numberOfAutoBlockPanels = 9

		# create a dictionary of block panels
		self._dictionaryOfBlockObjects = dict()

		# set text for title labels
		self._dictionaryOfBlockObjects["labelTitleText1"] = "Download & Enable All"
		self._dictionaryOfBlockObjects["labelTitleText2"] = "Cameleon Block List"
		self._dictionaryOfBlockObjects["labelTitleText3"] = "Disconnect.me Ads Block List"
		self._dictionaryOfBlockObjects["labelTitleText4"] = "Disconnect.me Tracking Block List"
		self._dictionaryOfBlockObjects["labelTitleText5"] = "hpHosts Block List"
		self._dictionaryOfBlockObjects["labelTitleText6"] = "Malware Domains Block List"
		self._dictionaryOfBlockObjects["labelTitleText7"] = "Steven Black's Block List"
		self._dictionaryOfBlockObjects["labelTitleText8"] = "Zeustracker Block List"
		self._dictionaryOfBlockObjects["labelTitleText9"] = "Custom Block List"

		# set text for url labels
		self._dictionaryOfBlockObjects["labelUrlText2"] = "http://sysctl.org/cameleon/hosts"
		self._dictionaryOfBlockObjects["labelUrlText3"] = "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt"
		self._dictionaryOfBlockObjects["labelUrlText4"] = "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt"
		self._dictionaryOfBlockObjects["labelUrlText5"] = "https://hosts-file.net/download/hosts.txt"
		self._dictionaryOfBlockObjects["labelUrlText6"] = "https://mirror1.malwaredomains.com/files/justdomains"
		self._dictionaryOfBlockObjects["labelUrlText7"] = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
		self._dictionaryOfBlockObjects["labelUrlText8"] = "https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist"

		# set filenames for downloading the block lists
		self._dictionaryOfBlockObjects["fileNameText2"] = "BurpAutoProxyBlockList-Cameleon.txt"
		self._dictionaryOfBlockObjects["fileNameText3"] = "BurpAutoProxyBlockList-DisconnectMeAds.txt"
		self._dictionaryOfBlockObjects["fileNameText4"] = "BurpAutoProxyBlockList-DisconnectMeTracking.txt"
		self._dictionaryOfBlockObjects["fileNameText5"] = "BurpAutoProxyBlockList-HpHosts.txt"
		self._dictionaryOfBlockObjects["fileNameText6"] = "BurpAutoProxyBlockList-MalwareDomains.txt"
		self._dictionaryOfBlockObjects["fileNameText7"] = "BurpAutoProxyBlockList-StevenBlack.txt"
		self._dictionaryOfBlockObjects["fileNameText8"] = "BurpAutoProxyBlockList-Zeustracker.txt"

		# create variable to store the path when downloading a block file to allow automatic importing
		self._autoBlockAutomatedPath = ""

		# create variable to determine if enable blocking button click is automated or manual
		self._autoBlockAutomatedOrManualClick = "Manual Click"

		# create a dictionary of block lists
		self._dictionaryOfAutoBlockLists = {}

		# get width of widest possible button
		tempButtonForSize = JButton("Blocking Disabled")
		tempButtonSize = tempButtonForSize.getPreferredSize()

		# create labels and buttons
		for i in range(1, self._numberOfAutoBlockPanels + 1):

			# check if first section
			if i == 1:

				# create label and button then add them to dictionary
				self._dictionaryOfBlockObjects["labelTitle" + str(i)] = JLabel(self._dictionaryOfBlockObjects["labelTitleText" + str(i)], JLabel.CENTER)
				self._dictionaryOfBlockObjects["buttonDownload" + str(i)] = JButton("Download Lists", actionPerformed=self.buttonActionDownloadBlocking)

				# set button name for indexing button clicks
				self._dictionaryOfBlockObjects["buttonDownload" + str(i)].setName(str(i))

				# set preferred button size
				self._dictionaryOfBlockObjects["buttonDownload" + str(i)].setPreferredSize(tempButtonSize)

			# check if last section
			elif i == 9:

				# create label and button then add them to dictionary
				self._dictionaryOfBlockObjects["labelTitle" + str(i)] = JLabel(self._dictionaryOfBlockObjects["labelTitleText" + str(i)], JLabel.CENTER)
				self._dictionaryOfBlockObjects["buttonEnableDisable" + str(i)] = JButton("Blocking Disabled", actionPerformed=self.buttonActionEnableDisableBlocking)

				# set background to red
				self._dictionaryOfBlockObjects["buttonEnableDisable" + str(i)].setBackground(Color(255, 100, 100))

				# set button name for indexing button clicks
				self._dictionaryOfBlockObjects["buttonEnableDisable" + str(i)].setName(str(i))

				# set preferred button size
				self._dictionaryOfBlockObjects["buttonEnableDisable" + str(i)].setPreferredSize(tempButtonSize)

				# create a list of hosts to block
				self._dictionaryOfAutoBlockLists["autoBlockList" + str(i)] = []

			# all other sections
			else:
				# create labels and buttons then add them to dictionary
				self._dictionaryOfBlockObjects["labelTitle" + str(i)] = JLabel(self._dictionaryOfBlockObjects["labelTitleText" + str(i)], JLabel.CENTER)
				self._dictionaryOfBlockObjects["labelUrl" + str(i)] = JLabel(self._dictionaryOfBlockObjects["labelUrlText" + str(i)], JLabel.CENTER)
				self._dictionaryOfBlockObjects["buttonDownload" + str(i)] = JButton("Download List", actionPerformed=self.buttonActionDownloadBlocking)
				self._dictionaryOfBlockObjects["buttonEnableDisable" + str(i)] = JButton("Blocking Disabled", actionPerformed=self.buttonActionEnableDisableBlocking)

				# set background to red
				self._dictionaryOfBlockObjects["buttonEnableDisable" + str(i)].setBackground(Color(255, 100, 100))

				# set button name for indexing button clicks
				self._dictionaryOfBlockObjects["buttonDownload" + str(i)].setName(str(i))
				self._dictionaryOfBlockObjects["buttonEnableDisable" + str(i)].setName(str(i))

				# create a list of hosts to block
				self._dictionaryOfAutoBlockLists["autoBlockList" + str(i)] = []

				# set preferred button size
				self._dictionaryOfBlockObjects["buttonDownload" + str(i)].setPreferredSize(tempButtonSize)
				self._dictionaryOfBlockObjects["buttonEnableDisable" + str(i)].setPreferredSize(tempButtonSize)

		# create main panel for AutoConfig
		self._panelAutoBlockDomainsMain = JPanel()

		# set panel layout
		self._panelAutoBlockDomainsMain.setLayout(GridLayout(9, 2))

		# add objects to main panel
		for i in range(1, self._numberOfAutoBlockPanels + 1):

			# create left panel
			tempPanel1 = JPanel()
			tempPanel1.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Color.BLACK))

			# create top and bottom of right panel
			tempPanel2a = JPanel()
			tempPanel2b = JPanel()
			tempPanel2a.setLayout(GridBagLayout())
			tempPanel2b.setLayout(GridBagLayout())

			# create right panel
			tempPanel2 = JPanel()
			tempPanel2.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Color.BLACK))

			# check if first section
			if i == 1:

				# finish creating left panel
				tempPanel1.setLayout(GridLayout(1, 1))
				tempPanel1.add(self._dictionaryOfBlockObjects["labelTitle" + str(i)])

				# finish creating the inside of the right panel
				tempPanel2a.add(self._dictionaryOfBlockObjects["buttonDownload" + str(i)])

				# finish creating right panel
				tempPanel2.setLayout(GridLayout(1, 1))
				tempPanel2.add(tempPanel2a)

			# check if lastsection
			elif i == 9:

				# finish creating left panel
				tempPanel1.setLayout(GridLayout(1, 1))
				tempPanel1.add(self._dictionaryOfBlockObjects["labelTitle" + str(i)])

				# finish creating the inside of the right panel
				tempPanel2b.add(self._dictionaryOfBlockObjects["buttonEnableDisable" + str(i)])

				# finish creating right panel
				tempPanel2.setLayout(GridLayout(1, 1))
				tempPanel2.add(tempPanel2b)

			# all other sections
			else:
				# finish creating left panel
				tempPanel1.setLayout(GridLayout(2, 1))
				tempPanel1.add(self._dictionaryOfBlockObjects["labelTitle" + str(i)])
				tempPanel1.add(self._dictionaryOfBlockObjects["labelUrl" + str(i)])

				# finish creating the inside of the right panel
				tempPanel2a.add(self._dictionaryOfBlockObjects["buttonDownload" + str(i)])
				tempPanel2b.add(self._dictionaryOfBlockObjects["buttonEnableDisable" + str(i)])

				# finish creating right panel
				tempPanel2.setLayout(GridLayout(2, 1))
				tempPanel2.add(tempPanel2a)
				tempPanel2.add(tempPanel2b)

			# add left and right panel for each row
			self._panelAutoBlockDomainsMain.add(tempPanel1)
			self._panelAutoBlockDomainsMain.add(tempPanel2)

		##### AutoBlock Tab - Main - End #####

		# create main four tabs
		self._tabsMain = JTabbedPane()
		self._tabsMain.addTab("AutoProxy", self._splitpaneAutoProxyVertical1)
		self._tabsMain.addTab("AutoTest", self._splitpaneAutoTestHorizontal1)
		self._tabsMain.addTab("AutoConfig", self._panelAutoConfigMain)
		self._tabsMain.addTab("AutoBlock", self._panelAutoBlockDomainsMain)

		# add change listener to fix log table issue after restore/import
		self._tabsMain.addChangeListener(self.propertyChangeAutoProxyMainTab)

		# customize UI components (recursive on child components)
		callbacks.customizeUiComponent(self._tabsMain)

		# add custom tab to Burp's UI
		callbacks.addSuiteTab(self)

		# register as proxy listener
		callbacks.registerProxyListener(self)

		# register context menu factory
		callbacks.registerContextMenuFactory(self)

		# print text to output window
		print(self._EXTENSION_NAME + " v" + self._EXTENSION_VERSION)
		print("Created by James Morris")
		print("https://github.com/JamesMorris-BurpSuite/")

		# end of BurpExtender
		return


	#
	# implement ITab
	#

	# set tab caption
	def getTabCaption(self):
		return self._EXTENSION_NAME

	# set main component
	def getUiComponent(self):
		return self._tabsMain


	#
	# extend IMessageEditorController to allow the request/response viewers to obtain details about the messages being displayed
	#

	# get the http service for the selected log table row
	def getHttpService(self):
		return self._currentlyDisplayedLogEntry.getHttpService()

	# get the request for the selected log table row
	def getRequest(self):
		return self._currentlyDisplayedLogEntry.getRequest()

	# get the response for the selected log table row
	def getResponse(self):
		return self._currentlyDisplayedLogEntry.getResponse()


	#
	# extend AbstractTableModel getRowCount for log table
	#

	def getRowCount(self):

		# return log size if it exists
		try:
			return self._log.size()

		# else return 0
		except:
			return 0


	#
	# extend AbstractTableModel getColumnCount for log table
	#

	def getColumnCount(self):
		return 10


	#
	# extend AbstractTableModel getColumnName for log table
	#

	def getColumnName(self, columnIndex):

		# return column name for Time column
		if columnIndex == 0:
			return "Time"

		# return column name for Method column
		if columnIndex == 1:
			return "Method"

		# return column name for Protocol column
		if columnIndex == 2:
			return "Protocol"

		# return column name for Port column
		if columnIndex == 3:
			return "Port"

		# return column name for Host column
		if columnIndex == 4:
			return "Host"

		# return column name for AutoAction column
		if columnIndex == 5:
			return "AutoAction"

		# return column name for Reason column
		if columnIndex == 6:
			return "Reason"

		# return column name for Referer column
		if columnIndex == 7:
			return "Referer"

		# return column name for URL column
		if columnIndex == 8:
			return "URL"

		# return column name for Path column
		if columnIndex == 9:
			return "Path"


	#
	# extend AbstractTableModel getValueAt for log table
	#

	def getValueAt(self, rowIndex, columnIndex):

		# get log entry for row
		logEntry = self._log.get(rowIndex)

		# return value for time column
		if columnIndex == 0:
			return logEntry.time

		# return value for method column
		if columnIndex == 1:
			return logEntry.method

		# return value for protocol column
		if columnIndex == 2:
			return logEntry.protocol

		# return value for port column
		if columnIndex == 3:
			return logEntry.port

		# return value for host column
		if columnIndex == 4:
			return logEntry.host

		# return value for action column
		if columnIndex == 5:
			return logEntry.action

		# return value for reason column
		if columnIndex == 6:
			return logEntry.reason

		# return value for referer column
		if columnIndex == 7:
			return logEntry.referer

		# return value for url column
		if columnIndex == 8:
			return logEntry.url

		# return value for path column
		if columnIndex == 9:
			return logEntry.path


	#
	# implement insert or delete log entries
	#

	def insertOrDeleteLogs(self, logAction, logPlacement, logEntryValues):

		# get the log size
		logSize = self._log.size()

		# check if action is to insert
		if logAction == "insert":

			# get log entry values
			time = logEntryValues[0]
			method = logEntryValues[1]
			protocol = logEntryValues[2]
			port = logEntryValues[3]
			host = logEntryValues[4]
			action = logEntryValues[5]
			reason = logEntryValues[6]
			referer = logEntryValues[7]
			url = logEntryValues[8]
			path = logEntryValues[9]
			request = logEntryValues[10]
			response = logEntryValues[11]
			requestResponseId = logEntryValues[12]

			# check if action is to insert into the first row
			if logPlacement == "first row":

				# add to start of log array list
				self._log.add(0, CustomLogEntry(time, method, protocol, port, host, action, reason, referer, url, path, request, response, requestResponseId))

			# insert into the last row
			else:
				# add to end of log array list
				self._log.add(CustomLogEntry(time, method, protocol, port, host, action, reason, referer, url, path, request, response, requestResponseId))

			# add to log table
			# SwingUtilities.invokeLater(CustomRunnable(self, logAction, logSize, logSize))

			# try to update the log table
			try:
				SwingUtilities.invokeLater(CustomRunnable(self, "update", 0, 0))
			except:
				pass

		# check if action is to delete
		elif logAction == "delete":

			# clear log array list
			self._log.clear()

			# set lock to not update request viewer when clearing the log table
			self._customJTableLogsTableChangeLock = True

			# add to log table
			SwingUtilities.invokeLater(CustomRunnable(self, logAction, 0, logSize - 1))

			# clear request viewer
			self._requestViewerAutoProxy.setMessage("", True)

			# clear response viewer
			self._responseViewerAutoProxy.setMessage("", True)


	#
	# implement IProxyListener
	#

	def processProxyMessage(self, messageIsRequest, message):

		# check if message is a response
		if not messageIsRequest:

			# get the requestResponseId
			requestResponseId = message.getMessageReference()

			# get the log size
			logSize = self._log.size()

			# loop through the logs
			for x in range(0, logSize):

				# check if the requestResponseId matches
				if self._log[x].requestResponseId == requestResponseId:
					
					# add the response to the logs
					self._log[x].response = self._callbacks.saveBuffersToTempFiles(message.getMessageInfo())

					# do not continue through the logs
					break

			# do not continue since it is a response
			return

		# check if the log table should be cleared automatically
		if self._autoClearLogTable == True:

			# check if the log table size is over the amount to clear
			if self._log.size() > self._autoClearLogTableAmount:

				# clear current logs and data
				self.buttonActionAutoConfigAutoClear1(self)

		# acquire the lock
		self._lock.acquire()

		# get hosts to forward
		hostsToForward = self._textAreaAutoProxyForwardHostsInput

		# get hosts to intercept
		hostsToIntercept = self._textAreaAutoProxyInterceptHostsInput

		# get hosts to drop
		hostsToDrop = self._textAreaAutoProxyDropHostsInput

		# set log table info
		time = datetime.now().strftime("%m-%d-%y %H:%M:%S")
		method = message.getMessageInfo().getRequest().tostring().split(" ", 1)[0]
		protocol = message.getMessageInfo().getHttpService().getProtocol()
		port = message.getMessageInfo().getHttpService().getPort()
		host = message.getMessageInfo().getHttpService().getHost()
		action = "No"
		reason = ""
		referer = ""
		path = message.getMessageInfo().getRequest().tostring().split(" ", 2)[1]
		request = self._callbacks.saveBuffersToTempFiles(message.getMessageInfo())
		requestResponseId = message.getMessageReference()
		body = message.getMessageInfo().getRequest().tostring()

		# check if http on port 80 or https on port 443
		if (protocol == "http" and port == 80) or (protocol == "https" and port == 443):

			# set the url without a port number
			url = protocol + "://" + host + path

		# not a standard protocol and port
		else:
			# set the url with a port number
			url = protocol + "://" + host + ":" + str(port) + path

		# get ip address
		# import socket
		# socket.gethostbyname(host)

		# loop each line in the request
		for line in message.getMessageInfo().getRequest().tostring().splitlines():

			# check if referer is in the line
			if "Referer: " in line:

				# get the referer line without the word referer
				referer = line.split(" ", 1)[1]

				# do not continue through the request
				break

		# regex lookup to determine AutoAction for current host
		def autoActionCheck(currentAction, hostRegexInput, textAreaName, method, protocol, port, host, action, currentReason, referer, url, path, body):

			# check if host should have an auto action 
			if currentAction == "No" and hostRegexInput.getText() != None and hostRegexInput.getText() != "":

				# create index for hostRegexInput
				rowIndex = 0

				# loop through each row
				for rowHostRegexInput in hostRegexInput.getText().splitlines():

					# try to search using regex
					try:
						# check if matching by method
						if rowHostRegexInput.startswith("Method: ") and len(rowHostRegexInput) > 8:

							# split string to remove "Method: "
							rowHostRegexInputMethod = rowHostRegexInput[8:]

							# check if method contains the data
							if re.search("(?i)" + rowHostRegexInputMethod, method):

								# return new action and reason
								return action, rowHostRegexInput

						# check if matching by protocol
						if rowHostRegexInput.startswith("Protocol: ") and len(rowHostRegexInput) > 10:

							# split string to remove "Protocol: "
							rowHostRegexInputProtocol = rowHostRegexInput[10:]

							# check if protocol contains the data
							if re.search("(?i)^" + rowHostRegexInputProtocol + "$", protocol):

								# return new action and reason
								return action, rowHostRegexInput

						# check if matching by port
						if rowHostRegexInput.startswith("Port: ") and len(rowHostRegexInput) > 6:

							# split string to remove "Port: "
							rowHostRegexInputPort = rowHostRegexInput[6:]

							# check if port contains the data
							if re.search("(?i)^" + rowHostRegexInputPort + "$", unicode(port)):

								# return new action and reason
								return action, rowHostRegexInput

						# match by host name
						if rowHostRegexInput.startswith("Host: ") and len(rowHostRegexInput) > 6:

							# split string to remove "Host: "
							rowHostRegexInputHost = rowHostRegexInput[6:]

							# check if host contains the data
							if re.search("(?i)" + rowHostRegexInputHost, host):

								# return new action and reason
								return action, rowHostRegexInput

						# check if matching by referer
						if rowHostRegexInput.startswith("Referer: ") and len(rowHostRegexInput) > 9:

							# split string to remove "Referer: "
							rowHostRegexInputReferer = rowHostRegexInput[9:]

							# check if referer contains the data
							if re.search("(?i)" + rowHostRegexInputReferer, referer):

								# return new action and reason
								return action, rowHostRegexInput

						# check if matching by URL
						if rowHostRegexInput.startswith("URL: ") and len(rowHostRegexInput) > 5:

							# split string to remove "URL: "
							rowHostRegexInputUrl = rowHostRegexInput[5:]

							# check if URL contains the data
							if re.search("(?i)" + rowHostRegexInputUrl, url):

								# return new action and reason
								return action, rowHostRegexInput

						# check if matching by path
						elif rowHostRegexInput.startswith("Path: ") and len(rowHostRegexInput) > 6:

							# split string to remove "Path: "
							rowHostRegexInputPath = rowHostRegexInput[6:]

							# check if URL contains the data
							if re.search("(?i)" + rowHostRegexInputPath, path):

								# return new action and reason
								return action, rowHostRegexInput

						# check if matching by body
						elif rowHostRegexInput.startswith("Body: ") and len(rowHostRegexInput) > 6:

							# split string to remove "Body: "
							rowHostRegexInputBody = rowHostRegexInput[6:]

							# remove the first two line containing the url and host
							body = body.split("\n")[2:]

							# create a new body
							newBody = ""

							# loop through the current body
							for rowBody in body:

								# check if the row does not start with referer
								if not rowBody.startswith("Referer: "):

									# append row to new body
									newBody += rowBody

							# check if URL contains the data
							if re.search("(?i)" + rowHostRegexInputBody, newBody):

								# return new action and reason
								return action, rowHostRegexInput

						# match by host name
						else:
							# check if regex matches host
							if re.search("(?i)" + rowHostRegexInput, host):

								# return new action and reason
								return action, rowHostRegexInput
					# catch exception
					except re.error:

						# remove any text selections keeping the caret position in the same spot 
						self._textAreaAutoProxyForwardHostsInput.setCaretPosition(self._textAreaAutoProxyForwardHostsInput.getCaretPosition())
						self._textAreaAutoProxyInterceptHostsInput.setCaretPosition(self._textAreaAutoProxyInterceptHostsInput.getCaretPosition())
						self._textAreaAutoProxyDropHostsInput.setCaretPosition(self._textAreaAutoProxyDropHostsInput.getCaretPosition())

						# transfer focus to the tab in the middle section that is selected
						self._textAreaAutoProxyDropHostsInput.requestFocusInWindow()
						self._textAreaAutoProxyDropHostsInput.transferFocus()

						# create highlighter and painter
						highlighter = hostRegexInput.getHighlighter()
						painter = DefaultHighlighter.DefaultHighlightPainter(Color(255, 150, 150))

						# try to highlight row with incorrect regex
						try:
							# get starting and ending position for row
							highlightStart = hostRegexInput.getLineStartOffset(rowIndex)
							highlightEnd = hostRegexInput.getLineEndOffset(rowIndex)

							# add highlight to row
							highlighter.addHighlight(highlightStart, highlightEnd, painter)

						# catch exception
						except:
							regexStatus = "AutoTest Regex Highlight Error"

						# display error message and capture input
						errorChoice = JOptionPane.showOptionDialog(None, "Invalid Regex: "  + rowHostRegexInput + "\n(?i) is already included. (?i)your_regex_goes_here\nPlease select an option for the proxy request to " + host, "Regex Error in " + textAreaName, JOptionPane.DEFAULT_OPTION, JOptionPane.ERROR_MESSAGE, None, ["Drop","Intercept","Forward"], "Drop")

						# set action from user input
						if errorChoice == 2:
							return "Forwarded", "User selection from regex error"
						elif errorChoice == 1:
							return "Intercepted", "User selection from regex error"
						else:
							return "Dropped", "User selection from regex error"

					# increment row index
					rowIndex += 1

			# action already set or not a match
			return currentAction, currentReason

		# check if host should be auto forwarded
		action, reason = autoActionCheck(action, hostsToForward, "AutoForward Hosts", method, protocol, port, host, "Forwarded", reason, referer, url, path, body)

		# check if host should be auto intercepted 
		action, reason = autoActionCheck(action, hostsToIntercept, "AutoIntercept Hosts", method, protocol, port, host, "Intercepted", reason, referer, url, path, body)

		# check if host should be auto dropped
		action, reason = autoActionCheck(action, hostsToDrop, "AutoDrop Hosts", method, protocol, port, host, "Dropped", reason, referer, url, path, body)

		# check if host should be blocked
		def blockHostCheck(currentAction, currentReason, host, blockHosts, blockReason):

			# loop through all of the hosts to block
			for blockHost in blockHosts:

				# check if host to block matches the current host
				if blockHost == host:

					# return new action and reason
					return "Blocked", blockReason

			# not a match
			return currentAction, currentReason

		# loop through all the possible block lists
		for i in range(2, self._numberOfAutoBlockPanels + 1):

			# determine if host should be checked if it is a host to be blocked 
			if action == "No" and self._dictionaryOfBlockObjects["buttonEnableDisable" + str(i)].getText() == "Blocking Enabled":

				# check if host should be blocked
				action, reason = blockHostCheck(action, reason, host, self._dictionaryOfAutoBlockLists["autoBlockList" + str(i)], self._dictionaryOfBlockObjects["labelTitleText" + str(i)])

		# check if action is to drop
		if action == "Dropped" or action == "Blocked":

			# set intercept action to ACTION_DROP
			message.setInterceptAction(3)

		# check if action is to forward
		elif action == "Forwarded":

			# set intercept action to ACTION_DONT_INTERCEPT
			message.setInterceptAction(2)

		# check if action is to intercept
		elif action == "Intercepted":

			# set intercept action to ACTION_INTERCEPT
			message.setInterceptAction(1)

		# insert data into the log table
		self.insertOrDeleteLogs("insert", "first row", [time, method, protocol, port, host, action, reason, referer, url, path, request, None, requestResponseId])

		# get host list tab
		allHosts = self._textEditorAutoProxyHostListTextFormat.getText()

		# check if None
		if allHosts == None:

			# release the lock
			self._lock.release()			

			# return
			return

		# assume host is not in list yet
		hostNotFound = True

		# loop through all of the hosts in the allHosts list
		for allHostsRow in allHosts.tostring().splitlines():

			# check if current row equals the current host
			if allHostsRow == host:

				# set host to found
				hostNotFound = False

				# break out of loop
				break

		# check if host is in host list tab
		if hostNotFound:

			# check if host list is emtpy
			if allHosts.tostring() == "":

				# add host to host list text format tab
				self._textEditorAutoProxyHostListTextFormat.setText(host)

				# add host to host list regex format tab
				self._textEditorAutoProxyHostListRegexFormat.setText(host.replace(".", "\."))

			else:
				# add host to beginning of host list text format tab
				self._textEditorAutoProxyHostListTextFormat.setText(host + "\n" + allHosts.tostring())

				# add host to beginning of host list regex format tab
				self._textEditorAutoProxyHostListRegexFormat.setText(host.replace(".", "\.") + "\n" + allHosts.tostring().replace(".","\."))

			# add to host table tab
			self._tableModelAutoProxyAutoAction.insertRow(0, [time, host, False, False, False])

		# check if a log table row is selected
		if self._currentlySelectedLogTableRow > -1:

			# increment the selected row since rows are added from the top
			self._currentlySelectedLogTableRow += 1

			# try to keep the same row selected
			try:
				# set the row to select accounting for sorting and filtering
				rowToSelect = self._tableAutoProxyLogs.convertRowIndexToView(self._currentlySelectedLogTableRow)
			except:
				# set row to select to -1 to clear selection
				rowToSelect = -1

				# clear selection when sorted
				self._currentlySelectedLogTableRow = -1

			# try to select the row that was selected before the new row was added from the top
			try:
				# keep same row selected
				self._tableAutoProxyLogs.setRowSelectionInterval(rowToSelect, rowToSelect)

			# row may not be visible due to filter on the table
			except:
				# try to clear the log table
				try:
					# clear the selection
					self._tableAutoProxyLogs.clearSelection()
					self._tableAutoProxyLogs.getSelectionModel().clearSelection()
				except:
					pass

				# clear request viewer
				self._requestViewerAutoProxy.setMessage("", True)

				# clear response viewer
				self._responseViewerAutoProxy.setMessage("", True)

		# release the lock
		self._lock.release()


	#
	# implement button action to automatically clear the log table and data
	#

	def buttonActionAutoProxyAutoClear(self, event):

		# check if auto clear is off
		if self._autoClearLogTable == False:

			# turn auto clear on
			self._autoClearLogTable = True

			# set auto clear amount to 100
			self._autoClearLogTableAmount = 100

			# set button text
			event.getSource().setText("<html><center>" + "Every" + "<br>" + "100" + "<br>" + "Rows" + "</center></html>")

		# auto clear is on
		else:
			# check if the auto clear amount is 100
			if self._autoClearLogTableAmount == 100:

				# set auto clear amount
				self._autoClearLogTableAmount = 1000

				# set button text
				event.getSource().setText("<html><center>" + "Every" + "<br>" + "1000" + "<br>" + "Rows" + "</center></html>")

			# the auto clear amount is 1000
			else:
				# turn auto clear off
				self._autoClearLogTable = False

				# set button text
				event.getSource().setText("Off")


	#
	# implement property change listener to detect when the main AutoProxy tab is selected and a restore or import has just been performed. This helps get rid of an issue where the log table shows duplicate rows after an import until the sorter/filter is called but calling it manually doesn't fix the issue possibly due to timing. 
	#

	def propertyChangeAutoProxyMainTab(self, event):

		# check if the main tab was selected and if the the restore/import flag is true
		if event.getSource().getSelectedIndex() == 0 and self._autoConfigRestoreOrImportLogTableFlag == True:

			# set restore/import flag to false
			self._autoConfigRestoreOrImportLogTableFlag = False

			# set intercepted filter to original value
			self._checkboxAutoProxyAutoFilterActionIntercepted.setSelected(self._autoConfigRestoreOrImportLogTableFilterValue)

			# try to sort the log table
			try:
				# filter the log table to recreate log table due to table freezing when restoring/importing
				self._tableRowSorterAutoProxyLogs.sort()

			# catch if table is being sorted by processProxyMessage and user
			except:
				pass


	#
	# implement property change listener to keep AutoTest vertical split panes the same height when any one is resized and to keep AutoProxy bottom horizontal split panes the same width as the top horizontal split panes when the tab is clicked
	#

	def propertyChangeDividerLocation(self, changedDivider, otherDividers):

		# get location of changed divider
		changedDividerLocation = changedDivider.getDividerLocation()

		# set location of other dividers
		for divider in otherDividers:
			divider.setDividerLocation(changedDividerLocation)


	#
	# implement property change listener to keep AutoProxy AutoFilter horizontal split panes the same height as the top dividers when the tab is clicked
	#

	def propertyChangeAutoProxyBottomTabs(self, event):

		# check if the filter tab was selected
		if event.getSource().getSelectedIndex() == 1:

			# set the first filter divider location
			self.propertyChangeDividerLocation(self._splitpaneAutoProxyHorizontal1, [self._splitpaneAutoProxyAutoFilterHorizontal1])

			# set the second filter divider location
			self.propertyChangeDividerLocation(self._splitpaneAutoProxyHorizontal2, [self._splitpaneAutoProxyAutoFilterHorizontal2])


	#
	# implement property change listener to keep AutoTest vertical split panes the same height when split pane 1 is resized
	#

	def propertyChangeAutoTest1(self, event):
		self.propertyChangeDividerLocation(self._splitpaneAutoTestVertical1, [self._splitpaneAutoTestVertical2, self._splitpaneAutoTestVertical3, self._splitpaneAutoTestVertical4])


	#
	# implement property change listener to keep AutoTest vertical split panes the same height when split pane 2 is resized
	#

	def propertyChangeAutoTest2(self, event):
		self.propertyChangeDividerLocation(self._splitpaneAutoTestVertical2, [self._splitpaneAutoTestVertical1, self._splitpaneAutoTestVertical3, self._splitpaneAutoTestVertical4])


	#
	# implement property change listener to keep AutoTest vertical split panes the same height when split pane 3 is resized
	#

	def propertyChangeAutoTest3(self, event):
		self.propertyChangeDividerLocation(self._splitpaneAutoTestVertical3, [self._splitpaneAutoTestVertical1, self._splitpaneAutoTestVertical2, self._splitpaneAutoTestVertical4])


	#
	# implement property change listener to keep AutoTest vertical split panes the same height when split pane 4 is resized
	#

	def propertyChangeAutoTest4(self, event):
		self.propertyChangeDividerLocation(self._splitpaneAutoTestVertical4, [self._splitpaneAutoTestVertical1, self._splitpaneAutoTestVertical2, self._splitpaneAutoTestVertical3])


	#
	# implement button action to test AutoTest settings
	#

	def buttonActionAutoTest(self, event):

		# test regex in AutoTest tab
		def testAutoTestRegex(hostRegexInput, textAreaName, suppressRegexAlert):

			# set default regex status
			regexStatus = "No Error"

			# create index for hostRegexInput
			rowIndex = 0

			# loop through each row of regex (Lines split with \r\n)
			for rowHostRegexInput in hostRegexInput.getText().splitlines():

				# try to test regex
				try:
					regexSearch = re.search("(?i)" + rowHostRegexInput, "test")

				# catch exception
				except re.error:

					# remove any text selections keeping the caret position in the same spot 
					self._textAreaAutoTestHostsInput.setCaretPosition(self._textAreaAutoTestHostsInput.getCaretPosition())
					self._textAreaAutoTestForwardHostsInput.setCaretPosition(self._textAreaAutoTestForwardHostsInput.getCaretPosition())
					self._textAreaAutoTestInterceptHostsInput.setCaretPosition(self._textAreaAutoTestInterceptHostsInput.getCaretPosition())

					self._textAreaAutoTestDropHostsInput.setCaretPosition(self._textAreaAutoTestDropHostsInput.getCaretPosition())

					# set regex status to error
					regexStatus = "Error"

					# create highlighter and painter
					highlighter = hostRegexInput.getHighlighter()
					painter = DefaultHighlighter.DefaultHighlightPainter(Color(255, 150, 150))

					# try to highlight row with incorrect regex
					try:
						# get starting and ending position for row
						highlightStart = hostRegexInput.getLineStartOffset(rowIndex)
						highlightEnd = hostRegexInput.getLineEndOffset(rowIndex)

						# add highlight to row
						highlighter.addHighlight(highlightStart, highlightEnd, painter)

					# catch exception
					except:
						regexStatus = "AutoTest Regex Highlight Error"

					# check if alerting should not be suppressed
					if suppressRegexAlert != True:

						# display the regex error asking if future alerts should be suppressed
						errorChoice = JOptionPane.showOptionDialog(None, "Invalid Regex: " + rowHostRegexInput + "\n(?i) is already included. (?i)your_regex_goes_here", "Regex Error in " + textAreaName, JOptionPane.DEFAULT_OPTION, JOptionPane.ERROR_MESSAGE, None, ["OK", "Suppress Alerts"], "OK")

						# check if error choice was to suppress alerts
						if errorChoice == 1:

							# suppress regex alerting
							suppressRegexAlert = True

				# increment row index
				rowIndex += 1

			# return regex status
			return regexStatus, suppressRegexAlert

		# perform the AutoTest
		def autoTest(currentAction, action, hostToTest, hostRegexInput):

			# check if action is already set
			if currentAction != "NoAction":
				return currentAction

			# loop through each row of regex
			for rowHostRegexInput in hostRegexInput.getText().splitlines():

				# try to test regex
				try:
					# check if regex matches host
					if re.search("(?i)" + rowHostRegexInput, hostToTest):

						# return matched action
						return action

				# catch exception
				except re.error:

					# regex error
					return "Error"

			# action was not a match
			return currentAction

		# remove lines with only spaces and tabs
		def removeBlankLines(textAreaAutoTestHostsInput):

			# create new hosts input
			newHostsInput = ""

			# loop through each row
			for row in textAreaAutoTestHostsInput.getText().splitlines():

				# check if the row contains text
				if not re.search("^[ \t]*$", row):

					# add row to new hosts input
					newHostsInput += row + "\r\n"

			# remove trailing line breaks
			newHostsInput = newHostsInput.rstrip("\r\n")

			# update HostsInput text
			textAreaAutoTestHostsInput.setText(newHostsInput)

		# remove lines with only spaces and tabs
		removeBlankLines(self._textAreaAutoTestHostsInput)

		# suppress regex error alert
		suppressRegexErrorAlert = False

		# test regex in each AutoTest host tab
		autoTestForwardErrorStatus, suppressRegexErrorAlert = testAutoTestRegex(self._textAreaAutoTestForwardHostsInput, "AutoForward Hosts", suppressRegexErrorAlert)
		autoTestInterceptErrorStatus, suppressRegexErrorAlert = testAutoTestRegex(self._textAreaAutoTestInterceptHostsInput, "AutoIntercept Hosts", suppressRegexErrorAlert)
		autoTestDropErrorStatus, suppressRegexErrorAlert = testAutoTestRegex(self._textAreaAutoTestDropHostsInput, "AutoDrop Hosts", suppressRegexErrorAlert)

		# check if there was a regex error
		if autoTestForwardErrorStatus == "Error" or autoTestInterceptErrorStatus == "Error" or autoTestDropErrorStatus == "Error":

			# set focus to host input so CustomFocusListener will be called if focus was in one of those text areas
			self._textAreaAutoTestHostsInput.requestFocusInWindow()

			# return
			return

		# create host lists for AutoTest results
		autoForwardedHosts = ""
		autoInterceptedHosts = ""
		autoDroppedHosts = ""
		noActionHosts = ""

		# loop through each host to test
		for rowHostsToTest in self._textAreaAutoTestHostsInput.getText().splitlines():

			# set action to NoAction by default
			currentAction = "NoAction"

			# test what the autoaction should be 
			currentAction = autoTest(currentAction, "Forward", rowHostsToTest, self._textAreaAutoTestForwardHostsInput)
			currentAction = autoTest(currentAction, "Intercept", rowHostsToTest, self._textAreaAutoTestInterceptHostsInput)
			currentAction = autoTest(currentAction, "Drop", rowHostsToTest, self._textAreaAutoTestDropHostsInput)

			# add tested host to autoForward list 
			if currentAction == "Forward":
				autoForwardedHosts += rowHostsToTest + "\r\n"

			# add tested host to autoIntercept list
			elif currentAction == "Intercept":
				autoInterceptedHosts += rowHostsToTest + "\r\n"

			# add tested host to autoDrop list
			elif currentAction == "Drop":
				autoDroppedHosts += rowHostsToTest + "\r\n"

			# add tested host to noAction list
			else:
				noActionHosts += rowHostsToTest + "\r\n"

		# remove trailing line breaks
		autoForwardedHosts = autoForwardedHosts.rstrip("\r\n")
		autoInterceptedHosts = autoInterceptedHosts.rstrip("\r\n")
		autoDroppedHosts = autoDroppedHosts.rstrip("\r\n")
		noActionHosts = noActionHosts.rstrip("\r\n")

		# set AutoTest output
		self._textAreaAutoTestForwardHostsOutput.setText(autoForwardedHosts)
		self._textAreaAutoTestInterceptHostsOutput.setText(autoInterceptedHosts)
		self._textAreaAutoTestDropHostsOutput.setText(autoDroppedHosts)
		self._textAreaAutoTestNoActionHostsOutput.setText(noActionHosts)

		# scroll to top of each output text area
		self._textAreaAutoTestForwardHostsOutput.setCaretPosition(0)
		self._textAreaAutoTestInterceptHostsOutput.setCaretPosition(0)
		self._textAreaAutoTestDropHostsOutput.setCaretPosition(0)
		self._textAreaAutoTestNoActionHostsOutput.setCaretPosition(0)


	#
	# implement dialog box for AutoConfig and AutoBlock import/enable
	#

	def dialogBoxAutoConfigOrAutoBlock(self, dialogTitle, extensionFilter, buttonText):

		# create frame
		frameAutoConfigDialogBox = JFrame()

		# try to load the last used directory
		try:
			# load the directory for future imports/exports
			fileChooserDirectory = self._callbacks.loadExtensionSetting("fileChooserDirectory")

		# there is not a last used directory
		except:
			# set the last used directory to blank
			fileChooserDirectory = ""

		# create file chooser
		fileChooserAutoConfigDialogBox = JFileChooser(fileChooserDirectory)

		# set dialog title
		fileChooserAutoConfigDialogBox.setDialogTitle(dialogTitle)

		# create extension filter
		filterAutoConfigDialogBox = FileNameExtensionFilter(extensionFilter[0], extensionFilter[1])

		# set extension filter
		fileChooserAutoConfigDialogBox.setFileFilter(filterAutoConfigDialogBox)

		# show dialog box and get value
		valueFileChooserAutoConfigDialogBox = fileChooserAutoConfigDialogBox.showDialog(frameAutoConfigDialogBox, buttonText)

		# check if a file was not selected
		if valueFileChooserAutoConfigDialogBox != JFileChooser.APPROVE_OPTION:
		
			# return no path/file selected
			return False, "No Path/File"

		# get the directory
		fileChooserDirectory = fileChooserAutoConfigDialogBox.getCurrentDirectory()#zzzzz

		# store the directory for future imports/exports
		self._callbacks.saveExtensionSetting("fileChooserDirectory", str(fileChooserDirectory))#zzzzz

		# get absolute path of file
		fileChosenAutoConfigDialogBox = fileChooserAutoConfigDialogBox.getSelectedFile().getAbsolutePath()

		# split name and extension
		fileNameAutoConfigDialogBox, fileExtensionAutoConfigDialogBox = os.path.splitext(fileChosenAutoConfigDialogBox)

		# check if file does not have an extention
		if fileExtensionAutoConfigDialogBox == "":

			# add extension to file
			fileChosenAutoConfigDialogBox = fileChosenAutoConfigDialogBox + extensionFilter[2]

		# return dialog box value and path/file
		return True, fileChosenAutoConfigDialogBox


	#
	# implement button action to save the state
	#

	def buttonActionAutoConfigSaveState(self, event):

		# check if no checkboxes are checked
		if self._checkboxAutoConfigSaveState1.isSelected() == False and self._checkboxAutoConfigSaveState2.isSelected() == False and self._checkboxAutoConfigSaveState3.isSelected() == False and self._checkboxAutoConfigSaveState4.isSelected() == False:

			# display message box
			dialogOption = JOptionPane.showMessageDialog(None, "Please select something to save.", "No Data Selected", JOptionPane.INFORMATION_MESSAGE)

			# do not continue
			return

		# set dialog options to send to dialogBoxAutoConfigOrAutoBlock
		dialogBoxTitle = "Save State File"
		dialogBoxExtensionFilter = ["JSON Files (*.json)", ["json"], ".json"]
		dialogBoxButtonText = "Save"

		# get the selected file
		fileChosen, fileAutoConfig = self.dialogBoxAutoConfigOrAutoBlock(dialogBoxTitle, dialogBoxExtensionFilter, dialogBoxButtonText)

		# return if user exited dialog box
		if fileChosen == False:
			return

		# open the file
		with open(fileAutoConfig, "w") as jsonFile:

			# create a json dictionary
			jsonDictionaryAutoConfigSave = {}

			# check if AutoProxy settings should be saved
			if self._checkboxAutoConfigSaveState1.isSelected():

				# save AutoProxy settings
				jsonDictionaryAutoConfigSave["AutoProxyForwardHosts"] = self._textAreaAutoProxyForwardHostsInput.getText()
				jsonDictionaryAutoConfigSave["AutoProxyInterceptHosts"] = self._textAreaAutoProxyInterceptHostsInput.getText()
				jsonDictionaryAutoConfigSave["AutoProxyDropHosts"] = self._textAreaAutoProxyDropHostsInput.getText()

			# AutoProxy settings should not be saved
			else:
				# do not save AutoProxy settings
				jsonDictionaryAutoConfigSave["AutoProxyForwardHosts"] = None
				jsonDictionaryAutoConfigSave["AutoProxyInterceptHosts"] = None
				jsonDictionaryAutoConfigSave["AutoProxyDropHosts"] = None

			# check if AutoProxy logs and data should be saved
			if self._checkboxAutoConfigSaveState2.isSelected():

				# create an array for the log table
				jsonDictionaryAutoConfigSave["AutoProxyLogTable"] = []

				# get the log size
				logSize = self._log.size()

				# get the host table size
				hostCount = self._tableAutoProxyAutoAction.getRowCount()

				# loop through the log array list
				for i in range(0, logSize):

					# create a temp json for each row
					tempJson = {}

					# create temp variables for each row
					tempJson["Time"] = self._log.get(i).time
					tempJson["Method"] = self._log.get(i).method
					tempJson["Protocol"] = self._log.get(i).protocol
					tempJson["Port"] = self._log.get(i).port
					tempJson["Host"] = self._log.get(i).host
					tempJson["Action"] = self._log.get(i).action
					tempJson["Reason"] = self._log.get(i).reason
					tempJson["Referer"] = self._log.get(i).referer
					tempJson["Url"] = self._log.get(i).url
					tempJson["Path"] = self._log.get(i).path
					tempJson["Request"] = base64.b64encode(self._log.get(i).request.getRequest())

					# try to encode response if one exists
					try:
						# encode response
						tempJson["Response"] = base64.b64encode(self._log.get(i).response.getResponse())
					except:
						# set response to none
						tempJson["Response"] = None

					# save AutoProxy log table
					jsonDictionaryAutoConfigSave["AutoProxyLogTable"].append(tempJson)

				# create an array for the host table
				jsonDictionaryAutoConfigSave["AutoProxyHostTable"] = []

				# loop through the log array list
				for i in range(0, hostCount):

					# create a temp json for each row
					tempJson = {}

					# create temp variables for each row
					tempJson["First Time Logged"] = self._tableAutoProxyAutoAction.getValueAt(i, 0)
					tempJson["Host"] = self._tableAutoProxyAutoAction.getValueAt(i, 1)
					tempJson["AutoForward"] = self._tableAutoProxyAutoAction.getValueAt(i, 2)
					tempJson["AutoIntercept"] = self._tableAutoProxyAutoAction.getValueAt(i, 3)
					tempJson["AutoDrop"] = self._tableAutoProxyAutoAction.getValueAt(i, 4)

					# save AutoProxy host table
					jsonDictionaryAutoConfigSave["AutoProxyHostTable"].append(tempJson)

				# save AutoProxy AutoRegex Hosts
				jsonDictionaryAutoConfigSave["AutoProxyAutoRegexHosts"] = self._textEditorAutoProxyHostListRegexFormat.getText().tostring()

				# save AutoProxy AutoText Hosts
				jsonDictionaryAutoConfigSave["AutoProxyAutoTextHosts"] = self._textEditorAutoProxyHostListTextFormat.getText().tostring()

			# AutoProxy logs and data should not be saved
			else:
				# do not save AutoProxy logs and data
				jsonDictionaryAutoConfigSave["AutoProxyLogTable"] = None
				jsonDictionaryAutoConfigSave["AutoProxyHostTable"] = None
				jsonDictionaryAutoConfigSave["AutoProxyAutoRegexHosts"] = None
				jsonDictionaryAutoConfigSave["AutoProxyAutoTextHosts"] = None

			# check if AutoProxy filters should be saved
			if self._checkboxAutoConfigSaveState3.isSelected():

				# save AutoProxy checkbox filters
				jsonDictionaryAutoConfigSave["AutoProxyFilterAutoActionNo"] = self._checkboxAutoProxyAutoFilterActionNo.isSelected()
				jsonDictionaryAutoConfigSave["AutoProxyFilterAutoActionForwarded"] = self._checkboxAutoProxyAutoFilterActionForwarded.isSelected()
				jsonDictionaryAutoConfigSave["AutoProxyFilterAutoActionIntercepted"] = self._checkboxAutoProxyAutoFilterActionIntercepted.isSelected()
				jsonDictionaryAutoConfigSave["AutoProxyFilterAutoActionDropped"] = self._checkboxAutoProxyAutoFilterActionDropped.isSelected()
				jsonDictionaryAutoConfigSave["AutoProxyFilterAutoActionBlocked"] = self._checkboxAutoProxyAutoFilterActionBlocked.isSelected()

				# save AutoProxy filters
				jsonDictionaryAutoConfigSave["AutoProxyFilterMethod"] = self._textAreaAutoProxyAutoFilterMethodInput.getText()
				jsonDictionaryAutoConfigSave["AutoProxyFilterProtocol"] = self._textAreaAutoProxyAutoFilterProtocolInput.getText()
				jsonDictionaryAutoConfigSave["AutoProxyFilterPort"] = self._textAreaAutoProxyAutoFilterPortInput.getText()
				jsonDictionaryAutoConfigSave["AutoProxyFilterHost"] = self._textAreaAutoProxyAutoFilterHostInput.getText()
				jsonDictionaryAutoConfigSave["AutoProxyFilterReferer"] = self._textAreaAutoProxyAutoFilterRefererInput.getText()
				jsonDictionaryAutoConfigSave["AutoProxyFilterUrl"] = self._textAreaAutoProxyAutoFilterUrlInput.getText()
				jsonDictionaryAutoConfigSave["AutoProxyFilterPath"] = self._textAreaAutoProxyAutoFilterPathInput.getText()
				jsonDictionaryAutoConfigSave["AutoProxyFilterRequest"] = self._textAreaAutoProxyAutoFilterRequestInput.getText()
				jsonDictionaryAutoConfigSave["AutoProxyFilterResponse"] = self._textAreaAutoProxyAutoFilterResponseInput.getText()

			# AutoProxy filters should not be saved
			else:

				# do not save AutoProxy checkbox filters
				jsonDictionaryAutoConfigSave["AutoProxyFilterAutoActionNo"] = None
				jsonDictionaryAutoConfigSave["AutoProxyFilterAutoActionForwarded"] = None
				jsonDictionaryAutoConfigSave["AutoProxyFilterAutoActionIntercepted"] = None
				jsonDictionaryAutoConfigSave["AutoProxyFilterAutoActionDropped"] = None
				jsonDictionaryAutoConfigSave["AutoProxyFilterAutoActionBlocked"] = None

				# do not save AutoProxy filters
				jsonDictionaryAutoConfigSave["AutoProxyFilterMethod"] = None
				jsonDictionaryAutoConfigSave["AutoProxyFilterProtocol"] = None
				jsonDictionaryAutoConfigSave["AutoProxyFilterPort"] = None
				jsonDictionaryAutoConfigSave["AutoProxyFilterHost"] = None
				jsonDictionaryAutoConfigSave["AutoProxyFilterReferer"] = None
				jsonDictionaryAutoConfigSave["AutoProxyFilterUrl"] = None
				jsonDictionaryAutoConfigSave["AutoProxyFilterPath"] = None
				jsonDictionaryAutoConfigSave["AutoProxyFilterRequest"] = None
				jsonDictionaryAutoConfigSave["AutoProxyFilterResponse"] = None

			# check if AutoTest settings should be saved
			if self._checkboxAutoConfigSaveState4.isSelected():

				# save AutoTest settings
				jsonDictionaryAutoConfigSave["AutoTestHosts"] = self._textAreaAutoTestHostsInput.getText()
				jsonDictionaryAutoConfigSave["AutoTestForwardHosts"] = self._textAreaAutoTestForwardHostsInput.getText()
				jsonDictionaryAutoConfigSave["AutoTestInterceptHosts"] = self._textAreaAutoTestInterceptHostsInput.getText()
				jsonDictionaryAutoConfigSave["AutoTestDropHosts"] = self._textAreaAutoTestDropHostsInput.getText()

			# AutoTest settings should not be saved
			else:
				# do not save AutoTest settings
				jsonDictionaryAutoConfigSave["AutoTestHosts"] = None
				jsonDictionaryAutoConfigSave["AutoTestForwardHosts"] = None
				jsonDictionaryAutoConfigSave["AutoTestInterceptHosts"] = None
				jsonDictionaryAutoConfigSave["AutoTestDropHosts"] = None

			# write json to file
			jsonFile.write(json.dumps(jsonDictionaryAutoConfigSave, ensure_ascii=False, indent=4, sort_keys=False, separators=(",", ": ")))


	#
	# implement button action to restore the state
	#

	def buttonActionAutoConfigRestoreState(self, event):

		# check if no checkboxes are checked
		if self._checkboxAutoConfigRestoreState1.isSelected() == False and self._checkboxAutoConfigRestoreState2.isSelected() == False and self._checkboxAutoConfigRestoreState3.isSelected() == False and self._checkboxAutoConfigRestoreState4.isSelected() == False:

			# display message box
			dialogOption = JOptionPane.showMessageDialog(None, "Please select something to restore.", "No Data Selected", JOptionPane.INFORMATION_MESSAGE)

			# do not continue
			return

		# create a message to display
		dialogMessage = ""

		# check if AutoProxy settings should be restored
		if self._checkboxAutoConfigRestoreState1.isSelected():

			# add to the dialog message
			dialogMessage += "Continuing will delete the current AutoProxy Settings.\n"

		# check if AutoProxy logs and data should be restored
		if self._checkboxAutoConfigRestoreState2.isSelected():

			# add to the dialog message
			dialogMessage += "Continuing will delete the current AutoProxy Logs/Data.\n"

		# check if AutoTest settings should be restored
		if self._checkboxAutoConfigRestoreState3.isSelected():

			# add to the dialog message
			dialogMessage += "Continuing will delete the current AutoProxy Filters.\n"

		# check if AutoProxy filters should be restored
		if self._checkboxAutoConfigRestoreState4.isSelected():

			# add to the dialog message
			dialogMessage += "Continuing will delete the current AutoTest Settings.\n"

		# check if log data should be replaced
		dialogConfirmClearLogs = JOptionPane.showOptionDialog(None, dialogMessage + "\nWould you like to continue?", "Replace Current Data?", JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE, None, ["No", "Yes"], "No")

		# do not continue if No was selected
		if dialogConfirmClearLogs != True:
			return

		# check if logs should be cleared
		if self._checkboxAutoConfigRestoreState2.isSelected():

			# clear current logs and data
			self.buttonActionAutoConfigAutoClear1(event)

		# set dialog options to send to dialogBoxAutoConfigOrAutoBlock
		dialogBoxTitle = "Restore State File"
		dialogBoxExtensionFilter = ["JSON Files (*.json)", ["json"], ".json"]
		dialogBoxButtonText = "Restore"

		# get the selected file
		fileChosen, fileAutoConfig = self.dialogBoxAutoConfigOrAutoBlock(dialogBoxTitle, dialogBoxExtensionFilter, dialogBoxButtonText)

		# return if user exited dialog box
		if fileChosen == False:
			return

		# open the file
		with open(fileAutoConfig, "r") as jsonFile:

			# load the json data
			jsonData = json.load(jsonFile)

			# check if AutoProxy settings should be restored
			if self._checkboxAutoConfigRestoreState1.isSelected():

				# get the json data
				restoredAutoProxyForwardHosts = jsonData["AutoProxyForwardHosts"]
				restoredAutoProxyInterceptHosts = jsonData["AutoProxyInterceptHosts"]
				restoredAutoProxyDropHosts = jsonData["AutoProxyDropHosts"]

				# check that at least one AutoProxy setting does not equal None
				if restoredAutoProxyForwardHosts != None or restoredAutoProxyInterceptHosts != None or restoredAutoProxyDropHosts != None:

					# restore AutoProxy settings
					self._textAreaAutoProxyForwardHostsInput.setText(restoredAutoProxyForwardHosts)
					self._textAreaAutoProxyInterceptHostsInput.setText(restoredAutoProxyInterceptHosts)
					self._textAreaAutoProxyDropHostsInput.setText(restoredAutoProxyDropHosts)

					# scroll to top of each AutoProxy text area
					self._textAreaAutoProxyForwardHostsInput.setCaretPosition(0)
					self._textAreaAutoProxyInterceptHostsInput.setCaretPosition(0)
					self._textAreaAutoProxyDropHostsInput.setCaretPosition(0)

				# no settings were saved
				else:
					# clear AutoProxy settings
					self._textAreaAutoProxyForwardHostsInput.setText("")
					self._textAreaAutoProxyInterceptHostsInput.setText("")
					self._textAreaAutoProxyDropHostsInput.setText("")

			# check if AutoProxy logs and data should be restored
			if self._checkboxAutoConfigRestoreState2.isSelected():

				# check that all AutoProxy logs and data do not equal None
				if jsonData["AutoProxyLogTable"] != None and jsonData["AutoProxyHostTable"] != None and jsonData["AutoProxyAutoRegexHosts"] != None and jsonData["AutoProxyAutoTextHosts"] != None:

					# loop through the saved json log table
					for tempJson in jsonData["AutoProxyLogTable"]:

						# get values to create new row in host table
						importTime = tempJson["Time"]
						importMethod = tempJson["Method"]
						importProtocol = tempJson["Protocol"]
						importPort = tempJson["Port"]
						importHost = tempJson["Host"]
						importAction = tempJson["Action"]
						importReason = tempJson["Reason"]
						importReferer = tempJson["Referer"]
						importUrl = tempJson["Url"]
						importPath = tempJson["Path"]
						importRequest = base64.b64decode(tempJson["Request"])

						# try to decode response
						try:
							# decode response
							importResponse = base64.b64decode(tempJson["Response"])
						except:
							# set response to none
							importResponse = None

						# build the http service
						httpService = self._helpers.buildHttpService(importHost, int(importPort), importProtocol)

						# create the request
						request = CustomIHttpRequestResponse(importRequest, None, httpService)
						response = CustomIHttpRequestResponse(None, importResponse, httpService)

						# insert data into the log table
						self.insertOrDeleteLogs("insert", "last row", [importTime, importMethod, importProtocol, importPort, importHost, importAction, importReason, importReferer, importUrl, importPath, self._callbacks.saveBuffersToTempFiles(request), self._callbacks.saveBuffersToTempFiles(response), -1])

					# loop through the saved json host table
					for tempJson in jsonData["AutoProxyHostTable"]:

						# get values to create new row in host table
						importTime = tempJson["First Time Logged"]
						importHost = tempJson["Host"]
						importAutoForward = tempJson["AutoForward"]
						importAutoIntercept = tempJson["AutoIntercept"]
						importAutoDrop = tempJson["AutoDrop"]

						# check if AutoProxy settings were restored too
						if self._checkboxAutoConfigRestoreState1.isSelected():

							# insert data into the host table including checkbox value
							self._tableModelAutoProxyAutoAction.addRow([importTime, importHost, importAutoForward, importAutoIntercept, importAutoDrop])

						# AutoProxy settings were not restored
						else:
							# insert data into the host table marking all checkbox values false
							self._tableModelAutoProxyAutoAction.addRow([importTime, importHost, False, False, False])

					# insert data into the AutoProxy AutoRegex Hosts
					self._textEditorAutoProxyHostListRegexFormat.setText(jsonData["AutoProxyAutoRegexHosts"])

					# insert data into the AutoProxy AutoText Hosts
					self._textEditorAutoProxyHostListTextFormat.setText(jsonData["AutoProxyAutoTextHosts"])

					# check if restore/import flag is false to account for multiple imports without switching to main AutoProxy tab
					if self._autoConfigRestoreOrImportLogTableFlag == False:

						# set restore flag to true
						self._autoConfigRestoreOrImportLogTableFlag = True

						# get the current intercepted filter value
						self._autoConfigRestoreOrImportLogTableFilterValue = self._checkboxAutoProxyAutoFilterActionIntercepted.isSelected()

						# set intercepted filter to opposite value
						self._checkboxAutoProxyAutoFilterActionIntercepted.setSelected(not self._autoConfigRestoreOrImportLogTableFilterValue)

			# check if AutoProxy filters should be restored
			if self._checkboxAutoConfigRestoreState3.isSelected():

				# get the json data
				restoredAutoProxyFilterNo = jsonData["AutoProxyFilterAutoActionNo"]
				restoredAutoProxyFilterForwarded = jsonData["AutoProxyFilterAutoActionForwarded"]
				restoredAutoProxyFilterIntercepted = jsonData["AutoProxyFilterAutoActionIntercepted"]
				restoredAutoProxyFilterDropped = jsonData["AutoProxyFilterAutoActionDropped"]
				restoredAutoProxyFilterBlocked = jsonData["AutoProxyFilterAutoActionBlocked"]
				restoredAutoProxyFilterMethod = jsonData["AutoProxyFilterMethod"]
				restoredAutoProxyFilterProtocol = jsonData["AutoProxyFilterProtocol"]
				restoredAutoProxyFilterPort = jsonData["AutoProxyFilterPort"]
				restoredAutoProxyFilterHost = jsonData["AutoProxyFilterHost"]
				restoredAutoProxyFilterReferer = jsonData["AutoProxyFilterReferer"]
				restoredAutoProxyFilterUrl = jsonData["AutoProxyFilterUrl"]
				restoredAutoProxyFilterPath = jsonData["AutoProxyFilterPath"]
				restoredAutoProxyFilterRequest = jsonData["AutoProxyFilterRequest"]
				restoredAutoProxyFilterResponse = jsonData["AutoProxyFilterResponse"]

				# check that at least one AutoProxy filter does not equal None
				if restoredAutoProxyFilterMethod != None or restoredAutoProxyFilterProtocol != None or restoredAutoProxyFilterPort != None or restoredAutoProxyFilterHost != None or restoredAutoProxyFilterReferer != None or restoredAutoProxyFilterUrl != None or restoredAutoProxyFilterPath != None or restoredAutoProxyFilterRequest != None or restoredAutoProxyFilterResponse or restoredAutoProxyFilterNo != None or restoredAutoProxyFilterForwarded != None or restoredAutoProxyFilterIntercepted != None or restoredAutoProxyFilterDropped != None or restoredAutoProxyFilterBlocked != None:

					# restore AutoProxy checkbox filters
					self._checkboxAutoProxyAutoFilterActionNo.setSelected(restoredAutoProxyFilterNo)
					self._checkboxAutoProxyAutoFilterActionForwarded.setSelected(restoredAutoProxyFilterForwarded)
					self._checkboxAutoProxyAutoFilterActionIntercepted.setSelected(restoredAutoProxyFilterIntercepted)
					self._checkboxAutoProxyAutoFilterActionDropped.setSelected(restoredAutoProxyFilterDropped)
					self._checkboxAutoProxyAutoFilterActionBlocked.setSelected(restoredAutoProxyFilterBlocked)

					# get the new intercepted filter value
					self._autoConfigRestoreOrImportLogTableFilterValue = self._checkboxAutoProxyAutoFilterActionIntercepted.isSelected()

					# restore AutoProxy filters
					self._textAreaAutoProxyAutoFilterMethodInput.setText(restoredAutoProxyFilterMethod)
					self._textAreaAutoProxyAutoFilterProtocolInput.setText(restoredAutoProxyFilterProtocol)
					self._textAreaAutoProxyAutoFilterPortInput.setText(restoredAutoProxyFilterPort)
					self._textAreaAutoProxyAutoFilterHostInput.setText(restoredAutoProxyFilterHost)
					self._textAreaAutoProxyAutoFilterRefererInput.setText(restoredAutoProxyFilterReferer)
					self._textAreaAutoProxyAutoFilterUrlInput.setText(restoredAutoProxyFilterUrl)
					self._textAreaAutoProxyAutoFilterPathInput.setText(restoredAutoProxyFilterPath)
					self._textAreaAutoProxyAutoFilterRequestInput.setText(restoredAutoProxyFilterRequest)
					self._textAreaAutoProxyAutoFilterResponseInput.setText(restoredAutoProxyFilterResponse)

					# scroll to top of each AutoProxy filter
					self._textAreaAutoProxyAutoFilterMethodInput.setCaretPosition(0)
					self._textAreaAutoProxyAutoFilterProtocolInput.setCaretPosition(0)
					self._textAreaAutoProxyAutoFilterPortInput.setCaretPosition(0)
					self._textAreaAutoProxyAutoFilterHostInput.setCaretPosition(0)
					self._textAreaAutoProxyAutoFilterRefererInput.setCaretPosition(0)
					self._textAreaAutoProxyAutoFilterUrlInput.setCaretPosition(0)
					self._textAreaAutoProxyAutoFilterPathInput.setCaretPosition(0)
					self._textAreaAutoProxyAutoFilterRequestInput.setCaretPosition(0)
					self._textAreaAutoProxyAutoFilterResponseInput.setCaretPosition(0)

				# no filters were saved
				else:
					# clear AutoProxy checkbox filters
					self._checkboxAutoProxyAutoFilterActionNo.setSelected(True)
					self._checkboxAutoProxyAutoFilterActionForwarded.setSelected(True)
					self._checkboxAutoProxyAutoFilterActionIntercepted.setSelected(True)
					self._checkboxAutoProxyAutoFilterActionDropped.setSelected(True)
					self._checkboxAutoProxyAutoFilterActionBlocked.setSelected(True)

					# clear AutoProxy filters
					self._textAreaAutoProxyAutoFilterMethodInput.setText("")
					self._textAreaAutoProxyAutoFilterProtocolInput.setText("")
					self._textAreaAutoProxyAutoFilterPortInput.setText("")
					self._textAreaAutoProxyAutoFilterHostInput.setText("")
					self._textAreaAutoProxyAutoFilterRefererInput.setText("")
					self._textAreaAutoProxyAutoFilterUrlInput.setText("")
					self._textAreaAutoProxyAutoFilterPathInput.setText("")
					self._textAreaAutoProxyAutoFilterRequestInput.setText("")
					self._textAreaAutoProxyAutoFilterResponseInput.setText("")

			# check if AutoTest settings should be restored
			if self._checkboxAutoConfigRestoreState4.isSelected():

				# get the json data
				restoredAutoTestHosts = jsonData["AutoTestHosts"]
				restoredAutoTestForwardHosts = jsonData["AutoTestForwardHosts"]
				restoredAutoTestInterceptHosts = jsonData["AutoTestInterceptHosts"]
				restoredAutoTestDropHosts = jsonData["AutoTestDropHosts"]

				# check that at least one AutoTest setting does not equal None
				if restoredAutoTestHosts != None or restoredAutoTestForwardHosts != None or restoredAutoTestInterceptHosts != None or restoredAutoTestDropHosts != None:

					# restore AutoTest settings
					self._textAreaAutoTestHostsInput.setText(restoredAutoTestHosts)
					self._textAreaAutoTestForwardHostsInput.setText(restoredAutoTestForwardHosts)
					self._textAreaAutoTestInterceptHostsInput.setText(restoredAutoTestInterceptHosts)
					self._textAreaAutoTestDropHostsInput.setText(restoredAutoTestDropHosts)

					# scroll to top of each AutoTest text area
					self._textAreaAutoTestHostsInput.setCaretPosition(0)
					self._textAreaAutoTestForwardHostsInput.setCaretPosition(0)
					self._textAreaAutoTestInterceptHostsInput.setCaretPosition(0)
					self._textAreaAutoTestDropHostsInput.setCaretPosition(0)

				# no settings were saved
				else:
					# clear AutoTest settings
					self._textAreaAutoTestHostsInput.setText("")
					self._textAreaAutoProxyForwardHostsInput.setText("")
					self._textAreaAutoProxyInterceptHostsInput.setText("")
					self._textAreaAutoProxyDropHostsInput.setText("")


	#
	# implement button action to export the log table to CSV
	#

	def buttonActionAutoConfigExportCsv(self, event):

		# set dialog options to send to dialogBoxAutoConfigOrAutoBlock
		dialogBoxTitle = "Export CSV File"
		dialogBoxExtensionFilter = ["CSV Files (*.csv)", ["csv"], ".csv"]
		dialogBoxButtonText = "Export"

		# get the selected file
		fileChosen, fileAutoConfig = self.dialogBoxAutoConfigOrAutoBlock(dialogBoxTitle, dialogBoxExtensionFilter, dialogBoxButtonText)

		# return if user exited dialog box
		if fileChosen == False:
			return

		# open the file
		with open(fileAutoConfig, "wb") as csvFile:

			# create csv writer
			csvWriter = csv.writer(csvFile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)

			# get the log size
			logSize = self._log.size()

			# loop through the log array list
			for i in range(0, logSize):

				# create export variables for each row
				exportTime = self._log.get(i).time
				exportMethod = self._log.get(i).method
				exportProtocol = self._log.get(i).protocol
				exportPort = self._log.get(i).port
				exportHost = self._log.get(i).host
				exportAction = self._log.get(i).action
				exportReason = self._log.get(i).reason
				exportReferer = self._log.get(i).referer
				exportUrl = self._log.get(i).url
				exportPath = self._log.get(i).path
				exportRequest = base64.b64encode(self._log.get(i).request.getRequest())

				# try to get response to export
				try:
					# get response
					exportResponse = base64.b64encode(self._log.get(i).response.getResponse())
				except:
					# set response to none
					exportResponse = None

				# create a row to add
				csvRow = [exportTime, exportMethod, exportProtocol, exportPort, exportHost, exportAction, exportReason, exportReferer, exportUrl, exportPath, exportRequest, exportResponse]

				# write row to file
				csvWriter.writerow(csvRow)


	#
	# implement button action to import the log table from CSV
	#

	def buttonActionAutoConfigImportCsv(self, event):

		# check if log data should be replaced
		dialogConfirmClearLogs = JOptionPane.showOptionDialog(None, "Continuing will delete the current AutoProxy Logs/Data.\nCurrent settings will not be deleted.\n\nWould you like to continue?", "Replace Current Data?", JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE, None, ["No", "Yes"], "No")

		# check if logs should be cleared
		if dialogConfirmClearLogs == True:

			# clear current logs and data
			self.buttonActionAutoConfigAutoClear1(event)

		# do not continue
		else:
			return

		# set dialog options to send to dialogBoxAutoConfigOrAutoBlock
		dialogBoxTitle = "Import CSV File"
		dialogBoxExtensionFilter = ["CSV Files (*.csv)", ["csv"], ".csv"]
		dialogBoxButtonText = "Import"

		# get the selected file
		fileChosen, fileAutoConfig = self.dialogBoxAutoConfigOrAutoBlock(dialogBoxTitle, dialogBoxExtensionFilter, dialogBoxButtonText)

		# return if user exited dialog box
		if fileChosen == False:
			return

		# set the limit to the max size
		csv.field_size_limit(sys.maxsize)

		# open the file
		with open(fileAutoConfig, "r") as csvFile:

			# read the csv
			csvReader = csv.reader(csvFile, delimiter=',', quotechar='"')

			# loop through each row in the csv file
			for row in csvReader:

				# get data from each row
				importTime = row[0]
				importMethod = row[1]
				importProtocol = row[2]
				importPort = row[3]
				importHost = row[4]
				importAction = row[5]
				importReason = row[6]
				importReferer = row[7]
				importUrl = row[8]
				importPath = row[9]
				importRequest = base64.b64decode(row[10])

				# try to decode response
				try:
					# decode response
					importResponse = base64.b64decode(row[11])
				except:
					# set response to none
					importResponse = None

				# build the http service
				httpService = self._helpers.buildHttpService(importHost, int(importPort), importProtocol)

				# create the request and response
				request = CustomIHttpRequestResponse(importRequest, None, httpService)
				response = CustomIHttpRequestResponse(None, importResponse, httpService)

				# insert data into the log table
				self.insertOrDeleteLogs("insert", "last row", [importTime, importMethod, importProtocol, importPort, importHost, importAction, importReason, importReferer, importUrl, importPath, self._callbacks.saveBuffersToTempFiles(request), self._callbacks.saveBuffersToTempFiles(response), -1])

		# check if restore/import flag is false to account for multiple imports without switching to main AutoProxy tab
		if self._autoConfigRestoreOrImportLogTableFlag == False:

			# set restore flag to true
			self._autoConfigRestoreOrImportLogTableFlag = True

			# get the current intercepted filter value
			self._autoConfigRestoreOrImportLogTableFilterValue = self._checkboxAutoProxyAutoFilterActionIntercepted.isSelected()

			# set intercepted filter to opposite value
			self._checkboxAutoProxyAutoFilterActionIntercepted.setSelected(not self._autoConfigRestoreOrImportLogTableFilterValue)


	#
	# implement button action to copy AutoProxy settings to AutoTest settings
	#

	def buttonActionAutoConfigAutoCopy1(self, event):

		# get AutoProxy settings
		autoProxyForward = self._textAreaAutoProxyForwardHostsInput.getText()
		autoProxyIntercept = self._textAreaAutoProxyInterceptHostsInput.getText()
		autoProxyDrop = self._textAreaAutoProxyDropHostsInput.getText()

		# set AutoTest settings
		self._textAreaAutoTestForwardHostsInput.setText(autoProxyForward)
		self._textAreaAutoTestInterceptHostsInput.setText(autoProxyIntercept)
		self._textAreaAutoTestDropHostsInput.setText(autoProxyDrop)


	#
	# implement button action to copy AutoTest settings to AutoProxy settings
	#

	def buttonActionAutoConfigAutoCopy2(self, event):

		# get AutoTest settings
		autoTestForward = self._textAreaAutoTestForwardHostsInput.getText()
		autoTestIntercept = self._textAreaAutoTestInterceptHostsInput.getText()
		autoTestDrop = self._textAreaAutoTestDropHostsInput.getText()

		# set AutoProxy settings
		self._textAreaAutoProxyForwardHostsInput.setText(autoTestForward)
		self._textAreaAutoProxyInterceptHostsInput.setText(autoTestIntercept)
		self._textAreaAutoProxyDropHostsInput.setText(autoTestDrop)


	#
	# implement button action to copy AutoProxy AutoText hosts to AutoProxy hosts
	#

	def buttonActionAutoConfigAutoCopy3(self, event):

		# get AutoProxy AutoText hosts
		autoProxyHostListTextFormat = self._textEditorAutoProxyHostListTextFormat.getText().tostring()

		# set AutoProxy settings
		self._textAreaAutoTestHostsInput.setText(autoProxyHostListTextFormat)


	#
	# implement button action to clear AutoProxy logs
	#

	def buttonActionAutoConfigAutoClear1(self, event):

		# set the last selected row to -1
		self._currentlySelectedLogTableRow = -1

		# clear the log table
		self.insertOrDeleteLogs("delete", "", [])

		# get table row sorter to recreate log table
		self._tableRowSorterAutoProxyLogs = CustomTableRowSorter(self)

		# create custom row filter to recreate log table
		self._filterAutoAction = CustomRowFilter(self) 

		# set row filter to recreate log table
		self._tableRowSorterAutoProxyLogs.setRowFilter(self._filterAutoAction)

		# set row sorter to recreate log table
		self._tableAutoProxyLogs.setRowSorter(self._tableRowSorterAutoProxyLogs)

		# clear AutoProxy AutoAction table
		self._tableModelAutoProxyAutoAction.setRowCount(0)

		# set the table model
		self._tableAutoProxyAutoAction.setModel(self._tableModelAutoProxyAutoAction)

		# clear AutoProxy AutoRegex Hosts
		self._textEditorAutoProxyHostListRegexFormat.setText("")

		# clear AutoProxy AutoText Hosts
		self._textEditorAutoProxyHostListTextFormat.setText("")


	#
	# implement button action to clear AutoProxy settings, AutoProxy filters, and AutoTest settings
	#

	def buttonActionAutoConfigAutoClear2(self, event):

		# get AutoProxy settings for undo
		textAreaAutoProxyForwardHostsInputUndo = self._textAreaAutoProxyForwardHostsInput.getText()
		textAreaAutoProxyInterceptHostsInputUndo = self._textAreaAutoProxyInterceptHostsInput.getText()
		textAreaAutoProxyDropHostsInputUndo = self._textAreaAutoProxyDropHostsInput.getText()

		# get AutoTest settings for undo
		textAreaAutoTestHostsInputUndo = self._textAreaAutoTestHostsInput.getText()
		textAreaAutoTestForwardHostsInputUndo = self._textAreaAutoTestForwardHostsInput.getText()
		textAreaAutoTestInterceptHostsInputUndo = self._textAreaAutoTestInterceptHostsInput.getText()
		textAreaAutoTestDropHostsInputUndo = self._textAreaAutoTestDropHostsInput.getText()

		# get AutoProxy filters for undo
		textAreaAutoProxyAutoFilterMethodInputUndo = self._textAreaAutoProxyAutoFilterMethodInput.getText()
		textAreaAutoProxyAutoFilterProtocolInputUndo = self._textAreaAutoProxyAutoFilterProtocolInput.getText()
		textAreaAutoProxyAutoFilterPortInputUndo = self._textAreaAutoProxyAutoFilterPortInput.getText()
		textAreaAutoProxyAutoFilterHostInputUndo = self._textAreaAutoProxyAutoFilterHostInput.getText()
		textAreaAutoProxyAutoFilterRefererInputUndo = self._textAreaAutoProxyAutoFilterRefererInput.getText()
		textAreaAutoProxyAutoFilterUrlInputUndo = self._textAreaAutoProxyAutoFilterUrlInput.getText()
		textAreaAutoProxyAutoFilterPathInputUndo = self._textAreaAutoProxyAutoFilterPathInput.getText()
		textAreaAutoProxyAutoFilterRequestInputUndo = self._textAreaAutoProxyAutoFilterRequestInput.getText()
		textAreaAutoProxyAutoFilterResponseInputUndo = self._textAreaAutoProxyAutoFilterResponseInput.getText()

		# check if any settings have data
		if textAreaAutoProxyForwardHostsInputUndo != "" or textAreaAutoProxyInterceptHostsInputUndo != "" or textAreaAutoProxyDropHostsInputUndo != "" or textAreaAutoTestHostsInputUndo != "" or textAreaAutoTestForwardHostsInputUndo != "" or textAreaAutoTestInterceptHostsInputUndo != "" or textAreaAutoTestDropHostsInputUndo != "" or textAreaAutoProxyAutoFilterMethodInputUndo != "" or textAreaAutoProxyAutoFilterProtocolInputUndo != "" or textAreaAutoProxyAutoFilterPortInputUndo != "" or textAreaAutoProxyAutoFilterHostInputUndo != "" or textAreaAutoProxyAutoFilterRefererInputUndo != "" or textAreaAutoProxyAutoFilterUrlInputUndo != "" or textAreaAutoProxyAutoFilterPathInputUndo != "" or textAreaAutoProxyAutoFilterRequestInputUndo != "" or textAreaAutoProxyAutoFilterResponseInputUndo != "" or self._checkboxAutoProxyAutoFilterActionNo.isSelected() == False or self._checkboxAutoProxyAutoFilterActionForwarded.isSelected() == False or self._checkboxAutoProxyAutoFilterActionIntercepted.isSelected() == False or self._checkboxAutoProxyAutoFilterActionDropped.isSelected() == False or self._checkboxAutoProxyAutoFilterActionBlocked.isSelected() == False:

			# save AutoProxy settings for undo
			self._textAreaAutoProxyForwardHostsInputUndo = textAreaAutoProxyForwardHostsInputUndo
			self._textAreaAutoProxyInterceptHostsInputUndo = textAreaAutoProxyInterceptHostsInputUndo
			self._textAreaAutoProxyDropHostsInputUndo = textAreaAutoProxyDropHostsInputUndo

			# save AutoTest settings for undo
			self._textAreaAutoTestHostsInputUndo = textAreaAutoTestHostsInputUndo
			self._textAreaAutoTestForwardHostsInputUndo = textAreaAutoTestForwardHostsInputUndo
			self._textAreaAutoTestInterceptHostsInputUndo = textAreaAutoTestInterceptHostsInputUndo
			self._textAreaAutoTestDropHostsInputUndo = textAreaAutoTestDropHostsInputUndo

			# save AutoProxy filters for undo
			self._textAreaAutoProxyAutoFilterMethodInputUndo = textAreaAutoProxyAutoFilterMethodInputUndo
			self._textAreaAutoProxyAutoFilterProtocolInputUndo = textAreaAutoProxyAutoFilterProtocolInputUndo
			self._textAreaAutoProxyAutoFilterPortInputUndo = textAreaAutoProxyAutoFilterPortInputUndo
			self._textAreaAutoProxyAutoFilterHostInputUndo = textAreaAutoProxyAutoFilterHostInputUndo
			self._textAreaAutoProxyAutoFilterRefererInputUndo = textAreaAutoProxyAutoFilterRefererInputUndo
			self._textAreaAutoProxyAutoFilterUrlInputUndo = textAreaAutoProxyAutoFilterUrlInputUndo
			self._textAreaAutoProxyAutoFilterPathInputUndo = textAreaAutoProxyAutoFilterPathInputUndo
			self._textAreaAutoProxyAutoFilterRequestInputUndo = textAreaAutoProxyAutoFilterRequestInputUndo
			self._textAreaAutoProxyAutoFilterResponseInputUndo = textAreaAutoProxyAutoFilterResponseInputUndo

			# save AutoProxy checkbox filters for undo
			self._checkboxAutoProxyAutoFilterActionNoUndo = self._checkboxAutoProxyAutoFilterActionNo.isSelected()
			self._checkboxAutoProxyAutoFilterActionForwardedUndo = self._checkboxAutoProxyAutoFilterActionForwarded.isSelected()
			self._checkboxAutoProxyAutoFilterActionInterceptedUndo = self._checkboxAutoProxyAutoFilterActionIntercepted.isSelected()
			self._checkboxAutoProxyAutoFilterActionDroppedUndo = self._checkboxAutoProxyAutoFilterActionDropped.isSelected()
			self._checkboxAutoProxyAutoFilterActionBlockedUndo = self._checkboxAutoProxyAutoFilterActionBlocked.isSelected()

		# clear AutoProxy top sections
		self._textAreaAutoProxyForwardHostsInput.setText("")
		self._textAreaAutoProxyInterceptHostsInput.setText("")
		self._textAreaAutoProxyDropHostsInput.setText("")

		# clear AutoTest tab top sections
		self._textAreaAutoTestHostsInput.setText("")
		self._textAreaAutoTestForwardHostsInput.setText("")
		self._textAreaAutoTestInterceptHostsInput.setText("")
		self._textAreaAutoTestDropHostsInput.setText("")

		# clear AutoTest tab bottom sections
		self._textAreaAutoTestNoActionHostsOutput.setText("")
		self._textAreaAutoTestForwardHostsOutput.setText("")
		self._textAreaAutoTestInterceptHostsOutput.setText("")
		self._textAreaAutoTestDropHostsOutput.setText("")

		# clear AutoProxy filters
		self._textAreaAutoProxyAutoFilterMethodInput.setText("")
		self._textAreaAutoProxyAutoFilterProtocolInput.setText("")
		self._textAreaAutoProxyAutoFilterPortInput.setText("")
		self._textAreaAutoProxyAutoFilterHostInput.setText("")
		self._textAreaAutoProxyAutoFilterRefererInput.setText("")
		self._textAreaAutoProxyAutoFilterUrlInput.setText("")
		self._textAreaAutoProxyAutoFilterPathInput.setText("")
		self._textAreaAutoProxyAutoFilterRequestInput.setText("")
		self._textAreaAutoProxyAutoFilterResponseInput.setText("")

		# set AutoProxy checkbox filters to true
		self._checkboxAutoProxyAutoFilterActionNo.setSelected(True)
		self._checkboxAutoProxyAutoFilterActionForwarded.setSelected(True)
		self._checkboxAutoProxyAutoFilterActionIntercepted.setSelected(True)
		self._checkboxAutoProxyAutoFilterActionDropped.setSelected(True)
		self._checkboxAutoProxyAutoFilterActionBlocked.setSelected(True)


	#
	# implement button action to undo accidental clearing of AutoProxy and AutoTest settings
	#

	def buttonActionAutoConfigAutoClear3(self, event):

		# get undo settings for AutoProxy
		textAreaAutoProxyForwardHostsInputUndo = self._textAreaAutoProxyForwardHostsInputUndo
		textAreaAutoProxyInterceptHostsInputUndo = self._textAreaAutoProxyInterceptHostsInputUndo
		textAreaAutoProxyDropHostsInputUndo = self._textAreaAutoProxyDropHostsInputUndo

		# get undo settings for AutoTest
		textAreaAutoTestHostsInputUndo = self._textAreaAutoTestHostsInputUndo
		textAreaAutoTestForwardHostsInputUndo = self._textAreaAutoTestForwardHostsInputUndo
		textAreaAutoTestInterceptHostsInputUndo = self._textAreaAutoTestInterceptHostsInputUndo
		textAreaAutoTestDropHostsInputUndo = self._textAreaAutoTestDropHostsInputUndo

		# get undo filters for AutoProxy
		textAreaAutoProxyAutoFilterMethodInputUndo = self._textAreaAutoProxyAutoFilterMethodInputUndo
		textAreaAutoProxyAutoFilterProtocolInputUndo = self._textAreaAutoProxyAutoFilterProtocolInputUndo
		textAreaAutoProxyAutoFilterPortInputUndo = self._textAreaAutoProxyAutoFilterPortInputUndo
		textAreaAutoProxyAutoFilterHostInputUndo = self._textAreaAutoProxyAutoFilterHostInputUndo
		textAreaAutoProxyAutoFilterRefererInputUndo = self._textAreaAutoProxyAutoFilterRefererInputUndo
		textAreaAutoProxyAutoFilterUrlInputUndo = self._textAreaAutoProxyAutoFilterUrlInputUndo
		textAreaAutoProxyAutoFilterPathInputUndo = self._textAreaAutoProxyAutoFilterPathInputUndo
		textAreaAutoProxyAutoFilterRequestInputUndo = self._textAreaAutoProxyAutoFilterRequestInputUndo
		textAreaAutoProxyAutoFilterResponseInputUndo = self._textAreaAutoProxyAutoFilterResponseInputUndo

		# check if any settings or filters have data
		if textAreaAutoProxyForwardHostsInputUndo != "" or textAreaAutoProxyInterceptHostsInputUndo != "" or textAreaAutoProxyDropHostsInputUndo != "" or textAreaAutoTestHostsInputUndo != "" or textAreaAutoTestForwardHostsInputUndo != "" or textAreaAutoTestInterceptHostsInputUndo != "" or textAreaAutoTestDropHostsInputUndo != "" or textAreaAutoProxyAutoFilterMethodInputUndo != "" or textAreaAutoProxyAutoFilterProtocolInputUndo != "" or textAreaAutoProxyAutoFilterPortInputUndo != "" or textAreaAutoProxyAutoFilterHostInputUndo != "" or textAreaAutoProxyAutoFilterRefererInputUndo != "" or textAreaAutoProxyAutoFilterUrlInputUndo != "" or textAreaAutoProxyAutoFilterPathInputUndo != "" or textAreaAutoProxyAutoFilterRequestInputUndo != "" or textAreaAutoProxyAutoFilterResponseInputUndo != "":

			# undo clear AutoProxy Settings
			self._textAreaAutoProxyForwardHostsInput.setText(textAreaAutoProxyForwardHostsInputUndo)
			self._textAreaAutoProxyInterceptHostsInput.setText(textAreaAutoProxyInterceptHostsInputUndo)
			self._textAreaAutoProxyDropHostsInput.setText(textAreaAutoProxyDropHostsInputUndo)

			# undo clear AutoTest Settings
			self._textAreaAutoTestHostsInput.setText(textAreaAutoTestHostsInputUndo)
			self._textAreaAutoTestForwardHostsInput.setText(textAreaAutoTestForwardHostsInputUndo)
			self._textAreaAutoTestInterceptHostsInput.setText(textAreaAutoTestInterceptHostsInputUndo)
			self._textAreaAutoTestDropHostsInput.setText(textAreaAutoTestDropHostsInputUndo)

			# undo clear AutoProxy Filters
			self._textAreaAutoProxyAutoFilterMethodInput.setText(textAreaAutoProxyAutoFilterMethodInputUndo)
			self._textAreaAutoProxyAutoFilterProtocolInput.setText(textAreaAutoProxyAutoFilterProtocolInputUndo)
			self._textAreaAutoProxyAutoFilterPortInput.setText(textAreaAutoProxyAutoFilterPortInputUndo)
			self._textAreaAutoProxyAutoFilterHostInput.setText(textAreaAutoProxyAutoFilterHostInputUndo)
			self._textAreaAutoProxyAutoFilterRefererInput.setText(textAreaAutoProxyAutoFilterRefererInputUndo)
			self._textAreaAutoProxyAutoFilterUrlInput.setText(textAreaAutoProxyAutoFilterUrlInputUndo)
			self._textAreaAutoProxyAutoFilterPathInput.setText(textAreaAutoProxyAutoFilterPathInputUndo)
			self._textAreaAutoProxyAutoFilterRequestInput.setText(textAreaAutoProxyAutoFilterRequestInputUndo)
			self._textAreaAutoProxyAutoFilterResponseInput.setText(textAreaAutoProxyAutoFilterResponseInputUndo)

			# undo clear AutoProxy checkbox filters
			self._checkboxAutoProxyAutoFilterActionNo.setSelected(self._checkboxAutoProxyAutoFilterActionNoUndo)
			self._checkboxAutoProxyAutoFilterActionForwarded.setSelected(self._checkboxAutoProxyAutoFilterActionForwardedUndo)
			self._checkboxAutoProxyAutoFilterActionIntercepted.setSelected(self._checkboxAutoProxyAutoFilterActionInterceptedUndo)
			self._checkboxAutoProxyAutoFilterActionDropped.setSelected(self._checkboxAutoProxyAutoFilterActionDroppedUndo)
			self._checkboxAutoProxyAutoFilterActionBlocked.setSelected(self._checkboxAutoProxyAutoFilterActionBlockedUndo)


	#
	# implement dialog box for AutoBlock download block lists
	#

	def dialogBoxAutoBlockDownloadDialog(self):

		# create frame
		frameAutoBlockDialogBox = JFrame()

		# try to load the last used directory
		try:
			# load the directory for future imports/exports
			fileChooserDirectory = self._callbacks.loadExtensionSetting("fileChooserDirectory")

		# there is not a last used directory
		except:
			# set the last used directory to blank
			fileChooserDirectory = ""

		# create file chooser
		fileChooserAutoBlockDialogBox = JFileChooser(fileChooserDirectory)

		# only show directories
		fileChooserAutoBlockDialogBox.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)

		# set dialog title
		fileChooserAutoBlockDialogBox.setDialogTitle("Select Directory")

		# show dialog box and get value
		valueFileChooserAutoBlockDialogBox = fileChooserAutoBlockDialogBox.showDialog(frameAutoBlockDialogBox, "Download")

		# check if a file was not selected
		if valueFileChooserAutoBlockDialogBox != JFileChooser.APPROVE_OPTION:

			# show error message that path does not exist
			dialogOption = JOptionPane.showMessageDialog(None, "Directory not found.\nPlease select a valid directory next time.", "Directory Not Found", JOptionPane.INFORMATION_MESSAGE)
	
			# return no path selected
			return False, "No Path Selected"

		# get the directory
		fileChooserDirectory = fileChooserAutoBlockDialogBox.getCurrentDirectory()#zzzzz

		# store the directory for future imports/exports
		self._callbacks.saveExtensionSetting("fileChooserDirectory", str(fileChooserDirectory))#zzzzz

		# get absolute path of file
		fileChosenAutoBlockDialogBox = fileChooserAutoBlockDialogBox.getSelectedFile().getAbsolutePath()

		# check that path is valid
		if os.path.isdir(fileChosenAutoBlockDialogBox) == True:

			# return dialog box value and path/file
			return True, fileChosenAutoBlockDialogBox

		# path is not valid
		else:
			# show error message that path does not exist
			dialogOption = JOptionPane.showMessageDialog(None, "Directory not found.\nPlease select a valid directory next time.", "Directory Not Found", JOptionPane.INFORMATION_MESSAGE)

			# return invalid path
			return False, "Invalid Path"


	#
	# download the block list through Burp in case there is an upstream proxy
	#

	def downloadBlockListThroughBurp(self, urlIndex, fileDirectory):

		# convert url index to string
		urlIndexString = str(urlIndex)

		# set a file name to download to
		fileName = self._dictionaryOfBlockObjects["fileNameText" + urlIndexString]

		# set the path and filename
		fileAutoBlock = os.path.join(fileDirectory, fileName)

		# get the url to download the block list from
		urlToDownloadFrom = self._dictionaryOfBlockObjects["labelUrlText" + urlIndexString]

		# create the url
		downloadCreatedUrl = URL(urlToDownloadFrom)

		# set the host
		downloadHost = downloadCreatedUrl.getHost()

		# try to connect to the url
		try:
			# make the test connection
			testConnection = httplib.HTTPConnection(downloadHost)
			testConnection.request("HEAD", "")
			testConnectionResponse = testConnection.getresponse()

			# can connect to the url
			canConnectToUrl = True

		# cannot connect to the url
		except:
			canConnectToUrl = False

		# check that there is a valid connection
		if(canConnectToUrl):

			# create the request
			downloadRequest = self._helpers.buildHttpRequest(downloadCreatedUrl)

			# check if url protocol is https
			if urlToDownloadFrom.startswith("https"):
				useHttps = True
				port = 443
				protocol = "https"

			# url protocol is http
			else:
				useHttps = False
				port = 80
				protocol = "http"

			# try to download file
			try:
				# build the http service
				httpService = self._helpers.buildHttpService(downloadHost, port, protocol)

				# make the http request
				downloadResponse = self._callbacks.makeHttpRequest(httpService, downloadRequest)

				# get the response
				response = downloadResponse.getResponse().tostring()

				# save the response to a text file
				downloadFile = open(fileAutoBlock, "w")
				downloadFile.write(response)
				downloadFile.close()

				# set that the new thread is complete
				self._dictionaryOfThreadResultQueues[urlIndex].put(True)

			# download failed
			except:
				# set download failed
				self._dictionaryOfThreadResultQueues[urlIndex].put(False)

		# test connection failed
		else:
			# set download failed
			self._dictionaryOfThreadResultQueues[urlIndex].put(False)


	#
	# implement AutoBlock download block list button clicks
	#

	def buttonActionDownloadBlocking(self, event):

		# get the index of the button clicked
		buttonIndex = int(event.getSource().getName())

		# check if download all button was clicked
		if buttonIndex == 1:

			# show message that downloads may take a few minutes
			dialogOption = JOptionPane.showMessageDialog(None, "This may take a few minutes.", "Warning", JOptionPane.INFORMATION_MESSAGE)

		# get the directory to download the file into
		fileChosen, fileAutoBlockDirectory = self.dialogBoxAutoBlockDownloadDialog()

		# set path for automated import
		self._autoBlockAutomatedPath = fileAutoBlockDirectory

		# return if user exited dialog box
		if fileChosen == False:
			return

		# create a dictionary of queues to get values from new threads
		self._dictionaryOfThreadResultQueues = dict()

		# check if download all button was clicked
		if buttonIndex == 1:

			# create an array to keep track of the download statuses
			autoBlockDownloadStatusArray = [None, None, False, False, False, False, False, False, False]

			# download block lists for rows 2-8
			for i in range(2, 9):

				# create queue to get value from new thread
				self._dictionaryOfThreadResultQueues[i] = Queue.Queue()

				# download all block lists through Burp in case there is an upstream proxy
				start_new_thread(self.downloadBlockListThroughBurp, (i, fileAutoBlockDirectory))

			# click enable/disable buttons 2-8
			for i in range(2, 9):

				# set the download status
				autoBlockDownloadStatusArray[i] = self._dictionaryOfThreadResultQueues[i].get()

				# check if the file was downloaded before trying to import
				if autoBlockDownloadStatusArray[i] == True:

					# set click status to automated
					self._autoBlockAutomatedOrManualClick = "Automated Click"

					# check if blocking is disabled
					if self._dictionaryOfBlockObjects["buttonEnableDisable" + str(i)].getText() == "Blocking Disabled":

						# click the enable blocking button
						self._dictionaryOfBlockObjects["buttonEnableDisable" + str(i)].doClick()

					# blocking is enabled so disable then enable blocking to import downloaded list
					else:
						# click the button twice to import the new hosts to block
						self._dictionaryOfBlockObjects["buttonEnableDisable" + str(i)].doClick()
						self._dictionaryOfBlockObjects["buttonEnableDisable" + str(i)].doClick()

				# download failed
				else:
					# get the url to download the block list from
					urlToDownloadFrom = self._dictionaryOfBlockObjects["labelUrlText" + str(i)]

					# display message box
					dialogOption = JOptionPane.showMessageDialog(None, "Download failed for AutoBlock file: " + urlToDownloadFrom + ".\nTry downloading the file manually.", "Download Failed", JOptionPane.INFORMATION_MESSAGE)

		# single download button was clicked
		else:
			# create an array for the download status
			autoBlockDownloadStatusArray = [False]

			# create queue to get value from new thread
			self._dictionaryOfThreadResultQueues[buttonIndex] = Queue.Queue()

			# download a single block list through Burp in case there is an upstream proxy
			start_new_thread(self.downloadBlockListThroughBurp, (buttonIndex, fileAutoBlockDirectory))

			# set the download status
			autoBlockDownloadStatusArray[0] = self._dictionaryOfThreadResultQueues[buttonIndex].get()

			# check if the file was downloaded before trying to import
			if autoBlockDownloadStatusArray[0] == True:

				# set click status to automated
				self._autoBlockAutomatedOrManualClick = "Automated Click"

				# check if blocking is disabled
				if self._dictionaryOfBlockObjects["buttonEnableDisable" + str(buttonIndex)].getText() == "Blocking Disabled":

					# click the enable blocking button
					self._dictionaryOfBlockObjects["buttonEnableDisable" + str(buttonIndex)].doClick()

				# blocking is enabled so disable then enable blocking to import downloaded list
				else:
					# click the button twice
					self._dictionaryOfBlockObjects["buttonEnableDisable" + str(buttonIndex)].doClick()
					self._dictionaryOfBlockObjects["buttonEnableDisable" + str(buttonIndex)].doClick()

			# download failed
			else:
				# get the url to download the block list from
				urlToDownloadFrom = self._dictionaryOfBlockObjects["labelUrlText" + str(buttonIndex)]

				# display message box
				dialogOption = JOptionPane.showMessageDialog(None, "Download failed for AutoBlock file: " + urlToDownloadFrom + ".\nTry downloading the file manually.", "Download Failed", JOptionPane.INFORMATION_MESSAGE)


	#
	# implement importing AutoBlock block lists
	#

	def importBlockList(self, fileAutoBlock, buttonIndex):

		# open the file
		with open(fileAutoBlock, "r") as blockFile:

			# clear the current block list
			self._dictionaryOfAutoBlockLists["autoBlockList" + str(buttonIndex)] = []

			# check for button index to only import block hosts in the propper format
			if buttonIndex == 2:

				# loop through each row
				for rowBlockFile in blockFile:

					# http://sysctl.org/cameleon/hosts
					# 127.0.0.1 tab space host
					# 127.0.0.1	  host
					if rowBlockFile.startswith("127.0.0.1\t "):

						# add to block list
						self._dictionaryOfAutoBlockLists["autoBlockList" + str(buttonIndex)].append(rowBlockFile[11:].rstrip("\r\n"))

			# check for button index to only import block hosts in the propper format
			elif buttonIndex == 3:

				# loop through each row
				for rowBlockFile in blockFile:

					# https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt
					# comments starting with # followed by one blank row with a new line character
					# host
					if rowBlockFile.startswith("#") == False and len(rowBlockFile) > 1 and " " not in rowBlockFile:

						# add to block list
						self._dictionaryOfAutoBlockLists["autoBlockList" + str(buttonIndex)].append(rowBlockFile.rstrip("\r\n"))

			# check for button index to only import block hosts in the propper format
			elif buttonIndex == 4:

				# loop through each row
				for rowBlockFile in blockFile:

					# https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt
					# comments starting with # followed by one blank row with a new line character
					# host
					if rowBlockFile.startswith("#") == False and len(rowBlockFile) > 1 and " " not in rowBlockFile:

						# add to block list
						self._dictionaryOfAutoBlockLists["autoBlockList" + str(buttonIndex)].append(rowBlockFile.rstrip("\r\n"))

			# check for button index to only import block hosts in the propper format
			elif buttonIndex == 5:

				# loop through each row
				for rowBlockFile in blockFile:

					# https://hosts-file.net/download/hosts.txt
					# 127.0.0.1 tab host
					# 127.0.0.1	host
					if rowBlockFile.startswith("127.0.0.1\t"):

						# add to block list
						self._dictionaryOfAutoBlockLists["autoBlockList" + str(buttonIndex)].append(rowBlockFile[10:].rstrip("\r\n"))

			# check for button index to only import block hosts in the propper format
			elif buttonIndex == 6:

				# loop through each row
				for rowBlockFile in blockFile:

					# https://mirror1.malwaredomains.com/files/justdomains
					# host
					if len(rowBlockFile) > 1 and " " not in rowBlockFile:

						# add to block list
						self._dictionaryOfAutoBlockLists["autoBlockList" + str(buttonIndex)].append(rowBlockFile.rstrip("\r\n"))

			# check for button index to only import block hosts in the propper format
			elif buttonIndex == 7:

				# loop through each row
				for rowBlockFile in blockFile:

					# https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
					# 0.0.0.0 host
					if rowBlockFile.startswith("0.0.0.0 "):

						# add to block list
						self._dictionaryOfAutoBlockLists["autoBlockList" + str(buttonIndex)].append(rowBlockFile[8:].rstrip("\r\n"))

			# check for button index to only import block hosts in the propper format
			elif buttonIndex == 8:

				# loop through each row
				for rowBlockFile in blockFile:

					# https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist
					# comments starting with # followed by one blank row with a new line character
					# host
					if rowBlockFile.startswith("#") == False and len(rowBlockFile) > 1 and " " not in rowBlockFile:

						# add to block list
						self._dictionaryOfAutoBlockLists["autoBlockList" + str(buttonIndex)].append(rowBlockFile.rstrip("\r\n"))

			# check for button index to only import block hosts in the propper format
			elif buttonIndex == 9:

				# loop through each row
				for rowBlockFile in blockFile:

					# custom list with one host per line
					# host
					# add to block list
					self._dictionaryOfAutoBlockLists["autoBlockList" + str(buttonIndex)].append(rowBlockFile.rstrip("\r\n"))


	#
	# implement AutoBlock enable/disable button clicks
	#

	def buttonActionEnableDisableBlocking(self, event):

		# check if blocking is enabled
		if event.getSource().getText() == "Blocking Enabled":

			# set button text
			event.getSource().setText("Blocking Disabled")

			# set background to a soft red so the black text is readable
			event.getSource().setBackground(Color(255, 100, 100))

		# block is disabled
		else:
			# get the index of the button clicked
			buttonIndex = int(event.getSource().getName())

			# check if manual click
			if self._autoBlockAutomatedOrManualClick == "Manual Click":

				# set dialog options to send to dialogBoxAutoConfigOrAutoBlock
				dialogBoxTitle = "Import Block List"
				dialogBoxExtensionFilter = ["Text Files (*.txt)", ["txt"], ".txt"]
				dialogBoxButtonText = "Import"

				# get the selected file
				fileChosen, fileAutoBlock = self.dialogBoxAutoConfigOrAutoBlock(dialogBoxTitle, dialogBoxExtensionFilter, dialogBoxButtonText)

				# return if user exited dialog box
				if fileChosen == False:
					return

			# clicked from download all button
			elif self._autoBlockAutomatedOrManualClick == "Automated Click":

				# set click status back to manual
				self._autoBlockAutomatedOrManualClick = "Manual Click"

				# convert button index to string
				buttonIndexString = str(buttonIndex)

				# set a file name to import
				fileName = self._dictionaryOfBlockObjects["fileNameText" + buttonIndexString]

				# get the directory containing the import file
				fileDirectory = self._autoBlockAutomatedPath

				# set the path and filename to import
				fileAutoBlock = os.path.join(fileDirectory, fileName)

			# check that file is valid
			if os.path.isfile(fileAutoBlock) == False:

				# show error message that path does not exist
				dialogOption = JOptionPane.showMessageDialog(None, "File not found.\nPlease select a valid file next time.", "File Not Found", JOptionPane.INFORMATION_MESSAGE)

				# do not continue
				return

			# import and enable custom list
			self.importBlockList(fileAutoBlock, buttonIndex)

			# set button text
			event.getSource().setText("Blocking Enabled")

			# set background to green
			event.getSource().setBackground(Color.GREEN)


#
# extend JTextArea to allow tab key to transfer focus to next text area in AutoProxy and AutoTest
#

class CustomJTextArea(JTextArea):

	# override processComponentKeyEvent method
	def processComponentKeyEvent(self, event):

		# check if key code matches tab key code and that the key is being typed to avoid multiple triggers
		if event.getKeyCode() == KeyEvent.VK_TAB and event.getID() == KeyEvent.KEY_PRESSED:

			# cosume the event
			event.consume()

			# transfer focus to next JTextArea
			self.transferFocus()

		# check if key code matched tab key code and that event ID is KEY_RELEASED or KEY_TYPED
		elif event.getKeyCode() == KeyEvent.VK_TAB:

			# consume the event
			event.consume()


#
# extend FocusListener to clear regex error highlights for AutoProxy and AutoTest
#

class CustomFocusListener(FocusListener):

	# initialize variables
	def __init__(self, textAreaFocussed):
		self.textAreaFocussed = textAreaFocussed

	# override focuseGained method
	def focusGained(self, event):

		# check if focus was gained from regex error message box
		if event.getOppositeComponent() == None:
			return

		# remove highlights on text area focussed
		highlighter = self.textAreaFocussed.getHighlighter()
		highlighter.removeAllHighlights()
		
	# required to get rid of NotImplementedError
	def focusLost(self, event):
		pass


#
# implement custom log entries with request details
#

class CustomLogEntry:

	# initialize variables
	def __init__(self, time, method, protocol, port, host, action, reason, referer, url, path, request, response, requestResponseId):
		self.time = time
		self.method = method
		self.protocol = protocol
		self.port = port
		self.host = host
		self.reason = reason
		self.action = action
		self.referer = referer
		self.url = url
		self.path = path
		self.request = request
		self.response = response
		self.requestResponseId = requestResponseId


#
# extend JTable to handle cell selection for log table
#

class CustomJTableLogs(JTable):

	# initialize variables
	def __init__(self, extender):
		self.extender = extender
		self.setModel(extender)

	# override changeSelection method
	def changeSelection(self, row, col, toggle, extend):

		# allow row to be unselected but row will also unselect when scrolling left or right with arrow keys
		allowUnselectRow = False

		# allow cell border to be removed when clicked but loose scrolling with arrow keys
		allowRemoveCellBorder = False

		# try to get index of selected row
		try:
			# get index of selected row
			modelRowIndex = self.convertRowIndexToModel(row)
		except:
			# clear selection
			modelRowIndex = -1

		# try to add default changeSelection
		try:
			# add default changeSelection
			JTable.changeSelection(self, row, col, toggle, extend)
		except:
			pass

		# try to set the last selected row and update request viewer
		try:
			# set the last selected row to the row index accounting for sorting
			self.extender._currentlySelectedLogTableRow = modelRowIndex

			# get log details for selected row accounting for sorting
			logEntry = self.extender._log.get(modelRowIndex)

			# show request for selected row
			self.extender._requestViewerAutoProxy.setMessage(logEntry.request.getRequest(), True)

			# try to show response for selected row
			try:
				# show response
				self.extender._responseViewerAutoProxy.setMessage(logEntry.response.getResponse(), False)

				# set the currently displayed log entry
				self.extender._currentlyDisplayedLogEntry = logEntry.response
			except:
				# clear response
				self.extender._responseViewerAutoProxy.setMessage("", False)
		except:
			pass

		# check if unselecting a row is allowed and that the currently highlighted row was selected again
		if allowUnselectRow and modelRowIndex == self.extender._currentlySelectedLogTableRow:

			# set the last selected row to -1
			self.extender._currentlySelectedLogTableRow = -1

			# clear the selection on the row
			self.clearSelection()

			# clear request viewer
			self.extender._requestViewerAutoProxy.setMessage("", True)

			# clear response viewer
			self.extender._responseViewerAutoProxy.setMessage("", True)

		# check if removing the cell border is allowed
		if allowRemoveCellBorder:

			# remove border from cell when selected but arrow key scrolling is lost
			selectionModel = self.getSelectionModel()
			selectionModel.setAnchorSelectionIndex(-1)
			selectionModel.setLeadSelectionIndex(-1)

			# remove border from cell when selected but arrow key scrolling is lost
			columnModel = self.getColumnModel()
			columnModel.getSelectionModel().setAnchorSelectionIndex(-1)
			columnModel.getSelectionModel().setLeadSelectionIndex(-1)

	# override tableChanged method to keep the same row number highlighted but update the request viewer as new items are being added
	def tableChanged(self, event):

		# Feature that if true, keeps the current row number selected causing the request viewer to update as new rows are added. If false, it will keep the current item selected as it changes row and the request viewer stays the same since the same row object remains selected.
		keepRowSelectedAndUpdateRequestViewerWhenNewRowIsAdded = False

		# check if feature above is allowed
		if keepRowSelectedAndUpdateRequestViewerWhenNewRowIsAdded == False:

			# try to add default tableChanged
			try:
				# add default tableChanged
				JTable.tableChanged(self, event)

			# catch clearing the table
			except:
				pass

			# do not continue
			return

		# check if the table lock is false
		if self.extender._customJTableLogsTableChangeLock == False:

			# get the last row selected whether it is a single row selected or multiple rows
			rowLastSelected = self.selectionModel.getLeadSelectionIndex()

			# check if a row is selected
			if rowLastSelected != -1:

				try:
					# get index of selected row
					modelRowIndex = self.convertRowIndexToModel(rowLastSelected)

					# get log details for selected row accounting for sorting
					logEntry = self.extender._log.get(modelRowIndex)

					# show log entry for selected row
					self.extender._requestViewerAutoProxy.setMessage(logEntry.request.getRequest(), True)

					# try to show response for selected row
					try:
						# show response
						self.extender._responseViewerAutoProxy.setMessage(logEntry.response.getResponse(), False)

						# set the currently displayed log entry
						self.extender._currentlyDisplayedLogEntry = logEntry.response
					except:
						# clear response
						self.extender._responseViewerAutoProxy.setMessage("", False)
				except:
					pass
		# table lock was true
		else:
			# set table change lock to false
			self.extender._customJTableLogsTableChangeLock = False

		# try to add default tableChanged
		try:
			# add default tableChanged
			JTable.tableChanged(self, event)
		except:
			pass


#
# extend Runnable to insert or delete from log table triggered by button actions
#

class CustomRunnable(Runnable):

	# initialize variables
	def __init__(self, extender, fireTableRowsAction, firstRowIndex, lastRowIndex):
		self.extender = extender
		self.fireTableRowsAction = fireTableRowsAction
		self.firstRowIndex = firstRowIndex
		self.lastRowIndex = lastRowIndex

	# override run method
	def run(self):

		# check if action is to insert 
		if self.fireTableRowsAction == "insert":

			# try to insert into log table
			try:
				# insert into log table
				self.extender.fireTableRowsInserted(self.firstRowIndex, self.lastRowIndex)
			except:
				pass

		# check if action is to delete
		elif self.fireTableRowsAction == "delete":

			# try to delete from log table
			try:
				# delete from log table
				self.extender.fireTableRowsDeleted(self.firstRowIndex, self.lastRowIndex)
			except:
				pass

		# check if action is to update
		elif self.fireTableRowsAction == "update":

			# try to update log table
			try:
				# update log table
				self.extender.fireTableDataChanged()
			except:
				pass


#
# extend IHttpRequestResponse to build log table requests triggered by button actions
#

class CustomIHttpRequestResponse(IHttpRequestResponse):

	# initialize variables
	def __init__(self, request, response, httpService):
		self._request = request
		self._response = response
		self._httpService = httpService

	# override getRequest method
	def getRequest(self):
		return self._request

	# override getResponse method
	def getResponse(self):
		return self._response

	# override getHttpService method
	def getHttpService(self):
		return self._httpService


#
# extend TableRowSorter to toggle sorting ascending descending unsorted
#

class CustomTableRowSorter(TableRowSorter):

	# override toggleSortOrder method
	def toggleSortOrder(self, column):

		# check if valid column 
		if column >= 0:

			# get the sort keys
			keys = self.getSortKeys()

			# check if the sort keys are not empty
			if keys.isEmpty() == False:

				# get the sort key
				sortKey = keys.get(0)

				# check if the column clicked is sorted in descending order
				if sortKey.getColumn() == column and sortKey.getSortOrder() == SortOrder.DESCENDING:

					# clear sorting
					self.setSortKeys(None)

					# do not continue
					return

		# try to toggle default toggleSortOrder
		try:
			# toggle default toggleSortOrder
			TableRowSorter.toggleSortOrder(self, column)

		# catch if table is being sorted by processProxyMessage and user
		except:
			pass


#
# extend RowFilter to filter rows in the log table
#

class CustomRowFilter(RowFilter):

	# initialize variables
	def __init__(self, extender):
		self.extender = extender

	# override include method
	def include(self, entry):

		# filter on the AutoAction column
		def getFilterAction(self, entry):

			# check if log table should show rows with AutoAction of No
			if self.extender._checkboxAutoProxyAutoFilterActionNo.isSelected() and entry.getValue(5) == "No":
				return True

			# check if log table should show rows with AutoAction of Forwarded
			elif self.extender._checkboxAutoProxyAutoFilterActionForwarded.isSelected() and entry.getValue(5) == "Forwarded":
				return True

			# check if log table should show rows with AutoAction of Intercepted
			elif self.extender._checkboxAutoProxyAutoFilterActionIntercepted.isSelected() and entry.getValue(5) == "Intercepted":
				return True

			# check if log table should show rows with AutoAction of Dropped
			elif self.extender._checkboxAutoProxyAutoFilterActionDropped.isSelected() and entry.getValue(5) == "Dropped":
				return True

			# check if log table should show rows with AutoAction of Blocked
			elif self.extender._checkboxAutoProxyAutoFilterActionBlocked.isSelected() and entry.getValue(5) == "Blocked":
				return True

			# no checkboxes checked
			else:
				return False

		# filter the log table
		def getFilter(entry, filterInput, logTableColumn):

			# show the row by default
			rowVisible = True

			# loop through each filter
			for row in filterInput.getText().splitlines():

				# check if the filter should remove the row if it matches
				if len(row) > 0 and row[:1] == "-":

					# check if protocol or port column
					if logTableColumn == 2 or logTableColumn == 3:

						# check if the filter row matches the column using an exact match
						if len(row) > 1 and row[1:].lower() == unicode(entry.getValue(logTableColumn)).lower():

							# do not show row
							return False

					# not protocol or port column
					else:
						# check if the filter row matches the column
						if len(row) > 1 and row[1:].lower() in unicode(entry.getValue(logTableColumn)).lower():

							# do not show row
							return False

				# filter should keep the row if it matches
				else:
					# check if protocol or port column
					if logTableColumn == 2 or logTableColumn == 3:

						# check if the filter row matches the column
						if row.lower() != "" and row.lower() == unicode(entry.getValue(logTableColumn)).lower():

							# show row
							return True

						# does not match filter to hide row so show it
						else:
							# set rowVisible to false
							rowVisible = False

					# not protocol or port column
					else:
						# check if the filter row matches the column
						if row.lower() != "" and row.lower() in unicode(entry.getValue(logTableColumn)).lower():

							# show row
							return True

						# does not match filter to hide row so show it
						else:
							# set rowVisible to false
							rowVisible = False

			# return if the row is visible
			return rowVisible

		# filter on the request for the given row
		def getFilterRequestResponse(self, entry, requestOrResponse):

			# create a string of the log table entry
			logTableString = ""

			# loop through each column in the log table
			for i in range(0, 9):

				# append the value
				logTableString += str(entry.getValue(i))

			# create a match index
			matchIndex = -1

			# loop through the logs
			for x in range(0, self.extender._log.size()):

				# create a string of the log entry
				logString = ""

				# loop through all of the columns
				for i in range(0, 9):

					# append to the string
					logString += str(self.extender.getValueAt(x, i))

				# check if the entry row matches this log table row
				if logTableString == logString:

					# set the match index
					matchIndex = x

					# do not continue through the logs
					break

			# create variable for the matched request or response
			matchRequestResponse = ""

			# check that a match was found
			if matchIndex > -1:

				# try to get the log details and request or response details
				try:
					# get log details
					logEntry = self.extender._log.get(matchIndex)

					# check if it is a request filter
					if requestOrResponse == "request":

						# get request details
						matchRequestResponse = logEntry.request.getRequest().tostring()

					# requestOrResponse == "response"
					else:
						# get response details
						matchRequestResponse = logEntry.response.getResponse().tostring()
				except:
					pass

			# set the filter to search through
			if requestOrResponse == "request":

				# get the request filter rows
				filterRows = self.extender._textAreaAutoProxyAutoFilterRequestInput.getText().splitlines()

			# requestOrResponse == "response"
			else:
				# get the response filter rows
				filterRows = self.extender._textAreaAutoProxyAutoFilterResponseInput.getText().splitlines()

			# loop through each request or response row to filter
			for row in filterRows:

				# check if row should be a case sensitive search
				if row.startswith("Case Sensitive: ") and len(row) > 16:

					# should be a case sensitive search
					caseSensitiveSearch = True

					# split string to remove "Case Sensitive Search: "
					row = row[16:]

				# not case sensitive search
				else:
					# should not be a case sensitive search
					caseSensitiveSearch = False

				# check if it is a request filter
				if requestOrResponse == "request":

					# remove the first two line containing the url and host
					matchRequestResponse = matchRequestResponse.split("\n")[2:]

					# create a new request body
					newMatchRequestResponse = ""

					# loop through the current request body
					for rowMatchRequestResponse in matchRequestResponse:

						# check if the row does not start with referer
						if not rowMatchRequestResponse.startswith("Referer: "):

							# append row to new request body
							newMatchRequestResponse += rowMatchRequestResponse

					# set the request to the new request
					matchRequestResponse = newMatchRequestResponse

				# check if case sensitive search
				if caseSensitiveSearch:

					# check if the filter row matches the request or response
					if row in matchRequestResponse:
						return True

				# not a case sensitive search
				else:
					# check if the filter row matches the request or response
					if row.lower() in matchRequestResponse.lower():
						return True

			# request or response filter did not match
			return False

		# check if the action filter does not match
		if getFilterAction(self, entry) == False:

			# do not show row
			return False

		# check if the method filter is blank
		if self.extender._textAreaAutoProxyAutoFilterMethodInput.getText() == "":

			# do not filter out the row due to method filter since there is not a method filter set
			methodFilter = True
		else:
			# check if the method filter should filter out the row or not
			methodFilter = getFilter(entry, self.extender._textAreaAutoProxyAutoFilterMethodInput, 1)

		# check if the protocol filter is blank
		if self.extender._textAreaAutoProxyAutoFilterProtocolInput.getText() == "":

			# do not filter out the row due to protocol filter since there is not a protocol filter set
			protocolFilter = True
		else:
			# check if the protocol filter should filter out the row or not
			protocolFilter = getFilter(entry, self.extender._textAreaAutoProxyAutoFilterProtocolInput, 2)

		# check if the port filter is blank
		if self.extender._textAreaAutoProxyAutoFilterPortInput.getText() == "":

			# do not filter out the row due to port filter since there is not a port filter set
			portFilter = True
		else:
			# check if the port filter should filter out the row or not
			portFilter = getFilter(entry, self.extender._textAreaAutoProxyAutoFilterPortInput, 3)

		# check if the host filter is blank
		if self.extender._textAreaAutoProxyAutoFilterHostInput.getText() == "":

			# do not filter out the row due to host filter since there is not a host filter set
			hostFilter = True
		else:
			# check if the host filter should filter out the row or not
			hostFilter = getFilter(entry, self.extender._textAreaAutoProxyAutoFilterHostInput, 4)

		# check if the referer filter is blank
		if self.extender._textAreaAutoProxyAutoFilterRefererInput.getText() == "":

			# do not filter out the row due to referer filter since there is not a referer filter set
			refererFilter = True
		else:
			# check if the referer filter should filter out the row or not
			refererFilter = getFilter(entry, self.extender._textAreaAutoProxyAutoFilterRefererInput, 7)

		# check if the url filter is blank
		if self.extender._textAreaAutoProxyAutoFilterUrlInput.getText() == "":

			# do not filter out the row due to url filter since there is not a url filter set
			urlFilter = True
		else:
			# check if the url filter should filter out the row or not
			urlFilter = getFilter(entry, self.extender._textAreaAutoProxyAutoFilterUrlInput, 8)

		# check if the path filter is blank
		if self.extender._textAreaAutoProxyAutoFilterPathInput.getText() == "":

			# do not filter out the row due to path filter since there is not a path filter set
			pathFilter = True
		else:
			# check if the path filter should filter out the row or not
			pathFilter = getFilter(entry, self.extender._textAreaAutoProxyAutoFilterPathInput, 9)

		# check if the request filter is blank
		if self.extender._textAreaAutoProxyAutoFilterRequestInput.getText() == "":

			# do not filter out the row due to request filter since there is not a request filter set
			requestFilter = True
		else:
			# check if the request filter should filter out the row or not
			requestFilter = getFilterRequestResponse(self, entry, "request")

		# check if the request filter is blank
		if self.extender._textAreaAutoProxyAutoFilterResponseInput.getText() == "":

			# do not filter out the row due to response filter since there is not a response filter set
			responseFilter = True
		else:
			# check if the response filter should filter out the row or not
			responseFilter = getFilterRequestResponse(self, entry, "response")

		# return if the row should be filtered out or not
		return (methodFilter and protocolFilter and portFilter and hostFilter and refererFilter and urlFilter and pathFilter and requestFilter and responseFilter)


#
# extend ItemListener to detect checkbox actions to filter log table by action
#

class CustomItemListener(ItemListener):

	# initialize variables
	def __init__(self, extender):
		self.extender = extender

	# override itemStateChanged method
	def itemStateChanged(self, event):

		# try to update log table
		try:
			# update log table
			self.extender.fireTableDataChanged()

			# will not allow the original row to remain selected
			# SwingUtilities.invokeLater(CustomRunnable(self.extender, "update", 0, 0))
		except:
			pass

		# try to keep the same row selected
		try:
			# set the row to select accounting for sorting and filtering
			rowToSelect = self.extender._tableAutoProxyLogs.convertRowIndexToView(self.extender._currentlySelectedLogTableRow)

			# keep same row selected
			self.extender._tableAutoProxyLogs.setRowSelectionInterval(rowToSelect, rowToSelect)

			# get log details for selected row accounting for sorting
			logEntry = self.extender._log.get(self.extender._currentlySelectedLogTableRow)

			# show log entry for selected row
			self.extender._requestViewerAutoProxy.setMessage(logEntry.request.getRequest(), True)

			# try to show response for selected row
			try:
				# show response
				self.extender._responseViewerAutoProxy.setMessage(logEntry.response.getResponse(), False)

				# set the currently displayed log entry
				self.extender._currentlyDisplayedLogEntry = logEntry.response
			except:
				# clear response
				self.extender._responseViewerAutoProxy.setMessage("", False)
		except:
			# clear request viewer
			self.extender._requestViewerAutoProxy.setMessage("", True)

			# clear response viewer
			self.extender._responseViewerAutoProxy.setMessage("", True)


#
# extend DocumentListener to filter log table by host or method when text is inserted or removed from filter text areas
#

class CustomDocumentListener(DocumentListener):

	# initialize variables
	def __init__(self, extender):
		self.extender = extender

	# override changedUpdate method for when the style of text changes
	def changedUpdate(self, event):
		pass

	# override changedUpdate method for when text is inserted
	def insertUpdate(self, event):

		# try to update log table
		try:
			# update log table
			self.extender.fireTableDataChanged()
		except:
			pass

		# try to keep the same row selected
		try:
			# set the row to select accounting for sorting and filtering
			rowToSelect = self.extender._tableAutoProxyLogs.convertRowIndexToView(self.extender._currentlySelectedLogTableRow)

			# keep same row selected
			self.extender._tableAutoProxyLogs.setRowSelectionInterval(rowToSelect, rowToSelect)

			# get log details for selected row accounting for sorting
			logEntry = self.extender._log.get(self.extender._currentlySelectedLogTableRow)

			# show log entry for selected row
			self.extender._requestViewerAutoProxy.setMessage(logEntry.request.getRequest(), True)

			# try to show response for selected row
			try:
				# show response
				self.extender._responseViewerAutoProxy.setMessage(logEntry.response.getResponse(), False)

				# set the currently displayed log entry
				self.extender._currentlyDisplayedLogEntry = logEntry.response
			except:
				# clear response
				self.extender._responseViewerAutoProxy.setMessage("", False)
		except:
			# clear request viewer
			self.extender._requestViewerAutoProxy.setMessage("", True)

			# clear response viewer
			self.extender._responseViewerAutoProxy.setMessage("", True)

	# override changedUpdate method for when text is removed
	def removeUpdate(self, event):

		# try to update log table
		try:
			# update log table
			self.extender.fireTableDataChanged()
		except:
			pass

		# try to keep the same row selected
		try:
			# set the row to select accounting for sorting and filtering
			rowToSelect = self.extender._tableAutoProxyLogs.convertRowIndexToView(self.extender._currentlySelectedLogTableRow)

			# keep same row selected
			self.extender._tableAutoProxyLogs.setRowSelectionInterval(rowToSelect, rowToSelect)

			# get log details for selected row accounting for sorting
			logEntry = self.extender._log.get(self.extender._currentlySelectedLogTableRow)

			# show log entry for selected row
			self.extender._requestViewerAutoProxy.setMessage(logEntry.request.getRequest(), True)

			# try to show response for selected row
			try:
				# show response
				self.extender._responseViewerAutoProxy.setMessage(logEntry.response.getResponse(), False)

				# set the currently displayed log entry
				self.extender._currentlyDisplayedLogEntry = logEntry.response
			except:
				# clear response
				self.extender._responseViewerAutoProxy.setMessage("", False)
		except:
			# clear request viewer
			self.extender._requestViewerAutoProxy.setMessage("", True)

			# clear response viewer
			self.extender._responseViewerAutoProxy.setMessage("", True)


#
# extend TableCellRenderer to align column headers for AutoAction host table
#

class CustomTableCellRendererHostTable(TableCellRenderer):

	# initialize variables
	def __init__(self, defaultCellRender):
		self.defaultCellRender = defaultCellRender

	# override getTableCellRendererComponent method
	def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
		
		# add default getTableCellRendererComponent
		self.defaultCellRender.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)

		# check if column index is greater than 1
		if column > 1:

			# center align column header
			self.defaultCellRender.setHorizontalAlignment(JLabel.CENTER)

		# column index is not greater than 1
		else:
			# left align column header
			self.defaultCellRender.setHorizontalAlignment(JLabel.LEFT)			

		# return aligned column headers
		return self.defaultCellRender


#
# extend DefaultTableModel to add checkboxes to AutoAction host table
#

class CustomDefaultTableModelHosts(DefaultTableModel):

	# override isCellEditable method
	def isCellEditable(self, row, column):

		# check if column index is greater than 1
		if column > 1:

			# set column as editable for checkbox
			return 1

		# column index not greater than 1
		else:
			# set column as not editable
			return 0
	
	# override getColumnClass method
	def getColumnClass(self, column):

		# check if column index is greater than 1
		if column > 1:

			# set object type to boolean for checkbox
			return lang.Boolean

		# column index not greater than 1
		else:
			# try to get the value for the fist row in the current column
			try:
				# get the object type
				objectType = type(self.getValueAt(0, column))

			# catch exception from clearing table because getValueAt will return null
			except:
				# set default object type to string
				objectType = lang.String

			# return the object type
			return objectType


#
# extend JTable to add checkbox listeners for AutoAction host table
#

class CustomJTableHosts(JTable):

	# initialize variables
	def __init__(self, extender, textAreaForward, textAreaIntercept, textAreaDrop):
		self.extender = extender
		self.setModel(extender)
		self.textAreaForward = textAreaForward
		self.textAreaIntercept = textAreaIntercept
		self.textAreaDrop = textAreaDrop

	# override tableChanged method
	def tableChanged(self, event):

		# get changed column
		changedColumnIndex = event.getColumn()

		# return if header row or new row being added
		if event.getFirstRow() == event.HEADER_ROW or changedColumnIndex < 2:

			# try to add default tableChanged
			try:
				# add default tableChanged
				JTable.tableChanged(self, event)
			except:
				pass

			# do not continue
			return
		
		# get index of row
		modelRowIndex = event.getFirstRow()

		# get table model
		model = event.getSource()

		# get host for selected row
		host = model.getValueAt(modelRowIndex, 1)

		# adds or removes host from list
		def addOrRemoveHost(listAction, changedHost, textArea):

			# get current host list
			oldHostList = textArea.getText()

			# create new host list
			newHostList = ""

			# convert host to regex format
			changedHostRegexFormat = changedHost.replace(".", "\.")

			# add host to list
			if listAction == "Add":

				# add host to new host list
				newHostList = changedHostRegexFormat + "\r\n" + oldHostList

			# remove host from list
			else:
				# loop through each row
				for row in oldHostList.splitlines():

					# check if row equals the host to remove (will remove multiple rows if the same host was manually entered multiple times)
					if row == changedHostRegexFormat:
						continue

					# add non-matching rows to new host list
					newHostList += row + "\r\n"

			# remove trailing line breaks
			newHostList = newHostList.rstrip("\r\n")

			# update host list
			textArea.setText(newHostList)

			# scroll to top of list
			textArea.setCaretPosition(0)

		# get checkbox value and not checkbox value
		checkboxIsChecked = model.getValueAt(modelRowIndex, changedColumnIndex)
		checkboxIsNotChecked = not checkboxIsChecked

		# checkbox checked in forward column
		if checkboxIsChecked and changedColumnIndex == 2:

			# add host to AutoForward Hosts
			addOrRemoveHost("Add", host, self.textAreaForward)

		# checkbox unchecked in forward column
		elif checkboxIsNotChecked and changedColumnIndex == 2:

			# remove host from AutoForward Hosts
			addOrRemoveHost("Remove", host, self.textAreaForward)

		# checkbox checked in intercept column
		elif checkboxIsChecked and changedColumnIndex == 3:

			# add host to AutoIntercept Hosts
			addOrRemoveHost("Add", host, self.textAreaIntercept)

		# checkbox unchecked in intercept column
		elif checkboxIsNotChecked and changedColumnIndex == 3:

			# remove host from AutoIntercept Hosts
			addOrRemoveHost("Remove", host, self.textAreaIntercept)

		# checkbox checked in drop column
		elif checkboxIsChecked and changedColumnIndex == 4:

			# add host to AutoDrop Hosts
			addOrRemoveHost("Add", host, self.textAreaDrop)

		# checkbox unchecked in drop column
		elif checkboxIsNotChecked and changedColumnIndex == 4:

			# remove host from AutoDrop Hosts
			addOrRemoveHost("Remove", host, self.textAreaDrop)

		# try to add default tableChanged
		try:
			# add default tableChanged
			JTable.tableChanged(self, event)
		except:
			pass
