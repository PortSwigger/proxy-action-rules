# Proxy Action Rules

This extension can automatically forward, intercept, and drop proxy requests while actively displaying proxy log information and centralizing list management. This extension can also block ads, tracking sites, malware sites, etc. The state of the extension including the settings, filters, and data can easily be exported and imported.


## Requirements:
This extension requires Burp Suite and Jython standalone.
This extension does not require Burp Suite Professional.


## Main features include:
 - Automatically drop specific requests while browsing the web. (Proxy Intercept turned off.)
 - Automatically drop specific requests while intercepting requests to all other hosts. (Proxy Intercept turned on.)
 - Automatically forward specific requests while intercepting all other hosts. (Proxy Intercept turned on.)
 - Automatically intercept specific requests while browsing the web. (Proxy Intercept turned off.)
 - Automatically block specific requests to hosts that are known for ads, tracking, malware, etc.
 - Automatically flag specific requests for later review if they match the specified criteria.
 - Centralize the location of the lists that have to be managed to forward, intercept, and drop requests.
 - Actively view information from the proxy logs.


## Other features that have been added include:
 - A combination of the main features. For example, intercept requests to abc.com for inspection if they have the word password within the request, forward requests to test.abc.com even if they have the word password within the request, and drop all other requests that are not to abc.com.
 - Keep track of unique hosts that had requests.
 - Filter the proxy logs by the method, protocol, port, host, referrer, URL, path, request, and response.
 - Easily save/restore the settings and data for the extension.
 - Clear settings, data, and filters from the extension.
 - Undo the most recent clearing of settings and filters, in case they are accidentally cleared.
 - Test settings and regex to see the outcome of the extensions without having to actually visit the hosts.
 - Easily copy settings back and forth between the main tab and test tab.
 - Easily download multiple block lists containing hosts that are known for ads, tracking, malware, etc.


## Matching Options for the Main Features (To AutoForward, AutoIntercept, & AutoDrop Requests)

Requests can automatically be forwarded, intercepted, or dropped using a variety of matching options. Case insensitive, regex matching on the host name is used by default. Enter one host per line to use the default matching option.

The order of precedence if from left to right. The forward action takes precedence of the intercept action. The intercept action takes precedence of the drop action. The drop action takes precedence of the block action. Within the forward, intercept, and drop sections, the order of precedence if from top to bottom.

Other matching options are listed below. Enter one matching option per line. There should be one space after each semicolon, followed by a regex search string. Do not include the bullet or spaces after the bullet if pasting matching options.
 - Method: 
 - Protocol: 
 - Port: 
 - Host: 
 - Referer: 
 - URL: 
 - Path: 
 - Body: 

Note: The "Protocol: " and "Port: " options use starting and ending anchors "^$" with the matching string in between. This is so "Port: 80" will only match port 80, but regex can still be used to make it match any port that contains 80. The "Body: " option does not search the URL row, Host row, or Referer row within the request body. The URL, Host, and Referer options can be used to match these fields. The URL field will not include the port if the protocol/port is http/80 or https/443.


## Whitelisting Requests from Being AutoBlocked

If a block list is imported from the AutoBlock tab, any requests to matching hosts will be blocked. Entering hosts in the AutoForward Hosts section can act like a whitelist by allowing traffic to the specified hosts even if they are in a block list. Some websites require tracking to function properly.


## Matching Examples

The bullets below could be entered in the AutoForward, AutoIntercept, or AutoDrop sections to match the corresponding URL.

In the examples below, notice the following:
 - The word "ampl" can be typed in a row by itself and it would match any host containing ampl such as example.com.
 - Regex can be used to match any sites that use https on port 8443.
 - Specific words can be searched within the url, path, body, etc.

Below are matching examples for ```http://www.example.com/path/resource?a=b&c=d```.
 - example
 - Method: get
 - Protocol: http
 - Port: 80
 - Host: www\\.example\\.com
 - Referer: Referer_Domain_Name_Here
 - URL: ```http://www.example.com/path/resource?a=b&c=d```
 - Path: /path/resource?a=b&c=d
 - Body: Text_String_Within_The_Request_Body_Here

Below are some additional examples for ```https://example.com:8443/path/file.asp?name=test&a=b```.
 - ampl
 - Protocol: https
 - Port: 8443
 - Host: example.com
 - Host: ampl
 - URL: ```https://example.com:8443/path/file.asp?name=test&a=b```
 - URL: https.*example.*8443
 - URL: ^https.*8443
 - Path: /path/file.asp?name=test&a=b
 - Path: file.asp


## Filtering the Log Table

The log table can be filtered using a variety of case insensitive filters. Enter one filter string per line.

The Protocol and Port filters use an exact match. The Request filter does not search the URL row, Host row, or Referer row within the request body. The URL, Host, or Referer filters can be used to search these fields. The URL field will not include the port if the protocol/port is http/80 or https/443.

Case sensitive searching can be performed on the request and the response by using the filter option listed below. There should be one space after the semicolon, followed by a regex filter string.
 - Case Sensitive: 

Starting a row with a hyphen "-" will filter out matches. If you need to filter something with a hyphen in the filter string, put another character before the hyphen. The hyphen works for all filters except the request and response filters. The request and response filters will search for the string with the hyphen in it.
 - \-


## Clearing the Log Table

The log table can be cleared automatically if the size reaches 100 or 1000 rows. The AutoClear button is located near the log table filters within the main AutoProxy tab.
The log table can also be cleared completely from the AutoConfig tab.

## Other Tabs

 - AutoTest:
   - Test the default AutoProxy host matching option, without visiting any hosts.
 - AutoConfig:
   - Save, restore, copy, and clear data.
 - AutoBlock:
   - Download and import lists of hosts to block traffic to. Ads, tracking sites, malware, and more can be blocked.


## Usage
Enter one host per line. A regex statement or other matching option can be entered as well.

The order of precedence if from left to right. The forward action takes precedence of the intercept action. The intercept action takes precedence of the drop action. The drop action takes precedence of the block action. Within the forward, intercept, and drop sections, the order of precedence if from top to bottom.


## Background
This extension started as an extension that would automatically drop all requests to a list of specific hosts, while logging which requests were dropped. This functionality was similar to forwarding and intercepting requests so those features were added as well. Regex support and regex error handling were added, followed by other matching options. A responsive UI was created to look good with larger monitors, as well as, on smaller laptop screens. This way the extension works even if Burp is run on one side of the screen while the browser is on the other side. There are a few extensions that have the positions of buttons and text hard coded, causing them to run off the side of the screen while running Burp on a laptop.


## Why it was Started
This extension overcomes some limitations within Burp, centralizes list management from multiple areas within Burp, and displays logging information near the lists beings managed.

The built in HTTP history tab, under the Proxy tab, logs information about requests.

The built in Options tab under the Proxy tab has the Intercept Client Requests section allowing only specific requests to be intercepted.

The built in Scope tab under the Target tab allows targets to be included or excluded from the scope.

The built in Project Options tab has an option to drop out-of-scope requests. This creates an alert in the Alert tab and cause the Alert tab to flash each time a request is blocked. This flashing is unwanted if the block is expected. Other alerts may be missed if the alert tab is not cleared after each block.

If hosts are excluded from the scope, the option to drop all out-of-scope requests is selected, and proxy intercept is on, the requests that should be dropped are still shown sometimes. This seems to only be temporary, as if it takes some time to go into effect. Hosts can be included or excluded from being intercepted using the Intercept Client Requests section within the Proxy options tab but this causes duplicate work and can add an additional host list that needs to be managed. It can be difficult to manage this list while viewing the proxy logs to confirm hosts are dropped or forwarded because of the constant clicking back and forth between multiple tabs. Additionally, there are not columns to view which requests were dropped, forwarded, and intercepted. To see if responses were dropped, each row in the log table has to be individually selected to see if there is a response tab or not. There were also limitations to searching the history.

There are other Burp limitations regarding forwarding, intercepting, and dropping requests. This extension overcomes these limitations of Burp but most of the limitations are related to specific use cases.


## Limitations
This extension intercepts requests before they hit the Proxy tab. While it can override some settings, it does not override all settings within Burp.

This extension can override the Proxy Intercept settings, but requests will default to the Proxy Intercept settings if they do not match the criteria to override these settings.
If the Proxy Intercept is turned off within the Proxy tab, but hosts are added to the intercept field within this extension, then it will intercept those requests as if the Proxy Intercept was on.

This extension does not override current settings such as "Drop all out-of-scope requests" from the Project options tab. This extension may show that the out-of-scope request was forwarded or intercepted which is the extension did, but after the request leaves the extension, it would be dropped by the Burp project options.


## Details About the AutoProxy Tab
This tab is the main tab for the extension.


### Top Section of the AutoProxy Tab

#### AutoForward Hosts
Input field containing hosts to forward requests to. Regex and additional matching options can also be used.*

#### AutoIntercept Hosts
Input field containing hosts to intercept requests to. Regex and additional matching options can also be used.*

#### AutoDrop Hosts
Input field containing hosts to drop requests to. Regex and additional matching options can also be used.*

*See all of the matching options in the Matching Options for the Main Features section.

If a regex error from the user is detected while trying to match to the current request, the regex error will be highlighted, and a popup will notify the user of the regex error.


###  Middle Section of AutoProxy Tab

#### AutoProxy Logs Tab
Contains a log table with detailed information from the proxy requests. The Time, Method, Protocol, Port, Host, AutoAction, Reason, Referer, URL, and Path are saved.

#### AutoAction Hosts Tab
Contains a table with unique hosts from the log table along with the first time the host had a request sent to it. This tab also provides a way to quickly add and remove hosts to the top three sections by using checkboxes. 

####  AutoRegex Hosts Tab
Contains a list of unique hosts in regex format.

####  AutoText Hosts Tab
Contains a list of unique hosts in text format.

####  AutoProxy Details Tab
Contains details about the extension.


###  Bottom Section of AutoProxy Tab

#### AutoFilter Logs Tab
Allows the log table to be filters or automatically cleared when it reaches a certain size.

 - AutoAction Filter
   - Filters the log table by the AutoAction column.

 - Method Filter 
   - Filters the log table by the Method column.
   - Rows can be filtered out of the log table by starting the row with a hyphen "-" followed by a search string.

 - Protocol Filter 
   - Filters the log table by the Protocol column. 
   - Rows can be filtered out of the log table by starting the row with a hyphen "-" followed by a search string.

 - Port Filter 
   - Filters the log table by the Port column. 
   - Rows can be filtered out of the log table by starting the row with a hyphen "-" followed by a search string.

 - Host Filter 
   - Filters the log table by the Host column. 
   - Rows can be filtered out of the log table by starting the row with a hyphen "-" followed by a search string.

 - Referer Filter 
   - Filters the log table by the Referer column. 
   - Rows can be filtered out of the log table by starting the row with a hyphen "-" followed by a search string.

 - URL Filter 
   - Filters the log table by the URL column. 
   - Rows can be filtered out of the log table by starting the row with a hyphen "-" followed by a search string.

 - Path Filter 
   - Filters the log table by the Path column. 
   - Rows can be filtered out of the log table by starting the row with a hyphen "-" followed by a search string.

 - Response Filter 
   - Filters the log table by the Request Details tab using a case insensitive search by default. 
   - Case sensitive searching can be performed using "Case Sensitive: " followed by a search string.

 - Request Filter
   - Filters the log table by the Request Details tab using a case insensitive search by default. 
   - Case sensitive searching can be performed using "Case Sensitive: " followed by a search string.

 - AutoClear Button
   - If enabled, the log table will automatically be cleared if the size reaches 100, or 1000 rows.

#### Request Details Tab
Displays additional request details for the row currently selected in the log table.

#### Response Details Tab
Displays additional response details for the row currently selected in the log table.


## Details About the AutoTest Tab
The AutoProxy settings can be tested without actually visiting the hosts.

### AutoTest Hosts
Input field to test hosts that would be visited in the browser.

### Start AutoTest Button
Button to start the test after filling in all four input fields.

### AutoForward Hosts
Input field containing hosts to forward requests to.

### AutoIntercept Hosts
Input field containing hosts to intercept requests to.

### AutoDrop Hosts
Input field containing hosts to drop requests to.

### NoAction
Output for hosts that would not be forwarded, intercepted, or dropped.

### AutoForwarded
Output for hosts that would be forwarded.

### AutoIntercepted
Output for hosts that would be intercepted.

### AutoDropped
Output for hosts that would be dropped.

### Other AutoTest Details
Normally the tab key would insert a tab into the text fields.  Instead, the tab key will transfer focus to next text area.

If there are blank lines or lines containing only spaces/tabs, they will be removed. 

The output text areas will automatically scroll to the top in case there is a large amount of text.

If there is a regex error, any selected text is deselected while the caret position stays in the same position. The text area will not scroll to top or bottom of the text area.

If there are not any regex errors, selected text will remain selected.

If there is a regex error, the focus is shifted to host input text area.

If there is a regex error, a message box will be displayed showing what caused the error and which text area it came from. The error message box allows suppressing future errors for the current set of checks in case there are many errors. This is to avoid having to click through many errors.

If there is a regex error, the error will be highlighted in red. When focus is transferred to the text area with a highlighted regex error, the red highlights will be removed.


## Details About the AutoConfig Tab
This tab allows for easy configuration of the extension.


### Save State Section
Allows for saving the state of the extension.

#### AutoProxy Settings
The top three text areas in the AutoProxy tab.

#### AutoProxy Logs/Data
The middle four tabs in the AutoProxy tab.

#### AutoProxy Filters
The bottom text areas in the AutoProxy tab.

#### AutoTest Settings
The top four text areas in the AutoTest tab.


### Restore State Section
Allows for restoring the state of the extension. 

#### AutoProxy Settings
The top three text areas in the AutoProxy tab.

#### AutoProxy Logs/Data
The middle four tabs in the AutoProxy tab.

#### AutoProxy Filters
The bottom text areas in the AutoProxy tab.

#### AutoTest Settings
The top four text areas in the AutoTest tab.

If the logs and data are restored without the AutoProxy settings, then the AutoAction table will unselect all of the checkboxes within the table. If the logs and data are restored with the settings, then the checkboxes will restore as they were saved since they will match what is in the settings.


### Export Log Table To CSV Section
Exports the log table to a CSV file.


### Import Log Table From CSV Section
Imports the log table from a CSV file.


### Copy Section
Quickly copies the content to and from text areas.

#### Copy AutoProxy Settings to AutoTest
Copies the top three text areas from the AutoProxy tab to the top three text areas in the AutoTest tab.

#### Copy AutoTest Settings to AutoProxy
Copies the top three text areas settings from the AutoTest tab to the top three text areas in the AutoProxy tab.

#### Copy AutoText hosts to AutoTest Hosts
Copies the hosts stored in the middle AutoProxy AutoText Hosts tab to the AutoTest Hosts text field.


### Clear Section
Quickly clears the logs, data, settings, and filters.

#### Clear AutoProxy Logs/Data
Clears the middle AutoProxy tabs.

#### Clear AutoProxy/AutoTest Settings & Filters
Clears the top and bottom text areas from the AutoProxy and AutoTest tabs.

####  Undo Clear AutoProxy/AutoTest Settings & Filters
Restores the AutoProxy and AutoTest settings and filters that were last cleared.


## Details About the AutoBlock Tab
This tab allows for the downloading and importing of block lists containing hosts that are known for ads, tracking, malware, etc.
For the request to be blocked, the host in the block list must match the host in the request.

During testing, it took .01 microseconds to check through blank AutoForward, AutoIntercept, and AutoDrop lists. 
Multiple block lists were loaded containing a total of almost 1,000,000 hosts to block. It took .103 microseconds to check through the same blank AutoForward, AutoIntercept, and AutoDrop lists along with the block lists.
Searching nearly 1,000,000 hosts to block took 0.093 microseconds longer or 0.000000093 seconds if the host is not in any of the block host lists. If the host in within a block list, it could take less time because it would not continue searching through all of the hosts to block. If the host already has an action of forwarded, intercepted, or dropped, it will not be checked against any block lists.

Browsing may be quicker than normal as additional pages such as ads or tracking will not be loaded and will be dropped instead. Performance may vary.

Below are the block lists available. A custom block list can also be imported and should contain one host per line.
If a block list is disabled, the button next to the list will be red. If blocking is enabled, the button will be green.

### Download & Enable All
Attempts to download and enable all of the block lists. This could take a few minutes.

### Cameleon Block List
```http://sysctl.org/cameleon/hosts```

Will attempt to download and save the list as BurpAutoProxyBlockList-Cameleon.txt

### Disconnect.me Ads Block List
```https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt```

Will attempt to download and save the list as BurpAutoProxyBlockList-DisconnectMeAds.txt

### Disconnect.me Tracking Block List
```https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt```

Will attempt to download and save the list as BurpAutoProxyBlockList-DisconnectMeTracking.txt

### Hosts-File.net Ads & Tracking Block List
```https://hosts-file.net/ad_servers.txt```

Will attempt to download and save the list as BurpAutoProxyBlockList-HostsFileNetAdsAndTracking.txt

### hpHosts Block List
```https://hosts-file.net/download/hosts.txt```

Will attempt to download and save the list as BurpAutoProxyBlockList-HpHosts.txt

### Malware Domains Block List
```https://mirror1.malwaredomains.com/files/justdomains```

Will attempt to download and save the list as BurpAutoProxyBlockList-MalwareDomains.txt

### Steven Black's Block List
```https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts```

Will attempt to download and save the list as BurpAutoProxyBlockList-StevenBlack.txt

### Zeustracker Block List
```https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist```

Will attempt to download and save the list as BurpAutoProxyBlockList-Zeustracker.txt

### Custom Block List
A custom block list can be imported. The list should contain one host per row.


## Details About Using Regex 

The regex matching for AutoForward Hosts, AutoIntercept Hosts, and AutoDrop Hosts,  is in the following format (?i)your_regex_here where "your_regex_here" is each line of text within the top three text areas. The regex matching is case insensitive.

### Regex Error Checking
If a regex error by the user is detected while trying to match to the current request, the regex error will be highlighted in red, and a popup will notify the user of the regex error. The popup will ask if the request should be dropped, forwarded, or intercepted because the user's regex error prevented the extension from being able to determine the intended action.

### Regex Examples
Since a period "." matches any character (except for line terminators) putting abc.com will match the host abc.com but would also match abczcom. It would be better to use abc\\.com because "\\." matches the period "." literally. However, being that the text entered is in the format (?i)your_regex_here for most cases, it should be okay to enter hosts in either format. Not having to add a backslash may be easier when copying and pasting from a lists of hosts. Although it would be quick and easy to perform a find and replace to replace any "." characters with "\\." characters. The examples below include the backslash to match the period character literally, but most examples would achieve similar results without the backslash.

The examples below are demonstrating how to drop requests but similar regex could be used to forward or intercept requests.

Drop to abc.com
 - abc\\.com

Drop to abc.com (Would also drop to abcacom, abcbcom, abcccom, etc. In most cases this shouldn't cause an issue unless there happens to be a host such as abcacom that requests should not be dropped to but do want to drop requests to abc.com)
 - abc.com

Drop to all domains ".*" or "." can be used
 - .

Drop to all domains containing abc
 - abc

Drop to all domains starting with abc
 - ^abc

Drop to domains ending with abc.com
 - abc\\.com$

Drop to abc.com (Will not drop to subdomain.abc.com)
 - ^abc\\.com$

Drop to abc.com and ```www.abc.com```
 - ^(www\\.)?abc\\.com$

Drop to abc.com, ```www.abc.com```, xyz.com, ```www.xyz.com```, and any subdomains
 - ^((www\\.)\*(.\*\\.)*(abc|xyz)\\.com)$

Drop to domains containing abc or xyz (Can be put on separate lines or combined  to one line)
 - abc
 - xyz
 - abc|xyz

Drop to xabc.com, yabc.com, and zabc.com
 - ^[xyz]abc\\.com$

Drop to abc.com, xabc.com, yabc.com, and zabc.com
 - ^[xyz]?abc\\.com$
 - ^[xyz]{,1}abc\\.com$

Drop to abc(6-8 digits)xyz.com example: abc123456xyz.com
 - ^abc\\d{6,8}xyz\\.com$

Drop to all hosts unless they contain abc.
 - ^((?!(abc)).)*$

Drop to all hosts unless they contain abc.
 - Enter ".*" in the drop field and "abc" in the forward or intercept field.

Drop to all hosts unless they have abc or xyz in them
 - ^((?!(abc|xyz)).)*$

Drop to all hosts except abc.com and xyz.com (Will not drop to subdomains.abc.com or ```www.abc.com```)
 - ^((?!((www\\.)\*(.\*\\.)\*(abc|xyz)\\.com)).)\*$

Drop to IP Addresses
 - ((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)

Testing was performed at ```https://regex101.com/``` choosing Python as the flavor (on the left side of the screen) along with the flags "global" and "multi line" (flag icon to the right of your regex input) using the regex format (?i)your_regex_here where your_regex_here is the data entered into the Active AutoProxy extension.


## License
[MIT License](LICENSE)

