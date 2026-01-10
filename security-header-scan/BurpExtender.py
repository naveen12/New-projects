
# coding=utf-8
# Burp Extender: Security Headers Analyzer
# Author: Naveen Yalagandula
# Version: 1.0

# Jython/Python Standard Libraries
import sys
import json
import re
from collections import defaultdict
from threading import Lock

# Java Swing GUI
from javax.swing import (JPanel, JButton, JTable, JScrollPane, JComboBox,
                         JLabel, JCheckBox, JMenuItem, JFileChooser, JOptionPane, JEditorPane, DefaultListModel, JList, SwingUtilities, JTextField, JPopupMenu)
from javax.swing.table import (AbstractTableModel, DefaultTableCellRenderer)
from java.awt import (BorderLayout, FlowLayout, GridLayout, Font, Point, Dimension, Color)
from java.awt.event import MouseAdapter
from java.lang import String
from java.util import ArrayList

# Burp Suite APIs
from burp import (IBurpExtender, ITab, IHttpListener, IContextMenuFactory,
                  IHttpRequestResponse, IContextMenuInvocation)

# Constants
EXTENSION_NAME = "Security Headers Analyzer"
VERSION = "1.0"

# List of static file extensions to ignore
STATIC_EXTENSIONS = [
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".mp3", ".webm"
]

# Security Headers to be checked
SECURITY_HEADERS = [
    "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
    "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
    "Cache-Control", "Set-Cookie-Secure", "Set-Cookie-HttpOnly", "Set-Cookie-SameSite"
]

# Application Profiles and their header weights
# Profiles can be customized to change the importance of headers
PROFILES = {
    "Default Web Application": {
        "Strict-Transport-Security": 10, "Content-Security-Policy": 20,
        "X-Frame-Options": 10, "X-Content-Type-Options": 10,
        "Referrer-Policy": 5, "Permissions-Policy": 5, "Cache-Control": 5,
        "Set-Cookie-Secure": 15, "Set-Cookie-HttpOnly": 15, "Set-Cookie-SameSite": 5
    },
    "API Endpoint": {
        "Strict-Transport-Security": 10, "Content-Security-Policy": 5,
        "X-Frame-Options": 0, "X-Content-Type-Options": 15,
        "Referrer-Policy": 5, "Permissions-Policy": 5, "Cache-Control": 10,
        "Set-Cookie-Secure": 20, "Set-Cookie-HttpOnly": 20, "Set-Cookie-SameSite": 10
    },
    "SSO Authenticated Zone": {
        "Strict-Transport-Security": 15, "Content-Security-Policy": 25,
        "X-Frame-Options": 15, "X-Content-Type-Options": 10,
        "Referrer-Policy": 5, "Permissions-Policy": 5, "Cache-Control": 5,
        "Set-Cookie-Secure": 20, "Set-Cookie-HttpOnly": 20, "Set-Cookie-SameSite": 10
    }
}


class BurpExtender(IBurpExtender, ITab, IHttpListener, IContextMenuFactory):
    """
    Main class for the Security Headers Analyzer extension.
    """

    def registerExtenderCallbacks(self, callbacks):
        """
        Entry point for the Burp extension.
        """
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(EXTENSION_NAME)

        # Data stores
        self._analyzed_results = ArrayList()
        self._excluded_urls = ArrayList()
        self._lock = Lock()

        # Initialize UI
        self._init_ui()

        # Register listeners and factories
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        
        print "{} v{} loaded successfully.".format(EXTENSION_NAME, VERSION)
        return

    def _init_ui(self):
        """
        Initializes the Swing UI for the custom tab.
        """
        self._main_panel = JPanel(BorderLayout())

        # --- Top Control Panel ---
        controls_panel = JPanel(GridLayout(1, 3, 10, 10))
        
        # Target & Controls
        target_panel = JPanel(BorderLayout(5, 5))
        target_panel.setBorder(self._create_titled_border("Target & Controls"))

        self._scope_list_model = DefaultListModel()
        self._scope_list = JList(self._scope_list_model)
        scope_scroll_pane = JScrollPane(self._scope_list)

        # Panel for buttons and checkboxes at the bottom
        bottom_controls_panel = JPanel(GridLayout(0, 1))

        self._auto_detect_checkbox = JCheckBox("Auto-detect meaningful URLs", True)
        self._show_excluded_checkbox = JCheckBox("Show excluded URLs (debug)", False)
        
        checkbox_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        checkbox_panel.add(self._auto_detect_checkbox)
        checkbox_panel.add(self._show_excluded_checkbox)

        bottom_controls_panel.add(checkbox_panel)

        target_panel.add(scope_scroll_pane, BorderLayout.CENTER)
        target_panel.add(bottom_controls_panel, BorderLayout.SOUTH)
        
        # Application Context
        context_panel = JPanel(GridLayout(0, 1))
        context_panel.setBorder(self._create_titled_border("Application Context"))
        self._exposure_dropdown = JComboBox(["External", "Internal"])
        self._auth_dropdown = JComboBox(["Public", "SSO", "NA"])
        self._profile_dropdown = JComboBox(PROFILES.keys())
        context_panel.add(JLabel("Exposure:"))
        context_panel.add(self._exposure_dropdown)
        context_panel.add(JLabel("Authentication:"))
        context_panel.add(self._auth_dropdown)
        context_panel.add(JLabel("Profile:"))
        context_panel.add(self._profile_dropdown)

        # Actions
        actions_panel = JPanel(GridLayout(0, 1, 5, 5))
        actions_panel.setBorder(self._create_titled_border("Actions"))
        self._evaluate_button = JButton("Evaluate")
        self._evaluate_button.addActionListener(self._evaluate_action)
        self._export_button = JButton("Export...")
        self._export_button.addActionListener(self._export_action)
        self._help_button = JButton("Help")
        self._help_button.addActionListener(self._show_help_action)
        actions_panel.add(self._evaluate_button)
        actions_panel.add(self._export_button)
        actions_panel.add(self._help_button)

        controls_panel.add(target_panel)
        controls_panel.add(context_panel)
        controls_panel.add(actions_panel)

        # --- Center Results Panel ---
        results_container = JPanel(BorderLayout())

        # Summary Panel
        summary_panel = JPanel(FlowLayout(FlowLayout.CENTER, 20, 5))
        summary_panel.setBorder(self._create_titled_border("Overall Summary"))
        
        score_label_prefix = JLabel("Overall Score:")
        self._overall_score_label = JTextField("N/A", 8)
        self._overall_score_label.setEditable(False)
        self._overall_score_label.setBorder(None)
        self._overall_score_label.setOpaque(False)
        
        risk_label_prefix = JLabel("Overall Risk:")
        self._overall_risk_label = JTextField("N/A", 8)
        self._overall_risk_label.setEditable(False)
        self._overall_risk_label.setBorder(None)
        self._overall_risk_label.setOpaque(False)

        bold_font = score_label_prefix.getFont().deriveFont(Font.BOLD, 14.0)
        score_label_prefix.setFont(bold_font)
        self._overall_score_label.setFont(bold_font)
        risk_label_prefix.setFont(bold_font)
        self._overall_risk_label.setFont(bold_font)
        
        summary_panel.add(score_label_prefix)
        summary_panel.add(self._overall_score_label)
        summary_panel.add(risk_label_prefix)
        summary_panel.add(self._overall_risk_label)

        # Results Table
        self._table_model = ResultsTableModel(self._analyzed_results)
        self._results_table = JTable(self._table_model)
        # Apply the custom renderer to all String-based cells
        self._results_table.setDefaultRenderer(String, RiskAndHeaderCellRenderer())
        
        # Add a mouse listener for the context menu on the table
        self._results_table.addMouseListener(TableMouseListener(self))

        j_scroll_pane = JScrollPane(self._results_table)
        
        results_container.add(summary_panel, BorderLayout.NORTH)
        results_container.add(j_scroll_pane, BorderLayout.CENTER)

        self._main_panel.add(controls_panel, BorderLayout.NORTH)
        self._main_panel.add(results_container, BorderLayout.CENTER)
        
        return

    #
    # ITab implementation
    #
    def getTabCaption(self):
        return EXTENSION_NAME

    def getUiComponent(self):
        return self._main_panel

    #
    # IHttpListener implementation
    #
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """
        Processes HTTP messages for the 'Show excluded URLs' debug view.
        """
        if self._show_excluded_checkbox.isSelected() and not messageIsRequest and self._callbacks.isInScope(self._helpers.analyzeRequest(messageInfo).getUrl()):
            score, reason = self._get_relevance_score(messageInfo)
            if score < 40:
                with self._lock:
                    self._excluded_urls.add((self._helpers.analyzeRequest(messageInfo).getUrl(), reason))

    #
    # IContextMenuFactory implementation
    #
    def createMenuItems(self, invocation):
        """
        Creates context menu items for Burp's sitemap and other applicable locations.
        """
        context = invocation.getInvocationContext()
        
        # Context integer values for various locations in Burp.
        sitemap_contexts = {
            2, # CONTEXT_PROXY_HISTORY
            3, # CONTEXT_SCANNER_RESULTS
            4, # CONTEXT_TARGET_SITE_MAP_TREE
            5, # CONTEXT_TARGET_SITE_MAP_TABLE
            10, # CONTEXT_SEARCH_RESULTS
            11, # CONTEXT_INTRUDER_ATTACK_RESULTS
        }

        if context in sitemap_contexts:
            menu_list = ArrayList()
            
            def add_hosts_action(e):
                try:
                    selected_messages = invocation.getSelectedMessages()
                    if not selected_messages:
                        return
                    
                    hosts_to_add = set()
                    for message_info in selected_messages:
                        if message_info:
                            host = message_info.getHttpService().getHost()
                            hosts_to_add.add(host)
                    
                    added_count = 0
                    for host in hosts_to_add:
                        if not self._scope_list_model.contains(host):
                            self._scope_list_model.addElement(host)
                            added_count += 1
                    print "Added {} new host(s) to target list.".format(added_count)
                except Exception as ex:
                    print "Error adding hosts from context menu: {}".format(ex)

            menu_item = JMenuItem("Add host(s) to Security Headers Analyzer")
            menu_item.addActionListener(add_hosts_action)
            menu_list.add(menu_item)
            return menu_list

        return None

    #
    # UI Actions
    #
    def _evaluate_action(self, event):
        """
        Handles the 'Evaluate' button click. Actively collects requests from the
        sitemap for the selected hosts and performs the analysis.
        """
        try:
            print "Evaluation started."
            self._analyzed_results.clear()
            self._table_model.fireTableDataChanged()

            selected_hosts = self._scope_list.getSelectedValuesList()
            if selected_hosts.isEmpty():
                JOptionPane.showMessageDialog(self._main_panel, "No hosts selected in the target list.\nPlease add hosts via the Sitemap context menu first.", "No Targets", JOptionPane.WARNING_MESSAGE)
                return

            print "Collecting requests for hosts: {}".format(list(selected_hosts))
            requests_to_analyze = []
            sitemap = self._callbacks.getSiteMap(None)
            if sitemap:
                for item in sitemap:
                    if item.getHttpService().getHost() in selected_hosts:
                        requests_to_analyze.append(item)
            
            if not requests_to_analyze:
                JOptionPane.showMessageDialog(self._main_panel, "No requests found in the sitemap for the selected host(s).", "No Requests Found", JOptionPane.INFORMATION_MESSAGE)
                return
            
            print "Found {} requests to analyze.".format(len(requests_to_analyze))

            profile_name = self._profile_dropdown.getSelectedItem()
            app_context = {
                "exposure": self._exposure_dropdown.getSelectedItem(),
                "auth": self._auth_dropdown.getSelectedItem(),
                "profile": profile_name
            }

            for messageInfo in requests_to_analyze:
                if messageInfo is None or messageInfo.getResponse() is None:
                    continue
                
                # Apply relevance filtering if enabled
                if self._auto_detect_checkbox.isSelected():
                    score, reason = self._get_relevance_score(messageInfo)
                    if score >= 40:
                        analysis = self._analyze_single_request(messageInfo, app_context)
                        self._analyzed_results.add(analysis)
                else: # Analyze all if not auto-detecting
                    analysis = self._analyze_single_request(messageInfo, app_context)
                    self._analyzed_results.add(analysis)

            self._calculate_overall_score()
            
            def update_table():
                self._table_model.fireTableDataChanged()
                print "Evaluation finished. Displaying {} results.".format(len(self._analyzed_results))
                if self._analyzed_results.isEmpty() and len(requests_to_analyze) > 0:
                     JOptionPane.showMessageDialog(self._main_panel, "Evaluation finished, but no 'meaningful' URLs were found.\nTry unchecking 'Auto-detect meaningful URLs'.", "No Relevant URLs", JOptionPane.INFORMATION_MESSAGE)

            SwingUtilities.invokeLater(update_table)

        except Exception as e:
            print "An error occurred during evaluation: {}".format(e)
            import traceback
            traceback.print_exc()
            JOptionPane.showMessageDialog(self._main_panel, "An unexpected error occurred during evaluation.\nCheck the extension's output tabs for details.", "Error", JOptionPane.ERROR_MESSAGE)
        
    def _export_action(self, event):
        """
        Handles the 'Export' button click. Allows exporting results to CSV or JSON.
        """
        file_chooser = JFileChooser()
        file_chooser.setDialogTitle("Export Results")
        
        return_val = file_chooser.showSaveDialog(self._main_panel)
        if return_val == JFileChooser.APPROVE_OPTION:
            file_to_save = file_chooser.getSelectedFile()
            file_path = file_to_save.getAbsolutePath()

            if file_path.lower().endswith(".json"):
                self._export_as_json(file_path)
            else: # Default to CSV
                if not file_path.lower().endswith(".csv"):
                    file_path += ".csv"
                self._export_as_csv(file_path)

    def _show_help_action(self, event):
        """
        Displays a help dialog with instructions on how to use the extension.
        """
        from javax.swing import JOptionPane, JEditorPane
        from java.awt import Dimension

        # HTML content for better formatting
        help_content = self._get_help_content()

        # Use JEditorPane to render HTML
        editor_pane = JEditorPane("text/html", help_content)
        editor_pane.setEditable(False)
        
        scroll_pane = JScrollPane(editor_pane)
        scroll_pane.setPreferredSize(Dimension(600, 400))

        JOptionPane.showMessageDialog(self._main_panel,
                                      scroll_pane,
                                      "Help - Security Headers Analyzer",
                                      JOptionPane.INFORMATION_MESSAGE)

    def _get_help_content(self):
        """
        Returns the HTML-formatted help content string.
        """
        return """
        <html>
        <body style='font-family: sans-serif; padding: 10px;'>
            <h2>Security Headers Analyzer v{version}</h2>
            <p>This extension analyzes HTTP security headers for web applications.</p>

            <h3>Workflow</h3>
            <ol>
                <li><b>Browse Target:</b> Navigate the target application with your browser to populate the extension with HTTP traffic.</li>
                <li><b>Set Context:</b> Configure the 'Application Context' panel to match the target application's environment. This adjusts the scoring.</li>
                <li><b>Evaluate:</b> Click the 'Evaluate' button to perform the analysis on the captured, relevant URLs.</li>
                <li><b>Review Results:</b> Examine the per-URL results in the table and the 'Overall Summary' score and risk.</li>
                <li><b>Export:</b> Use the 'Export' button to save the findings to a CSV or JSON file.</li>
            </ol>

            <h3>UI Components</h3>
            <h4>Target & Controls</h4>
            <ul>
                <li><b>In-scope host dropdown:</b> Filters evaluation to a specific host or all in-scope hosts.</li>
                <li><b>Auto-detect meaningful URLs:</b> (Default: ON) Intelligently filters out irrelevant requests like images and CSS, focusing on pages and API calls.</li>
                <li><b>Show excluded URLs (debug):</b> For debugging the relevance engine.</li>
            </ul>

            <h4>Application Context</h4>
            <ul>
                <li><b>Exposure:</b> 'External' for internet-facing apps (stricter scoring), 'Internal' for intranet apps.</li>
                <li><b>Authentication:</b> 'SSO' for single sign-on (stricter scoring on session headers), 'Public', or 'NA'.</li>
                <li><b>Application Profile:</b> Adjusts the weight/importance of each security header based on the app type (e.g., a web app vs. an API).</li>
            </ul>

            <h4>Results Table & Summary</h4>
            <ul>
                <li><b>Score:</b> A 0-100 score for each URL and for the application overall. Higher is better.</li>
                <li><b>Risk:</b> A classification (Low, Medium, High) based on the score.</li>
                <li><b>Header Columns:</b> Shows the status of each analyzed security header.</li>
            </ul>

            <h3>Scoring Calculation</h3>
            <p>The scoring engine is designed to be flexible and context-aware.</p>
            <ul>
                <li><b>Base Score:</b> Each security header is assigned a weight based on the selected <b>Application Profile</b>. For example, Content-Security-Policy is more critical for a 'Default Web Application' than for a backend 'API Endpoint'. The base score for a URL is calculated by summing the weights of all correctly implemented headers.</li>
                <li><b>Context Multipliers:</b> The score is then adjusted based on the application's context:
                    <ul>
                        <li><b>Exposure ('External'):</b> Applications exposed to the internet are considered higher risk, so the score is slightly reduced to reflect this.</li>
                        <li><b>Authentication ('SSO'):</b> An application handling Single Sign-On is more sensitive, so the score is also slightly reduced to emphasize the need for stricter controls.</li>
                    </ul>
                </li>
                <li><b>Overall Score:</b> The 'Overall Score' in the summary panel is not a simple average. It's a <b>weighted average</b> of all the URLs in the results table. URLs are weighted by their individual risk:
                    <ul>
                        <li><b>High</b> risk URLs have a higher weight (1.5x).</li>
                        <li><b>Medium</b> risk URLs have a standard weight (1.0x).</li>
                        <li><b>Low</b> risk URLs have a lower weight (0.5x).</li>
                    </ul>
                    This means that fixing a single 'High' risk URL will improve the overall score more than fixing a single 'Low' risk URL.
                </li>
            </ul>

            <h3>Right-Click Menu</h3>
            <p>Right-click on a row in the results table to:</p>
            <ul>
                <li>Send the request to Repeater or Intruder.</li>
                <li>Copy the URL.</li>
                <li>Copy the row's results as a JSON object.</li>
            </ul>
        </body>
        </html>
        """.format(version=VERSION)

    #
    # Core Logic
    #
    def _get_relevance_score(self, messageInfo):
        """
        Calculates a relevance score for a given HTTP request/response.
        """
        request_info = self._helpers.analyzeRequest(messageInfo)
        response_info = self._helpers.analyzeResponse(messageInfo.getResponse())
        url = request_info.getUrl()
        score = 0
        reasons = []

        # Penalize static resources heavily
        if any(str(url).lower().endswith(ext) for ext in STATIC_EXTENSIONS):
            return 0, ["Static file extension"]
        
        # Check content type
        content_type = response_info.getInferredMimeType()
        if any(t in content_type for t in ["image", "font", "css", "javascript"]):
             score -= 20
             reasons.append("Static content-type: " + content_type)
        elif any(t in content_type for t in ["html", "json", "xml", "text"]):
             score += 30
             reasons.append("Dynamic content-type: " + content_type)

        # Check status code
        if response_info.getStatusCode() == 200:
            score += 20
        elif str(response_info.getStatusCode()).startswith("3"):
            score -= 10 # Redirects are less interesting
        
        # Check for cookies
        if self._helpers.analyzeResponse(messageInfo.getResponse()).getCookies():
            score += 20
            reasons.append("Contains Set-Cookie header")

        # Keyword detection in URL/body (simple version)
        response_body = self._helpers.bytesToString(messageInfo.getResponse()[response_info.getBodyOffset():])
        keywords = ["login", "session", "user", "admin", "token", "jwt", "account", "profile"]
        for keyword in keywords:
            if keyword in str(url).lower() or keyword in response_body.lower():
                score += 15
                reasons.append("Found keyword: " + keyword)
                break
        
        return max(0, score), reasons

    def _analyze_single_request(self, messageInfo, app_context):
        """
        Analyzes security headers for a single request/response.
        """
        response_bytes = messageInfo.getResponse()
        response_info = self._helpers.analyzeResponse(response_bytes)
        headers = response_info.getHeaders()
        
        header_map = defaultdict(list)
        for header in headers:
            if ":" in header:
                name, value = header.split(":", 1)
                header_map[name.strip().lower()].append(value.strip())

        result = {
            "URL": self._helpers.analyzeRequest(messageInfo).getUrl(),
            "messageInfo": messageInfo,
            "headers": {}
        }
        
        # Header analysis
        result["headers"]["Strict-Transport-Security"] = "Present" if "strict-transport-security" in header_map else "Missing"
        result["headers"]["Content-Security-Policy"] = self._check_csp(header_map.get("content-security-policy", []))
        result["headers"]["X-Frame-Options"] = "Present" if "x-frame-options" in header_map else "Missing"
        result["headers"]["X-Content-Type-Options"] = "nosniff" if "nosniff" in "".join(header_map.get("x-content-type-options", [])) else "Missing/Invalid"
        result["headers"]["Referrer-Policy"] = "Present" if "referrer-policy" in header_map else "Missing"
        result["headers"]["Permissions-Policy"] = "Present" if "permissions-policy" in header_map else "Missing"
        
        # Cache control
        cache_headers = header_map.get("cache-control", [])
        if any(val in "".join(cache_headers) for val in ["no-store", "no-cache"]):
             result["headers"]["Cache-Control"] = "Secure"
        else:
             result["headers"]["Cache-Control"] = "Insecure"
             
        # Cookie flags
        cookie_headers = header_map.get("set-cookie", [])
        result["headers"]["Set-Cookie-Secure"] = self._check_cookie_flag(cookie_headers, "Secure")
        result["headers"]["Set-Cookie-HttpOnly"] = self._check_cookie_flag(cookie_headers, "HttpOnly")
        result["headers"]["Set-Cookie-SameSite"] = self._check_cookie_flag(cookie_headers, "SameSite")

        # Scoring
        score = self._calculate_url_score(result["headers"], app_context)
        result["Score"] = score
        result["Risk"] = self._classify_risk(score)

        return result
    
    def _check_csp(self, csp_headers):
        if not csp_headers: return "Missing"
        csp = " ".join(csp_headers)
        if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp or "*" in csp:
            return "Weak"
        return "Strong"
        
    def _check_cookie_flag(self, cookie_headers, flag):
        if not cookie_headers: return "N/A"
        
        all_cookies_good = True
        for cookie in cookie_headers:
            if flag.lower() not in cookie.lower():
                all_cookies_good = False
                break
        return "Good" if all_cookies_good else "Missing"

    def _calculate_url_score(self, header_results, app_context):
        """
        Calculates the security score for a URL based on its headers and the application context.
        """
        profile = PROFILES.get(app_context["profile"], PROFILES["Default Web Application"])
        max_score = sum(profile.values())
        achieved_score = 0
        
        for header, status in header_results.items():
            if status in ["Present", "Strong", "Secure", "Good", "nosniff"]:
                achieved_score += profile.get(header, 0)
        
        base_score_percent = (float(achieved_score) / max_score) * 100 if max_score > 0 else 100
        
        # Apply multipliers
        if app_context["exposure"] == "External":
            base_score_percent *= 0.9 # External apps are riskier
        if app_context["auth"] == "SSO":
            base_score_percent *= 0.95 # SSO context is more sensitive
            
        return int(base_score_percent)

    def _calculate_overall_score(self):
        """
        Calculates the weighted average score for the entire application and updates summary UI.
        """
        if not self._analyzed_results:
            self._overall_score_label.setText("N/A")
            self._overall_risk_label.setText("N/A")
            self._overall_risk_label.setForeground(Color.BLACK)
            return

        total_weighted_score = 0
        total_weight = 0
        
        risk_weights = {"High": 1.5, "Medium": 1.0, "Low": 0.5}

        for result in self._analyzed_results:
            risk = result.get("Risk")
            score = result.get("Score")
            weight = risk_weights.get(risk, 1.0)
            
            total_weighted_score += score * weight
            total_weight += weight
            
        overall_score = int(total_weighted_score / total_weight) if total_weight > 0 else 0
        overall_risk = self._classify_overall_risk(overall_score)

        self._overall_score_label.setText(str(overall_score))
        self._overall_risk_label.setText(overall_risk)
        
        # Set color for the risk label
        if overall_risk == "High":
            self._overall_risk_label.setForeground(Color.RED)
        elif overall_risk == "Medium":
            self._overall_risk_label.setForeground(Color.ORANGE)
        else: # Low
            self._overall_risk_label.setForeground(Color(0, 128, 0)) # Dark Green
        
    def _classify_risk(self, score):
        if score >= 85: return "Low"
        if score >= 60: return "Medium"
        return "High"
    
    def _classify_overall_risk(self, score):
        if score >= 90: return "Low"
        if score >= 70: return "Medium"
        return "High"

    #
    # Helper & Utility Functions
    #
    def _create_titled_border(self, title):
        from javax.swing import BorderFactory
        return BorderFactory.createTitledBorder(title)
        
    def _copy_to_clipboard(self, text):
        from java.awt.datatransfer import StringSelection
        from java.awt import Toolkit
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(StringSelection(text), None)

    def _export_as_csv(self, file_path):
        import csv
        with open(file_path, 'wb') as f:
            writer = csv.writer(f)
            
            # Write summary
            writer.writerow(["Overall Score", self._overall_score_label.getText().split(": ")[1]])
            writer.writerow(["Overall Risk", self._overall_risk_label.getText().split(": ")[1]])
            writer.writerow([]) # Spacer
            
            # Write headers
            headers = self._table_model.get_column_names()
            writer.writerow(headers)
            
            # Write data
            for result in self._analyzed_results:
                row = [result.get("URL"), result.get("Score"), result.get("Risk")]
                for h in SECURITY_HEADERS:
                    row.append(result.get("headers", {}).get(h, "N/A"))
                writer.writerow(row)
        print "Exported to CSV: " + file_path

    def _export_as_json(self, file_path):
        summary = {
            "overallScore": self._overall_score_label.getText().split(": ")[1],
            "overallRisk": self._overall_risk_label.getText().split(": ")[1],
            "applicationContext": {
                "exposure": self._exposure_dropdown.getSelectedItem(),
                "auth": self._auth_dropdown.getSelectedItem(),
                "profile": self._profile_dropdown.getSelectedItem()
            }
        }
        
        results_list = []
        for result in self._analyzed_results:
            results_list.append(self._json_default(result))

        export_data = {"summary": summary, "results": results_list}

        with open(file_path, 'w') as f:
            json.dump(export_data, f, indent=4, default=self._json_default)
        print "Exported to JSON: " + file_path

    def _json_default(self, o):
        if isinstance(o, IHttpRequestResponse):
            return {"url": str(self._helpers.analyzeRequest(o).getUrl()), "details": "IHttpRequestResponse object not serialized"}
        if isinstance(o, unicode):
            return str(o)
        if hasattr(o, '__dict__'):
            return o.__dict__
        return str(o)

class TableMouseListener(MouseAdapter):
    def __init__(self, extender):
        self._extender = extender

    def mousePressed(self, e):
        self._show_popup(e)

    def mouseReleased(self, e):
        self._show_popup(e)

    def _show_popup(self, e):
        if e.isPopupTrigger():
            table = e.getComponent()
            point = e.getPoint()
            row = table.rowAtPoint(point)
            if row >= 0:
                # Select the row that was right-clicked before showing the menu
                table.setRowSelectionInterval(row, row)
                # Build and show the popup menu
                popup = self._build_popup_menu(row)
                popup.show(e.getComponent(), e.getX(), e.getY())

    def _build_popup_menu(self, row_index):
        ext = self._extender
        popup = JPopupMenu()
        
        selected_result = ext._analyzed_results[ext._results_table.convertRowIndexToModel(row_index)]

        send_to_repeater = JMenuItem("Send to Repeater")
        send_to_repeater.addActionListener(lambda e, r=selected_result: ext._callbacks.sendToRepeater(r.get("messageInfo").getHttpService().getHost(), r.get("messageInfo").getHttpService().getPort(), r.get("messageInfo").getHttpService().getProtocol() == "https", r.get("messageInfo").getRequest(), "Header Analysis"))
        
        send_to_intruder = JMenuItem("Send to Intruder")
        send_to_intruder.addActionListener(lambda e, r=selected_result: ext._callbacks.sendToIntruder(r.get("messageInfo").getHttpService().getHost(), r.get("messageInfo").getHttpService().getPort(), r.get("messageInfo").getHttpService().getProtocol() == "https", r.get("messageInfo").getRequest()))

        copy_url = JMenuItem("Copy URL")
        copy_url.addActionListener(lambda e, r=selected_result: ext._copy_to_clipboard(str(r.get("URL"))))

        copy_json = JMenuItem("Copy result as JSON")
        copy_json.addActionListener(lambda e, r=selected_result: ext._copy_to_clipboard(json.dumps(r, indent=2, default=ext._json_default)))

        popup.add(send_to_repeater)
        popup.add(send_to_intruder)
        popup.add(JMenuItem("---")) # Separator
        popup.add(copy_url)
        popup.add(copy_json)
        
        return popup

class RiskAndHeaderCellRenderer(DefaultTableCellRenderer):
    """
    Custom cell renderer to apply colors based on risk and header status.
    """
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        # Get the default component from the parent class
        c = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column)

        # If the cell is not selected, apply our custom foreground color
        if not isSelected:
            val_str = str(value).strip()
            if val_str in ("High", "Missing", "Weak", "Insecure", "Missing/Invalid"):
                c.setForeground(Color.RED)
            elif val_str == "Medium":
                c.setForeground(Color.ORANGE)
            elif val_str in ("Low", "Present", "Strong", "Secure", "Good", "nosniff"):
                c.setForeground(Color(0, 128, 0)) # Dark Green
            elif val_str == "N/A":
                c.setForeground(Color.GRAY)
            else:
                # Reset to default foreground color for all other values
                c.setForeground(table.getForeground())
        
        return c

class ResultsTableModel(AbstractTableModel):
    """
    Custom TableModel for the results table.
    """
    def __init__(self, data):
        self._data = data
        self._column_names = ["URL", "Score", "Risk"] + SECURITY_HEADERS

    def get_column_names(self):
        return self._column_names
        
    def getRowCount(self):
        return len(self._data)

    def getColumnCount(self):
        return len(self._column_names)

    def getColumnName(self, col):
        return self._column_names[col]

    def getValueAt(self, row, col):
        result = self._data[row]
        col_name = self._column_names[col]
        
        if col_name == "URL":
            return str(result.get("URL"))
        if col_name == "Score":
            return result.get("Score")
        if col_name == "Risk":
            return result.get("Risk")
        
        # Header columns
        return result.get("headers", {}).get(col_name, "N/A")

# Self-test for running in Jython standalone for quick syntax checks
if __name__ == '__main__':
    print "This script is intended to be loaded as a Burp Suite extension."
    print "Running basic syntax check..."
    # You can add basic non-Burp-dependent function calls here for testing
    print "Syntax check passed."

