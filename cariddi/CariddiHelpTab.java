package burp;

import javax.swing.*;
import java.awt.*;

/**
 * Help tab with comprehensive documentation
 */
public class CariddiHelpTab {
    private JPanel mainPanel;

    public CariddiHelpTab() {
        initializePanel();
    }

    private void initializePanel() {
        mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JTabbedPane helpTabs = new JTabbedPane();

        // Overview tab
        helpTabs.addTab("Overview", createOverviewPanel());

        // Features tab
        helpTabs.addTab("Features", createFeaturesPanel());

        // Usage tab
        helpTabs.addTab("Usage Guide", createUsagePanel());

        // Examples tab
        helpTabs.addTab("Test Cases", createExamplesPanel());

        // Settings tab
        helpTabs.addTab("Settings", createSettingsPanel());

        mainPanel.add(helpTabs, BorderLayout.CENTER);
    }

    private JPanel createOverviewPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        String content = "CARIDDI - Burp Suite Extension\n" +
                "\n" +
                "Overview:\n" +
                "Cariddi is a comprehensive endpoint discovery and secrets scanning tool integrated with Burp Suite.\n" +
                "It automatically crawls URLs and scans for:\n" +
                "  • API Endpoints\n" +
                "  • Sensitive Information (Secrets, API Keys, Tokens)\n" +
                "  • Error/Exception Disclosures\n" +
                "  • Information Leaks (Email, IP Addresses)\n" +
                "  • File Extensions and Configurations\n" +
                "\n" +
                "Purpose:\n" +
                "This extension helps penetration testers and security professionals to:\n" +
                "  • Discover hidden APIs and endpoints\n" +
                "  • Identify exposed credentials and secrets\n" +
                "  • Find configuration files and backups\n" +
                "  • Uncover information disclosure vulnerabilities\n" +
                "  • Speed up reconnaissance phase of security assessments\n" +
                "\n" +
                "Version: 1.0.0\n" +
                "Author: Security Team\n" +
                "License: GPL-3.0\n";

        JTextArea textArea = new JTextArea(content);
        textArea.setEditable(false);
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        textArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        textArea.setBackground(new Color(240, 240, 240));

        JScrollPane scrollPane = new JScrollPane(textArea);
        panel.add(scrollPane);
        return panel;
    }

    private JPanel createFeaturesPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        String content = "KEY FEATURES\n" +
                "\n" +
                "1. ENDPOINT DISCOVERY\n" +
                "   • Crawls URLs and discovers API endpoints\n" +
                "   • Tests common API paths (/api, /v1, /admin, etc.)\n" +
                "   • Identifies REST, GraphQL, and SOAP endpoints\n" +
                "   • Supports intensive mode for subdomain scanning\n" +
                "\n" +
                "2. SECRETS DETECTION\n" +
                "   • AWS Access Keys and Secret Keys\n" +
                "   • JWT Tokens\n" +
                "   • API Keys and Credentials\n" +
                "   • Slack/Discord/GitHub Tokens\n" +
                "   • Stripe API Keys\n" +
                "   • Database Connection Strings\n" +
                "   • Private Keys (.pem, .key files)\n" +
                "\n" +
                "3. ERROR DETECTION\n" +
                "   • Java Stack Traces\n" +
                "   • Python Tracebacks\n" +
                "   • JavaScript Errors\n" +
                "   • SQL Errors\n" +
                "   • Exception Disclosures\n" +
                "\n" +
                "4. INFORMATION GATHERING\n" +
                "   • Email Address Discovery\n" +
                "   • IP Address Extraction\n" +
                "   • Metadata Extraction\n" +
                "   • Server Information Disclosure\n" +
                "\n" +
                "5. ADVANCED FEATURES\n" +
                "   • Configurable Concurrency Level\n" +
                "   • Custom Headers Support\n" +
                "   • User Agent Randomization\n" +
                "   • Timeout Configuration\n" +
                "   • Crawl Depth Control\n" +
                "   • Export Results (JSON, CSV, XML, TXT)\n" +
                "   • Resizable UI Components\n" +
                "   • Real-time Progress Tracking\n";

        JTextArea textArea = new JTextArea(content);
        textArea.setEditable(false);
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        textArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        textArea.setBackground(new Color(240, 240, 240));

        JScrollPane scrollPane = new JScrollPane(textArea);
        panel.add(scrollPane);
        return panel;
    }

    private JPanel createUsagePanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        String content = "USAGE GUIDE\n" +
                "\n" +
                "STEP 1: INPUT URLS\n" +
                "   1. Go to the 'Scanner' tab\n" +
                "   2. Enter target URLs in the 'Target URLs' text area\n" +
                "   3. Enter one URL per line\n" +
                "   4. Examples:\n" +
                "      https://example.com\n" +
                "      https://api.example.com\n" +
                "      https://internal.example.com\n" +
                "\n" +
                "STEP 2: CONFIGURE SCANNING\n" +
                "   1. Go to the 'Settings' tab\n" +
                "   2. Select which findings to hunt for:\n" +
                "      ✓ Hunt for Endpoints (find API paths)\n" +
                "      ✓ Hunt for Secrets (find exposed credentials)\n" +
                "      □ Hunt for Errors (find error disclosures)\n" +
                "      □ Hunt for Info (find information leaks)\n" +
                "   3. Configure performance settings:\n" +
                "      • Concurrency Level: 20-200 (higher = faster but more load)\n" +
                "      • Timeout: 5-30 seconds per request\n" +
                "      • Max Crawl Depth: 1-10 levels\n" +
                "   4. (Optional) Add custom headers or user agent\n" +
                "\n" +
                "STEP 3: START SCAN\n" +
                "   1. Return to 'Scanner' tab\n" +
                "   2. Click 'Start Scan' button\n" +
                "   3. Monitor progress with the progress bar\n" +
                "   4. Results appear in real-time in 'Results' tab\n" +
                "\n" +
                "STEP 4: REVIEW RESULTS\n" +
                "   1. Go to 'Results' tab\n" +
                "   2. Browse discovered findings\n" +
                "   3. Color coding:\n" +
                "      - Red: Secrets (High Priority)\n" +
                "      - Blue: Endpoints\n" +
                "      - Yellow: Errors\n" +
                "      - Green: Info\n" +
                "   4. Click on rows to view details\n" +
                "\n" +
                "STEP 5: EXPORT RESULTS\n" +
                "   1. Select rows you want to export (optional)\n" +
                "   2. Click export format button:\n" +
                "      • JSON: For programmatic processing\n" +
                "      • CSV: For spreadsheet analysis\n" +
                "      • XML: For enterprise tools\n" +
                "      • TXT: For simple reports\n" +
                "   3. Choose file location and save\n";

        JTextArea textArea = new JTextArea(content);
        textArea.setEditable(false);
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        textArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        textArea.setBackground(new Color(240, 240, 240));

        JScrollPane scrollPane = new JScrollPane(textArea);
        panel.add(scrollPane);
        return panel;
    }

    private JPanel createExamplesPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        String content = "TEST CASES & EXAMPLES\n" +
                "\n" +
                "SCENARIO 1: Basic API Endpoint Discovery\n" +
                "Target: https://api.example.com\n" +
                "Settings:\n" +
                "  • Hunt for Endpoints: ON\n" +
                "  • Hunt for Secrets: ON\n" +
                "  • Concurrency: 50\n" +
                "Expected Results:\n" +
                "  • /api/users\n" +
                "  • /api/auth/login\n" +
                "  • /api/v1/products\n" +
                "  • /graphql\n" +
                "  • /swagger\n" +
                "\n" +
                "SCENARIO 2: Secrets & Credential Discovery\n" +
                "Target: https://github.com/someuser/somerepo\n" +
                "Settings:\n" +
                "  • Hunt for Secrets: ON\n" +
                "  • Hunt for Info: ON\n" +
                "  • Custom Timeout: 15 seconds\n" +
                "Expected Results:\n" +
                "  • API Keys in source code\n" +
                "  • Database connection strings\n" +
                "  • OAuth tokens\n" +
                "  • Email addresses\n" +
                "\n" +
                "SCENARIO 3: Error Disclosure Testing\n" +
                "Target: https://vulnerable.example.com\n" +
                "Settings:\n" +
                "  • Hunt for Errors: ON\n" +
                "  • Hunt for Info: ON\n" +
                "  • Max Crawl Depth: 5\n" +
                "Expected Results:\n" +
                "  • Stack traces revealing framework\n" +
                "  • Database error messages\n" +
                "  • Server information\n" +
                "\n" +
                "SCENARIO 4: Intensive Subdomain Scan\n" +
                "Target: https://example.com\n" +
                "Settings:\n" +
                "  • Intensive Mode: ON\n" +
                "  • Hunt for Endpoints: ON\n" +
                "  • Concurrency: 100\n" +
                "Expected Results:\n" +
                "  • All subdomains matching *.example.com\n" +
                "  • Endpoints across subdomains\n" +
                "  • Hidden services\n" +
                "\n" +
                "TIPS FOR BEST RESULTS:\n" +
                "  1. Start with standard settings, increase concurrency if needed\n" +
                "  2. Use custom headers if target requires authentication\n" +
                "  3. Increase timeout for slow servers\n" +
                "  4. Run multiple scans with different settings\n" +
                "  5. Combine with other security tools for complete assessment\n" +
                "  6. Review false positives carefully\n";

        JTextArea textArea = new JTextArea(content);
        textArea.setEditable(false);
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        textArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        textArea.setBackground(new Color(240, 240, 240));

        JScrollPane scrollPane = new JScrollPane(textArea);
        panel.add(scrollPane);
        return panel;
    }

    private JPanel createSettingsPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        String content = "SETTINGS REFERENCE\n" +
                "\n" +
                "SCAN OPTIONS:\n" +
                "\n" +
                "  Hunt for Endpoints\n" +
                "    Default: ON\n" +
                "    Purpose: Discovers API paths and endpoints\n" +
                "    Impact: Medium performance impact\n" +
                "\n" +
                "  Hunt for Secrets\n" +
                "    Default: ON\n" +
                "    Purpose: Detects exposed credentials, keys, tokens\n" +
                "    Impact: Low-Medium performance impact\n" +
                "\n" +
                "  Hunt for Errors\n" +
                "    Default: OFF\n" +
                "    Purpose: Finds error messages and stack traces\n" +
                "    Impact: Low performance impact\n" +
                "\n" +
                "  Hunt for Info\n" +
                "    Default: OFF\n" +
                "    Purpose: Discovers emails, IPs, and metadata\n" +
                "    Impact: Low performance impact\n" +
                "\n" +
                "PERFORMANCE SETTINGS:\n" +
                "\n" +
                "  Concurrency Level (Default: 20)\n" +
                "    Min: 1, Max: 200\n" +
                "    Higher values = faster scanning but more server load\n" +
                "    Recommended: 20-50 for public targets, 10-20 for private\n" +
                "\n" +
                "  Timeout (Default: 10 seconds)\n" +
                "    Min: 1s, Max: 60s\n" +
                "    Time to wait for each request\n" +
                "    Increase for slow/remote servers\n" +
                "\n" +
                "  Max Crawl Depth (Default: 3)\n" +
                "    Min: 1, Max: 10\n" +
                "    How deep to follow links from initial URL\n" +
                "    Higher = more comprehensive but slower\n" +
                "\n" +
                "CUSTOM HEADERS & USER AGENT:\n" +
                "\n" +
                "  Custom Headers Format:\n" +
                "    Cookie: session=value;; Authorization: Bearer token\n" +
                "    Use ;; to separate multiple headers\n" +
                "\n" +
                "  User Agent:\n" +
                "    Can be set to custom value or leave default\n" +
                "    Used to avoid detection or mimic specific browsers\n";

        JTextArea textArea = new JTextArea(content);
        textArea.setEditable(false);
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        textArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        textArea.setBackground(new Color(240, 240, 240));

        JScrollPane scrollPane = new JScrollPane(textArea);
        panel.add(scrollPane);
        return panel;
    }

    public JPanel getPanel() {
        return mainPanel;
    }
}
