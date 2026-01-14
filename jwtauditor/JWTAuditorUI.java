package burp.jwt;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import burp.IMessageEditorTabFactory;
import burp.IMessageEditorController;
import burp.IContextMenuFactory;

import javax.swing.*;
import javax.swing.table.*;
import java.awt.*;
import java.awt.event.*;
import java.awt.datatransfer.*;
import java.util.Arrays;
import java.util.List;
import java.util.ArrayList;

/**
 * Main JWT Auditor UI Panel for Burp Suite
 * Provides tabbed interface for all JWT operations
 */
public class JWTAuditorUI implements ITab {
    
    private IBurpExtenderCallbacks callbacks;
    private JPanel mainPanel;
    private JTabbedPane tabbedPane;
    private JWTToken currentToken;
    
    // Decoder tab components
    private JTextArea decoderHeaderOutput;
    private JTextArea decoderPayloadOutput;
    private JTextArea decoderSignatureOutput;
    private JTextArea decoderInfoOutput;
    
    // Bruteforcer state
    private volatile boolean bruteforceStopped = false;
    private SecretBruteforcer activeBruteforcer;
    
    public JWTAuditorUI(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.mainPanel = new JPanel(new BorderLayout(10, 10));
        this.mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Create tabbed interface
        this.tabbedPane = new JTabbedPane();
        
        tabbedPane.addTab("Decoder", createDecoderTab());
        tabbedPane.addTab("Analyzer", createAnalyzerTab());
        tabbedPane.addTab("Bruteforcer", createBruteforceTab());
        tabbedPane.addTab("Attacks", createAttackTab());
        tabbedPane.addTab("Editor", createEditorTab());
        tabbedPane.addTab("Help & Info", createHelpTab());
        
        mainPanel.add(tabbedPane, BorderLayout.CENTER);
    }
    
    /**
     * Create Help & Info Tab - For normal users
     */
    private JPanel createHelpTab() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBackground(new Color(240, 245, 250));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        JEditorPane helpText = new JEditorPane();
        helpText.setEditable(false);
        helpText.setContentType("text/plain");
        helpText.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        helpText.setBackground(new Color(255, 255, 255));
        helpText.setMargin(new Insets(10, 10, 10, 10));
        helpText.setText(
            "╔════════════════════════════════════════════════════════════════════════════════╗\n" +
            "║                      JWT AUDITOR - COMPREHENSIVE GUIDE                         ║\n" +
            "║                      Professional JWT Security Testing Tool                    ║\n" +
            "╚════════════════════════════════════════════════════════════════════════════════╝\n\n" +
            
            "═══════════════════════════════════════════════════════════════════════════════\n" +
            "1. WHAT IS JWT (JSON Web Token)?\n" +
            "═══════════════════════════════════════════════════════════════════════════════\n" +
            "JWT is a compact token used for authentication & authorization. It has 3 parts:\n\n" +
            "  • HEADER: Contains algorithm & type info\n" +
            "  • PAYLOAD: Contains user claims & data\n" +
            "  • SIGNATURE: Ensures token hasn't been tampered with\n\n" +
            "Example: eyJhbGci[HEADER].eyJzdWIi[PAYLOAD].SflKxw[SIGNATURE]\n\n" +
            
            "═══════════════════════════════════════════════════════════════════════════════\n" +
            "2. DECODER TAB - Parse & View JWT Structure\n" +
            "═══════════════════════════════════════════════════════════════════════════════\n" +
            "📋 How to use:\n" +
            "  1. Paste a JWT token in the input field\n" +
            "  2. Click 'Decode' button\n" +
            "  3. View three sections:\n" +
            "     • HEADER: Algorithm & type\n" +
            "     • PAYLOAD: User data & claims\n" +
            "     • SIGNATURE: Token signature\n" +
            "     • INFO: Expiration, issuance time, etc.\n\n" +
            
            "👁️ What to look for:\n" +
            "  ✓ Algorithm type (HS256, RS256, 'none', etc.)\n" +
            "  ✓ Expiration date (exp claim)\n" +
            "  ✓ User data and sensitive information\n" +
            "  ✓ Issuer (iss) and audience (aud) fields\n\n" +
            
            "═══════════════════════════════════════════════════════════════════════════════\n" +
            "3. ANALYZER TAB - Find Security Issues (15+ Checks)\n" +
            "═══════════════════════════════════════════════════════════════════════════════\n" +
            "🔴 CRITICAL Issues (Immediate exploitation possible):\n" +
            "  • 'none' algorithm - Signature bypass by changing alg to 'none'\n" +
            "  • Missing expiration - Token never expires\n" +
            "  • Dynamic JKU/X5U - Server Side Request Forgery (SSRF) risk\n" +
            "  • KID injection - SQL injection via key ID parameter\n\n" +
            
            "🟠 HIGH Risk Issues (Likely exploitable):\n" +
            "  • Weak HMAC algorithm - Secret can be brute forced\n" +
            "  • Sensitive data exposure - Contains PII, emails, API keys\n" +
            "  • Long expiration - Valid token for extended period\n" +
            "  • Weak secret vulnerability - Common words in secret\n\n" +
            
            "🟡 MEDIUM Risk Issues (Potentially exploitable):\n" +
            "  • Missing claims - Should have iss, aud, jti, exp\n" +
            "  • Timestamp validation - Invalid iat/nbf/exp values\n" +
            "  • Replay attack - No unique identifiers\n" +
            "  • Algorithm confusion - Can switch between algorithms\n\n" +
            
            "═══════════════════════════════════════════════════════════════════════════════\n" +
            "4. BRUTEFORCER TAB - Crack Weak Secrets\n" +
            "═══════════════════════════════════════════════════════════════════════════════\n" +
            "🔓 How it works:\n" +
            "  1. Token must use HMAC algorithm (HS256, HS384, HS512)\n" +
            "  2. Tests 1000+ common secrets/passwords\n" +
            "  3. Verifies each secret against token signature\n" +
            "  4. If match found: YOU CAN FORGE NEW TOKENS!\n\n" +
            
            "💻 Common secrets tested:\n" +
            "  • Passwords: password, admin, secret, test123\n" +
            "  • Service names: jwt-secret, api-secret, app-secret\n" +
            "  • Dates: 2024, 2025, january, december\n" +
            "  • Common patterns: 123456, password123, admin123\n\n" +
            
            "✅ If secret is found:\n" +
            "  You can now forge ANY valid JWT token for this application!\n" +
            "  Can impersonate any user or escalate privileges.\n\n" +
            
            "═══════════════════════════════════════════════════════════════════════════════\n" +
            "5. ATTACKS TAB - Generate Exploitation Payloads\n" +
            "═══════════════════════════════════════════════════════════════════════════════\n" +
            
            "🎯 Attack 1: NONE ALGORITHM BYPASS\n" +
            "  • Changes algorithm from RS256/HS256 to 'none'\n" +
            "  • Signature validation is skipped\n" +
            "  • Can edit claims freely\n" +
            "  • Works if app accepts 'none' algorithm\n\n" +
            
            "🎯 Attack 2: ALGORITHM CONFUSION (14+ variants)\n" +
            "  • Tries switching algorithms: RS256→HS256, ES256→HS256\n" +
            "  • Server may incorrectly validate signature\n" +
            "  • Can forge tokens if confusion exists\n\n" +
            
            "🎯 Attack 3: KID INJECTION (47+ payloads)\n" +
            "  • Exploits the 'kid' (Key ID) parameter\n" +
            "  • Tests: SQL injection, path traversal, command injection\n" +
            "  • Example: kid: \"../../etc/passwd\"\n" +
            "  • Server may retrieve wrong key for verification\n\n" +
            
            "🎯 Attack 4: JKU/X5U MANIPULATION\n" +
            "  • Changes JWKS URL to attacker-controlled server\n" +
            "  • Server fetches public key from YOUR server\n" +
            "  • You sign tokens with your private key\n" +
            "  • Server accepts tokens as valid\n\n" +
            
            "🎯 Attack 5: JWK INJECTION\n" +
            "  • Adds public key directly in JWT header\n" +
            "  • Server uses your public key to verify\n" +
            "  • You sign with your private key\n\n" +
            
            "🎯 Attack 6: PRIVILEGE ESCALATION\n" +
            "  • Modifies user role: \"user\" → \"admin\"\n" +
            "  • Adds is_admin: true flag\n" +
            "  • Changes permission levels\n" +
            "  • Works if server doesn't validate claims\n\n" +
            
            "═══════════════════════════════════════════════════════════════════════════════\n" +
            "6. EDITOR TAB - Manually Modify Tokens\n" +
            "═══════════════════════════════════════════════════════════════════════════════\n" +
            "✏️ Customize attacks:\n" +
            "  1. Edit header (algorithm, kid, jku, etc.)\n" +
            "  2. Edit payload (user_id, role, permissions, etc.)\n" +
            "  3. Select signature algorithm\n" +
            "  4. Specify secret key (for HMAC)\n" +
            "  5. Generate new token\n\n" +
            
            "═══════════════════════════════════════════════════════════════════════════════\n" +
            "7. PENETRATION TESTING WORKFLOW\n" +
            "═══════════════════════════════════════════════════════════════════════════════\n" +
            "📊 Step-by-step approach:\n\n" +
            "  STEP 1: GATHER TOKENS\n" +
            "    □ Login to application\n" +
            "    □ Intercept requests in Burp Proxy\n" +
            "    □ Find JWT tokens in Authorization headers\n\n" +
            
            "  STEP 2: ANALYZE\n" +
            "    □ Paste token in Decoder tab\n" +
            "    □ Review header, payload, signature\n" +
            "    □ Go to Analyzer tab\n" +
            "    □ Click 'Analyze Current Token'\n" +
            "    □ Note all CRITICAL and HIGH findings\n\n" +
            
            "  STEP 3: TEST CRITICAL ISSUES\n" +
            "    □ For 'none' algorithm: Use None Algorithm Bypass attack\n" +
            "    □ For weak secret: Use Bruteforcer tab\n" +
            "    □ For algorithm confusion: Try Algorithm Confusion attacks\n" +
            "    □ Copy generated token to Repeater\n" +
            "    □ Test against application\n" +
            "    □ Observe if token is accepted\n\n" +
            
            "  STEP 4: TEST PRIVILEGE ESCALATION\n" +
            "    □ Use Privilege Escalation attack\n" +
            "    □ Change user_id to admin account\n" +
            "    □ Set is_admin or role to 'admin'\n" +
            "    □ If brute force succeeded, use cracked secret\n" +
            "    □ Send to application\n" +
            "    □ Try accessing admin functions\n\n" +
            
            "  STEP 5: DOCUMENT FINDINGS\n" +
            "    □ Note all successful attacks\n" +
            "    □ Include affected token versions\n" +
            "    □ Document impact (data access, privilege escalation)\n" +
            "    □ Suggest remediation\n\n" +
            
            "═══════════════════════════════════════════════════════════════════════════════\n" +
            "8. COMMON JWT VULNERABILITIES & FIXES\n" +
            "═══════════════════════════════════════════════════════════════════════════════\n" +
            
            "❌ VULNERABILITY: 'none' algorithm accepted\n" +
            "   ✅ FIX: Only accept RS256, HS256, ES256 (no 'none')\n\n" +
            
            "❌ VULNERABILITY: No expiration (exp claim missing)\n" +
            "   ✅ FIX: Always set exp to 15-60 minutes from now\n\n" +
            
            "❌ VULNERABILITY: Weak secret (password123)\n" +
            "   ✅ FIX: Use strong random secret (256+ bits)\n\n" +
            
            "❌ VULNERABILITY: Accepts any algorithm\n" +
            "   ✅ FIX: Whitelist specific algorithms\n\n" +
            
            "❌ VULNERABILITY: No signature verification\n" +
            "   ✅ FIX: Always verify signature with known key/secret\n\n" +
            
            "❌ VULNERABILITY: KID not validated\n" +
            "   ✅ FIX: Whitelist known key IDs\n\n" +
            
            "═══════════════════════════════════════════════════════════════════════════════\n" +
            "9. EXAMPLE: Full Exploitation Scenario\n" +
            "═══════════════════════════════════════════════════════════════════════════════\n" +
            
            "🎯 Scenario: Web app vulnerable to multiple JWT issues\n\n" +
            "TOKEN: eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJpc19hZG1pbiI6ZmFsc2V9.xxx\n\n" +
            
            "STEP 1: Decode\n" +
            "  • Algorithm: HS256\n" +
            "  • User ID: 1\n" +
            "  • Is Admin: false\n" +
            "  • No expiration!\n\n" +
            
            "STEP 2: Analyze\n" +
            "  • CRITICAL: Missing expiration\n" +
            "  • HIGH: Weak HMAC algorithm\n" +
            "  • HIGH: Sensitive data (user_id)\n\n" +
            
            "STEP 3: Brute Force\n" +
            "  • Start Bruteforcer\n" +
            "  • After 30 seconds: Secret found! \"secret123\"\n\n" +
            
            "STEP 4: Privilege Escalation\n" +
            "  • Go to Attacks tab\n" +
            "  • Use Privilege Escalation\n" +
            "  • Generate: user_id: 1, is_admin: true\n" +
            "  • Sign with secret \"secret123\"\n\n" +
            
            "STEP 5: Test\n" +
            "  • Copy new token\n" +
            "  • Paste in Burp Repeater\n" +
            "  • Send request with new token\n" +
            "  • Application accepts it!\n" +
            "  • Now you have admin access\n\n" +
            
            "═══════════════════════════════════════════════════════════════════════════════\n" +
            "10. TIPS FOR PENETRATION TESTERS\n" +
            "═══════════════════════════════════════════════════════════════════════════════\n" +
            
            "💡 Always check for:\n" +
            "  ✓ Missing expiration (exp claim)\n" +
            "  ✓ Weak algorithms (HMAC-only, no RS256)\n" +
            "  ✓ 'none' algorithm acceptance\n" +
            "  ✓ Sensitive data in payload (PII, API keys)\n" +
            "  ✓ User ID in payload (privilege escalation vector)\n" +
            "  ✓ No signature verification\n" +
            "  ✓ Accepting multiple algorithms\n\n" +
            
            "🎯 Key test cases:\n" +
            "  1. Decode and review claims\n" +
            "  2. Try 'none' algorithm\n" +
            "  3. Try algorithm switching (RS256→HS256)\n" +
            "  4. Brute force secret (if HMAC)\n" +
            "  5. Modify user_id, role, permissions\n" +
            "  6. Test missing/invalid signatures\n" +
            "  7. Try expired tokens (if no validation)\n" +
            "  8. Test KID injection\n\n" +
            
            "═══════════════════════════════════════════════════════════════════════════════\n" +
            "Need help? This tool includes 11 Java classes with:\n" +
            "  • 15+ security vulnerability checks\n" +
            "  • 7 specialized attack modules\n" +
            "  • 1000+ secret wordlist\n" +
            "  • 68+ attack payload variations\n" +
            "  • Full Burp Suite integration\n" +
            "═══════════════════════════════════════════════════════════════════════════════\n"
        );
        
        JScrollPane scrollPane = new JScrollPane(helpText);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        panel.add(scrollPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * Create Decoder Tab - Parse & Display JWT
     */
    private JPanel createDecoderTab() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Input area
        JPanel inputPanel = new JPanel(new BorderLayout(5, 5));
        inputPanel.setBorder(BorderFactory.createTitledBorder("📋 Paste JWT Token Here"));
        
        JTextArea tokenInput = new JTextArea(3, 80);
        tokenInput.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        tokenInput.setLineWrap(true);
        JScrollPane inputScroll = new JScrollPane(tokenInput);
        inputPanel.add(inputScroll, BorderLayout.CENTER);
        
        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton decodeBtn = new JButton("🔓 Decode JWT");
        JButton clearBtn = new JButton("🗑️ Clear");
        
        decodeBtn.addActionListener(e -> {
            String token = tokenInput.getText().trim();
            try {
                currentToken = JWTUtils.parseToken(token);
                updateDecoderOutput(currentToken);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(panel, "❌ Invalid JWT: " + ex.getMessage(), 
                    "Error", JOptionPane.ERROR_MESSAGE);
            }
        });
        
        clearBtn.addActionListener(e -> {
            tokenInput.setText("");
            decoderHeaderOutput.setText("");
            decoderPayloadOutput.setText("");
            decoderSignatureOutput.setText("");
            decoderInfoOutput.setText("");
        });
        
        buttonPanel.add(decodeBtn);
        buttonPanel.add(clearBtn);
        inputPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        // Output area - Resizable components using JSplitPane
        decoderHeaderOutput = new JTextArea(6, 40);
        decoderHeaderOutput.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        decoderHeaderOutput.setEditable(false);
        decoderHeaderOutput.setLineWrap(true);
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setBorder(BorderFactory.createTitledBorder("Header (Algorithm & Type)"));
        headerPanel.add(new JScrollPane(decoderHeaderOutput), BorderLayout.CENTER);
        
        decoderPayloadOutput = new JTextArea(6, 40);
        decoderPayloadOutput.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        decoderPayloadOutput.setEditable(false);
        decoderPayloadOutput.setLineWrap(true);
        JPanel payloadPanel = new JPanel(new BorderLayout());
        payloadPanel.setBorder(BorderFactory.createTitledBorder("Payload (User Data)"));
        payloadPanel.add(new JScrollPane(decoderPayloadOutput), BorderLayout.CENTER);
        
        decoderSignatureOutput = new JTextArea(6, 40);
        decoderSignatureOutput.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        decoderSignatureOutput.setEditable(false);
        decoderSignatureOutput.setLineWrap(true);
        JPanel sigPanel = new JPanel(new BorderLayout());
        sigPanel.setBorder(BorderFactory.createTitledBorder("Signature (Base64URL)"));
        sigPanel.add(new JScrollPane(decoderSignatureOutput), BorderLayout.CENTER);
        
        decoderInfoOutput = new JTextArea(6, 40);
        decoderInfoOutput.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        decoderInfoOutput.setEditable(false);
        decoderInfoOutput.setLineWrap(true);
        JPanel infoPanel = new JPanel(new BorderLayout());
        infoPanel.setBorder(BorderFactory.createTitledBorder("Token Info (Expiration, etc.)"));
        infoPanel.add(new JScrollPane(decoderInfoOutput), BorderLayout.CENTER);
        
        // Create resizable split panes for 4-section layout
        JSplitPane topSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, headerPanel, payloadPanel);
        topSplit.setResizeWeight(0.5);
        topSplit.setDividerLocation(0.5);
        topSplit.setOneTouchExpandable(true);
        
        JSplitPane bottomSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, sigPanel, infoPanel);
        bottomSplit.setResizeWeight(0.5);
        bottomSplit.setDividerLocation(0.5);
        bottomSplit.setOneTouchExpandable(true);
        
        JSplitPane outputPanel = new JSplitPane(JSplitPane.VERTICAL_SPLIT, topSplit, bottomSplit);
        outputPanel.setResizeWeight(0.5);
        outputPanel.setDividerLocation(0.5);
        outputPanel.setOneTouchExpandable(true);
        outputPanel.setBorder(BorderFactory.createTitledBorder("✅ Decoded Components (Drag dividers to resize)"));
        
        panel.add(inputPanel, BorderLayout.NORTH);
        panel.add(outputPanel, BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * Update decoder output with parsed token
     */
    private void updateDecoderOutput(JWTToken token) {
        if (token == null) return;
        
        // Header
        JWTHeader header = token.getHeader();
        StringBuilder headerStr = new StringBuilder();
        headerStr.append("Algorithm (alg): ").append(header.getAlg()).append("\n");
        headerStr.append("Type (typ): ").append(header.getTyp()).append("\n");
        if (header.getKid() != null) {
            headerStr.append("Key ID (kid): ").append(header.getKid()).append("\n");
        }
        if (header.getJku() != null) {
            headerStr.append("JWKS URL (jku): ").append(header.getJku()).append("\n");
        }
        headerStr.append("\n[Full Header JSON]\n");
        headerStr.append(header.toJson());
        decoderHeaderOutput.setText(headerStr.toString());
        
        // Payload
        StringBuilder payloadStr = new StringBuilder();
        payloadStr.append("Subject (sub): ").append(token.getSubject()).append("\n");
        payloadStr.append("Issuer (iss): ").append(token.getIssuer()).append("\n");
        payloadStr.append("Audience (aud): ").append(token.getAudience()).append("\n");
        payloadStr.append("JWT ID (jti): ").append(token.getJTI()).append("\n");
        payloadStr.append("\n[Full Payload Data]\n");
        payloadStr.append(token.getPayloadJson());
        decoderPayloadOutput.setText(payloadStr.toString());
        
        // Signature
        decoderSignatureOutput.setText("Signature (Base64URL encoded):\n\n" + token.getSignature() + 
            "\n\n⚠️ Note: Signature validates token hasn't been tampered.\n" +
            "If you modify header/payload, signature becomes invalid.");
        
        // Token Info
        StringBuilder infoStr = new StringBuilder();
        infoStr.append(token.getTokenInfo());
        decoderInfoOutput.setText(infoStr.toString());
    }
    
    /**
     * Create Analyzer Tab
     */
    private JPanel createAnalyzerTab() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Info text
        JPanel infoPanel = new JPanel(new BorderLayout());
        JTextArea infoArea = new JTextArea(
            "🔍 SECURITY ANALYZER - Checks for 15+ JWT Vulnerabilities\n\n" +
            "This tool identifies:\n" +
            "  🔴 CRITICAL issues: Can be immediately exploited (none algorithm, missing expiration)\n" +
            "  🟠 HIGH risk: Likely exploitable (weak secrets, sensitive data)\n" +
            "  🟡 MEDIUM: Potentially exploitable (missing claims, timestamp issues)\n" +
            "  🟢 LOW: Minor issues (recommendations)\n\n" +
            "Click 'Analyze Current Token' to scan for vulnerabilities. You can resize columns by dragging headers.\n"
        );
        infoArea.setEditable(false);
        infoArea.setFont(new Font("Segoe UI", Font.PLAIN, 10));
        infoArea.setLineWrap(true);
        infoArea.setWrapStyleWord(true);
        infoArea.setBackground(new Color(240, 250, 255));
        infoPanel.add(infoArea, BorderLayout.CENTER);
        infoPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 120));
        
        // Findings table with resizable columns and context menu
        DefaultTableModel tableModel = new DefaultTableModel(
            new String[]{"🎯 Severity", "📌 Issue Title", "📝 Description", "Status"}, 0
        ) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 3; // Only Status column editable
            }
        };
        
        JTable findingsTable = new JTable(tableModel) {
            @Override
            public Class<?> getColumnClass(int column) {
                return String.class;
            }
        };
        findingsTable.setRowHeight(40);
        findingsTable.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        TableColumnModel columnModel = findingsTable.getColumnModel();
        columnModel.getColumn(0).setPreferredWidth(120);
        columnModel.getColumn(1).setPreferredWidth(200);
        columnModel.getColumn(2).setPreferredWidth(350);
        columnModel.getColumn(3).setPreferredWidth(100);
        
        // Make columns resizable by dragging
        for (int i = 0; i < columnModel.getColumnCount(); i++) {
            columnModel.getColumn(i).setResizable(true);
        }
        
        // Add right-click context menu
        JPopupMenu contextMenu = new JPopupMenu();
        JMenuItem markFalsePositive = new JMenuItem("✓ Mark as False Positive");
        JMenuItem markConfirmed = new JMenuItem("✓ Mark as Confirmed");
        JMenuItem changeSeverity = new JMenuItem("📊 Change Severity");
        JMenuItem reportIssue = new JMenuItem("📝 Report Issue");
        
        markFalsePositive.addActionListener(e -> {
            int row = findingsTable.getSelectedRow();
            if (row >= 0) {
                tableModel.setValueAt("FALSE +VE", row, 3);
            }
        });
        
        markConfirmed.addActionListener(e -> {
            int row = findingsTable.getSelectedRow();
            if (row >= 0) {
                tableModel.setValueAt("CONFIRMED", row, 3);
            }
        });
        
        changeSeverity.addActionListener(e -> {
            int row = findingsTable.getSelectedRow();
            if (row >= 0) {
                String[] options = {"CRITICAL", "HIGH", "MEDIUM", "LOW"};
                String severity = (String) JOptionPane.showInputDialog(panel,
                    "Select new severity level:",
                    "Change Severity",
                    JOptionPane.QUESTION_MESSAGE,
                    null,
                    options,
                    options[0]);
                if (severity != null) {
                    String emoji = severity.equals("CRITICAL") ? "🔴" :
                                  severity.equals("HIGH") ? "🟠" :
                                  severity.equals("MEDIUM") ? "🟡" : "🟢";
                    tableModel.setValueAt(emoji + " " + severity, row, 0);
                }
            }
        });
        
        reportIssue.addActionListener(e -> {
            int row = findingsTable.getSelectedRow();
            if (row >= 0) {
                String title = (String) tableModel.getValueAt(row, 1);
                String description = (String) tableModel.getValueAt(row, 2);
                String severity = (String) tableModel.getValueAt(row, 0);
                
                String reportText = "Issue Report\\n\\n" +
                    "Title: " + title + "\\n" +
                    "Severity: " + severity + "\\n" +
                    "Description: " + description + "\\n\\n" +
                    "Token Details:\\n" +
                    (currentToken != null ? "Algorithm: " + currentToken.getHeader().getAlg() : "N/A") + "\\n" +
                    "\\nRecommendations:\\n" +
                    "- Implement strong signature validation\\n" +
                    "- Use secure algorithms (RS256, ES256)\\n" +
                    "- Set appropriate token expiration\\n" +
                    "- Validate all claims on backend\\n";
                
                JTextArea reportArea = new JTextArea(reportText);
                reportArea.setEditable(true);
                reportArea.setLineWrap(true);
                reportArea.setWrapStyleWord(true);
                reportArea.setFont(new Font("Segoe UI", Font.PLAIN, 10));
                
                JScrollPane scrollPane = new JScrollPane(reportArea);
                scrollPane.setPreferredSize(new Dimension(600, 400));
                
                JOptionPane.showMessageDialog(panel, scrollPane, "Issue Report", JOptionPane.INFORMATION_MESSAGE);
            }
        });
        
        contextMenu.add(markConfirmed);
        contextMenu.add(markFalsePositive);
        contextMenu.add(new JSeparator());
        contextMenu.add(changeSeverity);
        contextMenu.add(reportIssue);
        
        // Add mouse listener for context menu
        findingsTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseReleased(java.awt.event.MouseEvent e) {
                int row = findingsTable.rowAtPoint(e.getPoint());
                if (row >= 0) {
                    findingsTable.setRowSelectionInterval(row, row);
                }
                if (e.isPopupTrigger()) {
                    contextMenu.show(findingsTable, e.getX(), e.getY());
                }
            }
        });
        
        JButton analyzeBtn = new JButton("🔎 Analyze Current Token");
        analyzeBtn.setFont(new Font("Segoe UI", Font.BOLD, 12));
        analyzeBtn.addActionListener(e -> {
            if (currentToken == null) {
                JOptionPane.showMessageDialog(panel, "❌ Please decode a token first in the Decoder tab", 
                    "Info", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            
            SecurityAnalyzer analyzer = new SecurityAnalyzer(currentToken);
            java.util.List<SecurityAnalyzer.SecurityFinding> findings = analyzer.analyze();
            
            tableModel.setRowCount(0);
            
            for (SecurityAnalyzer.SecurityFinding finding : findings) {
                tableModel.addRow(new Object[]{
                    finding.severity.getEmoji() + " " + finding.severity.name(),
                    finding.title,
                    finding.description,
                    "NEW"
                });
            }
            
            if (findings.isEmpty()) {
                JOptionPane.showMessageDialog(panel, "✅ No security issues found!", 
                    "Info", JOptionPane.INFORMATION_MESSAGE);
            }
        });
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttonPanel.add(analyzeBtn);
        
        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(infoPanel, BorderLayout.CENTER);
        topPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        JScrollPane findingsScrollPane = new JScrollPane(findingsTable);
        findingsScrollPane.setBorder(BorderFactory.createTitledBorder("Security Findings (Drag column headers to resize)"));
        
        panel.add(topPanel, BorderLayout.NORTH);
        panel.add(findingsScrollPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * Create Bruteforcer Tab
     */
    private JPanel createBruteforceTab() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Info
        JPanel infoPanel = new JPanel(new BorderLayout());
        JTextArea infoArea = new JTextArea(
            "🔓 SECRET BRUTEFORCER - Tests 1000+ Common Secrets\n\n" +
            "How it works:\n" +
            "  1. Token must use HMAC algorithm (HS256, HS384, HS512)\n" +
            "  2. Tests common passwords: password, admin, secret, test123, etc.\n" +
            "  3. Verifies each secret against token signature\n" +
            "  4. If found: YOU CAN FORGE NEW VALID TOKENS!\n\n" +
            "⚠️ If successful, you can impersonate any user or escalate privileges!\n"
        );
        infoArea.setEditable(false);
        infoArea.setFont(new Font("Segoe UI", Font.PLAIN, 10));
        infoArea.setLineWrap(true);
        infoArea.setWrapStyleWord(true);
        infoArea.setBackground(new Color(255, 240, 240));
        infoPanel.add(infoArea, BorderLayout.CENTER);
        infoPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 100));
        
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 10));
        JButton startBtn = new JButton("▶️ Start Bruteforce");
        JButton stopBtn = new JButton("⏸️ Stop");
        JLabel statusLabel = new JLabel("Ready");
        statusLabel.setFont(new Font("Segoe UI", Font.BOLD, 11));
        
        JProgressBar progress = new JProgressBar(0, 100);
        progress.setStringPainted(true);
        progress.setPreferredSize(new Dimension(300, 25));
        
        JTextArea resultArea = new JTextArea(8, 60);
        resultArea.setFont(new Font("Courier New", Font.PLAIN, 11));
        resultArea.setEditable(false);
        resultArea.setLineWrap(true);
        
        startBtn.addActionListener(e -> {
            if (currentToken == null) {
                JOptionPane.showMessageDialog(panel, "❌ Please decode a token first", 
                    "Info", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            
            SecretBruteforcer bruteforcer = new SecretBruteforcer(currentToken);
            
            if (!bruteforcer.canBruteforce()) {
                JOptionPane.showMessageDialog(panel, "❌ Token must use HMAC (HS256, HS384, HS512)\n\n" +
                    "Current algorithm: " + currentToken.getHeader().getAlg(), 
                    "Info", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            
            activeBruteforcer = bruteforcer;
            bruteforceStopped = false;
            startBtn.setEnabled(false);
            stopBtn.setEnabled(true);
            resultArea.setText("🔄 Bruteforce started...\n");
            resultArea.append("Testing common secrets...\n\n");
            
            bruteforcer.startBruteforce(new SecretBruteforcer.BruteforceCallback() {
                @Override
                public void onProgress(int tested, int total) {
                    progress.setMaximum(total);
                    progress.setValue(tested);
                    statusLabel.setText("Tested: " + tested + " / " + total + " secrets");
                }
                
                @Override
                public void onSecretFound(String secret, String algorithm) {
                    resultArea.append("\n" +
                        "═══════════════════════════════════════════════════════════\n" +
                        "🎉 SECRET FOUND!\n" +
                        "═══════════════════════════════════════════════════════════\n" +
                        "Secret: " + secret + "\n" +
                        "Algorithm: " + algorithm + "\n\n" +
                        "⚠️ CRITICAL VULNERABILITY!\n" +
                        "You can now:\n" +
                        "  1. Forge new tokens\n" +
                        "  2. Impersonate any user\n" +
                        "  3. Escalate privileges\n" +
                        "  4. Access restricted resources\n" +
                        "═══════════════════════════════════════════════════════════\n");
                }
                
                @Override
                public void onComplete(boolean found) {
                    if (!bruteforceStopped) {
                        if (!found) {
                            resultArea.append("\n✅ Bruteforce completed\n");
                            resultArea.append("❌ No secret found in default wordlist\n");
                            resultArea.append("(Secret might be custom or stronger)\n");
                        }
                    } else {
                        resultArea.append("\n⏹️ Bruteforce stopped by user\n");
                    }
                    startBtn.setEnabled(true);
                    stopBtn.setEnabled(false);
                }
            });
        });
        
        stopBtn.setEnabled(false);
        stopBtn.addActionListener(e -> {
            bruteforceStopped = true;
            if (activeBruteforcer != null) {
                resultArea.append("\n⏹️ Stopping bruteforce...\n");
            }
            stopBtn.setEnabled(false);
            startBtn.setEnabled(true);
        });
        
        controlPanel.add(startBtn);
        controlPanel.add(stopBtn);
        controlPanel.add(statusLabel);
        
        JPanel progressPanel = new JPanel(new BorderLayout(10, 10));
        progressPanel.add(controlPanel, BorderLayout.NORTH);
        progressPanel.add(progress, BorderLayout.CENTER);
        
        panel.add(infoPanel, BorderLayout.NORTH);
        panel.add(progressPanel, BorderLayout.CENTER);
        panel.add(new JScrollPane(resultArea), BorderLayout.SOUTH);
        
        return panel;
    }
    
    /**
     * Create Attack Platform Tab
     */
    private JPanel createAttackTab() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Info
        JPanel infoPanel = new JPanel(new BorderLayout());
        JTextArea infoArea = new JTextArea(
            "⚔️ ADVANCED ATTACKS - 7 Specialized JWT Attack Modules (68+ Payloads)\n\n" +
            "These attacks generate modified JWT tokens that exploit specific vulnerabilities.\n" +
            "Copy the generated token and test it against the application.\n\n" +
            "👇 Select an attack module below:"
        );
        infoArea.setEditable(false);
        infoArea.setFont(new Font("Segoe UI", Font.PLAIN, 10));
        infoArea.setLineWrap(true);
        infoArea.setWrapStyleWord(true);
        infoArea.setBackground(new Color(240, 255, 240));
        infoPanel.add(infoArea, BorderLayout.CENTER);
        infoPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 80));
        
        JPanel attackPanel = new JPanel(new GridLayout(4, 2, 10, 10));
        attackPanel.setBorder(BorderFactory.createTitledBorder("🎯 Available Attacks"));
        
        // Attack 1
        JButton noneAlgBtn = new JButton("1. None Algorithm Bypass - Set alg='none'");
        noneAlgBtn.setFont(new Font("Segoe UI", Font.BOLD, 11));
        noneAlgBtn.addActionListener(e -> {
            if (currentToken == null) {
                JOptionPane.showMessageDialog(panel, "❌ Please decode a token first", 
                    "Info", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            
            AdvancedAttackPlatform platform = new AdvancedAttackPlatform(currentToken);
            JWTToken attacked = platform.generateNoneAlgorithmBypass();
            showGeneratedToken(attacked, 
                "🎯 NONE ALGORITHM BYPASS\n\n" +
                "WHAT IT DOES:\n" +
                "Changes JWT algorithm from RS256/HS256 to 'none'\n" +
                "Removes signature from token completely\n\n" +
                "HOW IT WORKS:\n" +
                "Standard JWT: header.payload.signature\n" +
                "None algorithm: header.payload. (no signature)\n" +
                "Server skips signature verification\n\n" +
                "WHEN IT WORKS:\n" +
                "If application doesn't validate algorithm type\n" +
                "If server doesn't enforce signature checking\n\n" +
                "IMPACT: 🔴 CRITICAL\n" +
                "• Complete authentication bypass\n" +
                "• Can modify ANY claim without signature\n" +
                "• No verification needed\n\n" +
                "HOW TO TEST:\n" +
                "Copy token → Use in Burp Repeater\n" +
                "If accepted = CRITICAL vulnerability!");
        });
        
        // Attack 2
        JButton algConfusionBtn = new JButton("2. Algorithm Confusion - RS256 to HS256");
        algConfusionBtn.setFont(new Font("Segoe UI", Font.BOLD, 11));
        algConfusionBtn.addActionListener(e -> {
            if (currentToken == null) {
                JOptionPane.showMessageDialog(panel, "❌ Please decode a token first", 
                    "Info", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            
            String secret = JOptionPane.showInputDialog(panel, 
                "Enter HMAC secret to sign tokens:\n(leave empty for 'secret')", "secret");
            if (secret != null && !secret.isEmpty()) {
                AdvancedAttackPlatform platform = new AdvancedAttackPlatform(currentToken);
                java.util.List<JWTToken> attacks = platform.generateAlgorithmConfusionAttacks(secret);
                showGeneratedTokenList(attacks, 
                    "ALGORITHM CONFUSION\n" +
                    "Tests 14+ algorithm variations (RS256→HS256, HS384, etc.)\n" +
                    "Server might incorrectly validate signature with wrong algorithm");
            }
        });
        
        // Attack 3
        JButton kidInjectionBtn = new JButton("3. KID Injection - 67+ Payloads");
        kidInjectionBtn.setFont(new Font("Segoe UI", Font.BOLD, 11));
        kidInjectionBtn.addActionListener(e -> {
            if (currentToken == null) {
                JOptionPane.showMessageDialog(panel, "❌ Please decode a token first", 
                    "Info", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            
            AdvancedAttackPlatform platform = new AdvancedAttackPlatform(currentToken);
            java.util.List<JWTToken> attacks = platform.generateKIDInjectionPayloads();
            showGeneratedTokenList(attacks, 
                "KID PARAMETER INJECTION\n" +
                "Tests 47+ injection payloads in 'kid' (Key ID) header\n" +
                "Examples: SQL injection, path traversal, command injection\n" +
                "Server may retrieve wrong key for verification");
        });
        
        // Attack 4
        JButton jkuManipBtn = new JButton("4. JKU Manipulation - SSRF Attack");
        jkuManipBtn.setFont(new Font("Segoe UI", Font.BOLD, 11));
        jkuManipBtn.addActionListener(e -> {
            if (currentToken == null) {
                JOptionPane.showMessageDialog(panel, "❌ Please decode a token first", 
                    "Info", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            
            String jkuUrl = JOptionPane.showInputDialog(panel, 
                "Enter your malicious JWKS URL:\n(Example: https://attacker.com/jwks.json)", 
                "https://attacker.com/jwks.json");
            if (jkuUrl != null && !jkuUrl.isEmpty()) {
                AdvancedAttackPlatform platform = new AdvancedAttackPlatform(currentToken);
                JWTToken attacked = platform.generateJKUManipulation(jkuUrl);
                showGeneratedToken(attacked, 
                    "JKU MANIPULATION\n" +
                    "Changes JWKS URL to your server\n" +
                    "Server fetches public key from YOUR server\n" +
                    "You sign tokens with your private key\n" +
                    "Server accepts tokens as valid!");
            }
        });
        
        // Attack 5
        JButton jwkInjectionBtn = new JButton("5. JWK Header Injection - Key Embedding");
        jwkInjectionBtn.setFont(new Font("Segoe UI", Font.BOLD, 11));
        jwkInjectionBtn.addActionListener(e -> {
            if (currentToken == null) {
                JOptionPane.showMessageDialog(panel, "❌ Please decode a token first", 
                    "Info", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            
            AdvancedAttackPlatform platform = new AdvancedAttackPlatform(currentToken);
            JWTToken attacked = platform.generateJWKHeaderInjection("{\"kty\": \"RSA\", \"n\": \"...\", \"e\": \"AQAB\"}");
            showGeneratedToken(attacked, 
                "JWK HEADER INJECTION\n" +
                "Adds public key directly in JWT header\n" +
                "Server uses your public key to verify\n" +
                "You sign with your private key");
        });
        
        // Attack 6
        JButton privEscBtn = new JButton("6. Privilege Escalation - Role Modification");
        privEscBtn.setFont(new Font("Segoe UI", Font.BOLD, 11));
        privEscBtn.addActionListener(e -> {
            if (currentToken == null) {
                JOptionPane.showMessageDialog(panel, "❌ Please decode a token first", 
                    "Info", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            
            String secret = JOptionPane.showInputDialog(panel, 
                "Enter HMAC secret to sign token:\n(If you brute-forced it, paste here)", "secret");
            if (secret != null) {
                AdvancedAttackPlatform platform = new AdvancedAttackPlatform(currentToken);
                JWTToken attacked = platform.generatePrivilegeEscalation();
                showGeneratedToken(attacked, 
                    "PRIVILEGE ESCALATION\n" +
                    "Modifies user role from 'user' to 'admin'\n" +
                    "Changes is_admin to true\n" +
                    "Adds admin permissions\n" +
                    "Works if signature is not properly verified");
            }
        });
        
        // Attack 7
        JButton claimSpoofBtn = new JButton("7. Claim Spoofing - User Impersonation");
        claimSpoofBtn.setFont(new Font("Segoe UI", Font.BOLD, 11));
        claimSpoofBtn.addActionListener(e -> {
            if (currentToken == null) {
                JOptionPane.showMessageDialog(panel, "❌ Please decode a token first", 
                    "Info", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            
            AdvancedAttackPlatform platform = new AdvancedAttackPlatform(currentToken);
            java.util.List<JWTToken> attacks = platform.generateCommonSpoofingScenarios();
            showGeneratedTokenList(attacks, 
                "CLAIM SPOOFING\n" +
                "Generates 5 common spoofing scenarios:\n" +
                "  1. Admin impersonation\n" +
                "  2. Different user impersonation\n" +
                "  3. Permission escalation\n" +
                "  4. Time manipulation\n" +
                "  5. Service account spoofing");
        });
        
        attackPanel.add(noneAlgBtn);
        attackPanel.add(algConfusionBtn);
        attackPanel.add(kidInjectionBtn);
        attackPanel.add(jkuManipBtn);
        attackPanel.add(jwkInjectionBtn);
        attackPanel.add(privEscBtn);
        attackPanel.add(claimSpoofBtn);
        attackPanel.add(new JLabel()); // Spacer
        
        panel.add(infoPanel, BorderLayout.NORTH);
        panel.add(new JScrollPane(attackPanel), BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * Create Editor Tab
     */
    private JPanel createEditorTab() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        JTextArea infoArea = new JTextArea(
            "✏️ MANUAL TOKEN EDITOR - Create Custom JWT Tokens\n\n" +
            "Use this tab to manually modify JWT tokens:\n" +
            "  1. Edit the header (algorithm, kid, jku, etc.)\n" +
            "  2. Edit the payload (user_id, role, permissions, etc.)\n" +
            "  3. Select signature algorithm\n" +
            "  4. Specify your secret key (for HMAC)\n" +
            "  5. Click 'Generate Token' to create new JWT\n\n" +
            "⚠️ Advanced feature - Use for custom attack payloads!"
        );
        infoArea.setEditable(false);
        infoArea.setFont(new Font("Segoe UI", Font.PLAIN, 10));
        infoArea.setLineWrap(true);
        infoArea.setWrapStyleWord(true);
        infoArea.setBackground(new Color(255, 250, 240));
        
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setBorder(BorderFactory.createTitledBorder("Edit Header"));
        JTextArea headerEditor = new JTextArea(6, 50);
        headerEditor.setFont(new Font("Courier New", Font.PLAIN, 10));
        headerEditor.setText("{\"alg\": \"HS256\", \"typ\": \"JWT\"}");
        headerPanel.add(new JScrollPane(headerEditor), BorderLayout.CENTER);
        
        JPanel payloadPanel = new JPanel(new BorderLayout());
        payloadPanel.setBorder(BorderFactory.createTitledBorder("Edit Payload"));
        JTextArea payloadEditor = new JTextArea(6, 50);
        payloadEditor.setFont(new Font("Courier New", Font.PLAIN, 10));
        payloadEditor.setText("{\"sub\": \"1\", \"name\": \"John Doe\", \"is_admin\": false}");
        payloadPanel.add(new JScrollPane(payloadEditor), BorderLayout.CENTER);
        
        JPanel secretPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        secretPanel.add(new JLabel("Secret Key:"));
        JTextField secretField = new JTextField("secret", 20);
        secretPanel.add(secretField);
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        JButton generateBtn = new JButton("🔑 Generate Token");
        JButton copyBtn = new JButton("📋 Copy to Clipboard");
        
        generateBtn.addActionListener(e -> {
            try {
                // Parse header and payload
                String headerJson = headerEditor.getText();
                String payloadJson = payloadEditor.getText();
                String secret = secretField.getText();
                
                // Simple implementation - just show message
                JOptionPane.showMessageDialog(panel, 
                    "Custom token editor requires:\n" +
                    "- JSON parsing\n" +
                    "- Custom signing\n\n" +
                    "For now, use the Attacks tab for pre-built payloads.", 
                    "Info", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(panel, "❌ Error: " + ex.getMessage(), 
                    "Error", JOptionPane.ERROR_MESSAGE);
            }
        });
        
        buttonPanel.add(generateBtn);
        buttonPanel.add(copyBtn);
        
        JPanel editorsPanel = new JPanel(new GridLayout(1, 2, 10, 10));
        editorsPanel.add(headerPanel);
        editorsPanel.add(payloadPanel);
        
        panel.add(infoArea, BorderLayout.NORTH);
        panel.add(editorsPanel, BorderLayout.CENTER);
        panel.add(secretPanel, BorderLayout.SOUTH);
        
        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.add(buttonPanel, BorderLayout.CENTER);
        panel.add(bottomPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    /**
     * Show generated token
     */
    private void showGeneratedToken(JWTToken token, String description) {
        String output = "═══════════════════════════════════════════════════════════\n" +
            description + "\n" +
            "═══════════════════════════════════════════════════════════\n\n" +
            "Generated Token:\n\n" +
            token.reconstructToken() + "\n\n" +
            "═══════════════════════════════════════════════════════════\n" +
            "HOW TO TEST:\n" +
            "1. Click the 'Copy Token' button below\n" +
            "2. Open Burp Suite Repeater\n" +
            "3. Paste this token in Authorization header\n" +
            "4. Send the request\n" +
            "5. If token is accepted by app - vulnerability confirmed!\n" +
            "═══════════════════════════════════════════════════════════\n";
        
        String tokenValue = token.reconstructToken();
        
        // Create panel with text area and buttons
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        JTextArea textArea = new JTextArea(output);
        textArea.setEditable(false);
        textArea.setFont(new Font("Courier New", Font.PLAIN, 10));
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        
        JScrollPane scrollPane = new JScrollPane(textArea);
        panel.add(scrollPane, BorderLayout.CENTER);
        
        // Copy button
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 10));
        JButton copyBtn = new JButton("📋 Copy Token");
        copyBtn.setFont(new Font("Segoe UI", Font.BOLD, 12));
        copyBtn.addActionListener(e -> {
            StringSelection stringSelection = new StringSelection(tokenValue);
            java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(stringSelection, null);
            JOptionPane.showMessageDialog(panel, "✅ Token copied to clipboard!", "Success", JOptionPane.INFORMATION_MESSAGE);
        });
        buttonPanel.add(copyBtn);
        panel.add(buttonPanel, BorderLayout.SOUTH);
        
        JOptionPane optionPane = new JOptionPane(panel, JOptionPane.INFORMATION_MESSAGE);
        JDialog dialog = optionPane.createDialog("Generated Attack Token");
        dialog.setSize(750, 500);
        dialog.setVisible(true);
    }
    
    /**
     * Show multiple generated tokens
     */
    private void showGeneratedTokenList(java.util.List<JWTToken> tokens, String description) {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Info panel
        JPanel infoPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        infoPanel.add(new JLabel("Generated " + tokens.size() + " attack tokens - Scroll to view all"));
        panel.add(infoPanel, BorderLayout.NORTH);
        
        // Text area with all tokens
        StringBuilder sb = new StringBuilder(
            "═══════════════════════════════════════════════════════════\n" +
            description + "\n" +
            "═══════════════════════════════════════════════════════════\n\n"
        );
        
        for (int i = 0; i < tokens.size(); i++) {
            sb.append("[Token ").append(i + 1).append(" of ").append(tokens.size()).append("]\n");
            sb.append(tokens.get(i).reconstructToken()).append("\n\n");
        }
        
        sb.append("═══════════════════════════════════════════════════════════\n");
        
        JTextArea textArea = new JTextArea(sb.toString());
        textArea.setEditable(false);
        textArea.setFont(new Font("Courier New", Font.PLAIN, 9));
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        
        JScrollPane scrollPane = new JScrollPane(textArea);
        scrollPane.setPreferredSize(new Dimension(900, 600));
        panel.add(scrollPane, BorderLayout.CENTER);
        
        // Copy first token button
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 10));
        JButton copyFirstBtn = new JButton("📋 Copy First Token");
        copyFirstBtn.setFont(new Font("Segoe UI", Font.BOLD, 11));
        copyFirstBtn.addActionListener(e -> {
            StringSelection stringSelection = new StringSelection(tokens.get(0).reconstructToken());
            java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(stringSelection, null);
            JOptionPane.showMessageDialog(panel, "✅ First token copied to clipboard!", "Success", JOptionPane.INFORMATION_MESSAGE);
        });
        buttonPanel.add(copyFirstBtn);
        panel.add(buttonPanel, BorderLayout.SOUTH);
        
        JOptionPane optionPane = new JOptionPane(panel, JOptionPane.INFORMATION_MESSAGE);
        JDialog dialog = optionPane.createDialog("Generated Attack Tokens (" + tokens.size() + ")");
        dialog.setSize(950, 650);
        dialog.setVisible(true);
    }
    
    @Override
    public String getTabCaption() {
        return "JWT Auditor";
    }
    
    @Override
    public Component getUiComponent() {
        return mainPanel;
    }
    
    public Component getComponent() {
        return mainPanel;
    }
}
