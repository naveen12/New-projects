package burp.jwt;

import burp.*;
import javax.swing.*;

/**
 * JWT Auditor Extension for Burp Suite
 * Comprehensive JWT security testing and analysis platform
 * Based on JWTAuditor (https://github.com/dr34mhacks/jwtauditor)
 * 
 * Features:
 * - JWT Decoder & Analysis
 * - 15+ Security Checks
 * - Secret Bruteforcer (1000+ wordlist)
 * - Advanced Attack Platform (7 attack types)
 * - JWT Editor & Generator
 */
public class JWTAuditorExtender implements IBurpExtender {
    
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        
        callbacks.setExtensionName("JWT Auditor");
        
        // Print banner on load
        printBanner();
        
        // Create and register the main JWT Auditor UI panel
        SwingUtilities.invokeLater(() -> {
            JWTAuditorUI ui = new JWTAuditorUI(callbacks);
            callbacks.addSuiteTab(ui);
            callbacks.printOutput("[JWT Auditor] ✅ Main UI tab registered");
        });
        
        // Register request/response handler for JWT extraction from traffic
        callbacks.registerMessageEditorTabFactory(new JWTEditorTabFactory(callbacks));
        callbacks.printOutput("[JWT Auditor] ✅ Message editor tab factory registered");
        
        // Register context menu items for JWT operations
        callbacks.registerContextMenuFactory(new JWTContextMenuFactory(callbacks));
        callbacks.printOutput("[JWT Auditor] ✅ Context menu factory registered");
        
        printLoadingComplete();
    }
    
    /**
     * Print extension banner on startup
     */
    private void printBanner() {
        callbacks.printOutput("\n");
        callbacks.printOutput("╔══════════════════════════════════════════════════════════════════════════════╗");
        callbacks.printOutput("║                                                                              ║");
        callbacks.printOutput("║                       JWT AUDITOR - EXTENSION LOADED                         ║");
        callbacks.printOutput("║                                                                              ║");
        callbacks.printOutput("║                 Professional JWT Security Testing Tool v2.1                  ║");
        callbacks.printOutput("║                                                                              ║");
        callbacks.printOutput("╚══════════════════════════════════════════════════════════════════════════════╝");
        callbacks.printOutput("\n");
    }
    
    /**
     * Print feature information on load completion
     */
    private void printLoadingComplete() {
        callbacks.printOutput("[JWT Auditor] ════════════════════════════════════════════════════════════");
        callbacks.printOutput("[JWT Auditor] EXTENSION FEATURES:");
        callbacks.printOutput("[JWT Auditor] ");
        callbacks.printOutput("[JWT Auditor] 🔓 DECODER TAB");
        callbacks.printOutput("[JWT Auditor]    • Parse and display JWT tokens (header, payload, signature, info)");
        callbacks.printOutput("[JWT Auditor]    • Resizable 4-section layout for detailed inspection");
        callbacks.printOutput("[JWT Auditor]    • Shows expiration, issued time, claim count");
        callbacks.printOutput("[JWT Auditor] ");
        callbacks.printOutput("[JWT Auditor] 🔍 ANALYZER TAB");
        callbacks.printOutput("[JWT Auditor]    • 15+ security vulnerability checks");
        callbacks.printOutput("[JWT Auditor]    • Color-coded severity levels (CRITICAL → LOW)");
        callbacks.printOutput("[JWT Auditor]    • Right-click context menu: Mark false positives, change severity");
        callbacks.printOutput("[JWT Auditor]    • Generate detailed issue reports");
        callbacks.printOutput("[JWT Auditor] ");
        callbacks.printOutput("[JWT Auditor] ⚡ BRUTEFORCER TAB");
        callbacks.printOutput("[JWT Auditor]    • Tests 1000+ common JWT secrets");
        callbacks.printOutput("[JWT Auditor]    • Works with HMAC algorithms (HS256, HS384, HS512)");
        callbacks.printOutput("[JWT Auditor]    • Real-time progress tracking");
        callbacks.printOutput("[JWT Auditor]    • Typical time: 10-30 seconds per token");
        callbacks.printOutput("[JWT Auditor] ");
        callbacks.printOutput("[JWT Auditor] ⚔️ ATTACKS TAB");
        callbacks.printOutput("[JWT Auditor]    • 7 specialized attack modules (68+ payloads)");
        callbacks.printOutput("[JWT Auditor]    1. None Algorithm Bypass (signature bypass)");
        callbacks.printOutput("[JWT Auditor]    2. Algorithm Confusion (14 variants)");
        callbacks.printOutput("[JWT Auditor]    3. KID Injection (67 payloads - fully scrollable)");
        callbacks.printOutput("[JWT Auditor]    4. JKU Manipulation (SSRF attack)");
        callbacks.printOutput("[JWT Auditor]    5. JWK Header Injection (key embedding)");
        callbacks.printOutput("[JWT Auditor]    6. Privilege Escalation (role modification)");
        callbacks.printOutput("[JWT Auditor]    7. Claim Spoofing (5 impersonation scenarios)");
        callbacks.printOutput("[JWT Auditor]    • All attacks include copy-to-clipboard button");
        callbacks.printOutput("[JWT Auditor] ");
        callbacks.printOutput("[JWT Auditor] ✏️ EDITOR TAB");
        callbacks.printOutput("[JWT Auditor]    • Manually create custom JWT tokens");
        callbacks.printOutput("[JWT Auditor]    • Edit header and payload JSON");
        callbacks.printOutput("[JWT Auditor]    • Specify HMAC secret for signing");
        callbacks.printOutput("[JWT Auditor] ");
        callbacks.printOutput("[JWT Auditor] 📚 HELP & INFO TAB");
        callbacks.printOutput("[JWT Auditor]    • Comprehensive guide for all features");
        callbacks.printOutput("[JWT Auditor]    • Real-world exploitation examples");
        callbacks.printOutput("[JWT Auditor]    • Penetration testing methodology");
        callbacks.printOutput("[JWT Auditor] ");
        callbacks.printOutput("[JWT Auditor] ════════════════════════════════════════════════════════════");
        callbacks.printOutput("[JWT Auditor] QUICK START:");
        callbacks.printOutput("[JWT Auditor] ");
        callbacks.printOutput("[JWT Auditor] 1. Switch to 'JWT Auditor' tab in Burp Suite");
        callbacks.printOutput("[JWT Auditor] 2. Paste a JWT token in the Decoder tab");
        callbacks.printOutput("[JWT Auditor] 3. Click 'Analyze Current Token' to find vulnerabilities");
        callbacks.printOutput("[JWT Auditor] 4. Generate attack payloads from the Attacks tab");
        callbacks.printOutput("[JWT Auditor] 5. Test in Burp Repeater with Copy Token button");
        callbacks.printOutput("[JWT Auditor] ");
        callbacks.printOutput("[JWT Auditor] ════════════════════════════════════════════════════════════");
        callbacks.printOutput("[JWT Auditor] STATUS: ✅ All components loaded successfully");
        callbacks.printOutput("[JWT Auditor] Ready for JWT security testing!");
        callbacks.printOutput("[JWT Auditor] ════════════════════════════════════════════════════════════\n");
    }
}
