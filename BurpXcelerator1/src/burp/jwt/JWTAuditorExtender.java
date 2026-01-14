package burp.jwt;

import burp.*;
import javax.swing.*;

/**
 * JWT Auditor Extension for Burp Suite
 * Comprehensive JWT security testing and analysis platform
 * Based on JWTAuditor (https://github.com/dr34mhacks/jwtauditor)
 */
public class JWTAuditorExtender implements IBurpExtender {
    
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        
        callbacks.setExtensionName("JWT Auditor");
        
        // Create and register the main JWT Auditor UI panel
        SwingUtilities.invokeLater(() -> {
            JWTAuditorUI ui = new JWTAuditorUI(callbacks);
            callbacks.addSuiteTab(ui.getTabCaption(), ui.getComponent());
        });
        
        // Register request/response handler for JWT extraction from traffic
        callbacks.registerMessageEditorTabFactory(new JWTEditorTabFactory(callbacks));
        
        // Register context menu items for JWT operations
        callbacks.registerContextMenuFactory(new JWTContextMenuFactory(callbacks));
        
        callbacks.printOutput("JWT Auditor Extension loaded successfully");
    }
}
