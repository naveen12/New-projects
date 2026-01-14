package burp.jwt;

import burp.*;
import javax.swing.*;
import java.util.*;

/**
 * JWT Context Menu Factory for Burp Suite
 * Provides context menu items for JWT operations on right-click
 */
public class JWTContextMenuFactory implements IContextMenuFactory {
    
    private IBurpExtenderCallbacks callbacks;
    
    public JWTContextMenuFactory(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }
    
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> items = new ArrayList<>();
        
        // Get selected content
        byte[] selectedData = invocation.getSelectedMessages() != null && 
                             invocation.getSelectedMessages().length > 0 ?
                             invocation.getSelectedMessages()[0].getRequest() : null;
        
        if (selectedData == null) {
            return items;
        }
        
        String content = new String(selectedData);
        
        // Check if content contains JWT
        if (content.contains("Authorization: Bearer") || content.contains("token") || 
            content.matches(".*[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{0,}.*")) {
            
            JMenuItem analyzeJWT = new JMenuItem("Send to JWT Auditor");
            analyzeJWT.addActionListener(e -> {
                JOptionPane.showMessageDialog(null, 
                    "JWT Analysis would be performed. Activate the JWT Auditor tab in Burp Suite.", 
                    "JWT Auditor", JOptionPane.INFORMATION_MESSAGE);
            });
            
            items.add(analyzeJWT);
        }
        
        return items;
    }
}
