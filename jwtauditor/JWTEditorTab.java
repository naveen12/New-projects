package burp.jwt;

import burp.*;
import javax.swing.*;
import java.awt.*;

/**
 * JWT Editor Tab Implementation
 * Displays and allows editing of JWT tokens in HTTP messages
 */
public class JWTEditorTab implements IMessageEditorTab {
    
    private IMessageEditorController controller;
    private IBurpExtenderCallbacks callbacks;
    private boolean editable;
    private JPanel panel;
    private JTextArea display;
    private byte[] currentMessage;
    private JWTToken currentToken;
    
    public JWTEditorTab(IMessageEditorController controller, boolean editable, 
                       IBurpExtenderCallbacks callbacks) {
        this.controller = controller;
        this.editable = editable;
        this.callbacks = callbacks;
        initializeUI();
    }
    
    private void initializeUI() {
        panel = new JPanel(new BorderLayout());
        
        display = new JTextArea();
        display.setFont(new Font("Courier New", Font.PLAIN, 11));
        display.setEditable(editable);
        
        JScrollPane scroll = new JScrollPane(display);
        panel.add(scroll, BorderLayout.CENTER);
        
        // Add info panel
        JPanel infoPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel infoLabel = new JLabel("No JWT detected");
        infoPanel.add(infoLabel);
        panel.add(infoPanel, BorderLayout.NORTH);
    }
    
    @Override
    public String getTabCaption() {
        return "JWT";
    }
    
    @Override
    public JPanel getUiComponent() {
        return panel;
    }
    
    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        try {
            String text = new String(content);
            String jwt = JWTUtils.extractJWTFromRequest(text);
            return jwt != null && JWTUtils.isValidJWT(jwt);
        } catch (Exception e) {
            return false;
        }
    }
    
    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        currentMessage = content;
        
        try {
            String text = new String(content);
            String jwt = JWTUtils.extractJWTFromRequest(text);
            
            if (jwt != null) {
                currentToken = JWTUtils.parseToken(jwt);
                display.setText(formatTokenDisplay(currentToken));
                display.setCaretPosition(0);
            } else {
                display.setText("No JWT found in message");
            }
        } catch (Exception e) {
            display.setText("Error parsing JWT: " + e.getMessage());
        }
    }
    
    @Override
    public byte[] getMessage() {
        if (currentMessage != null) {
            return currentMessage;
        }
        return new byte[0];
    }
    
    @Override
    public boolean isModified() {
        return false;
    }
    
    @Override
    public byte[] getSelectedData() {
        String selected = display.getSelectedText();
        return selected != null ? selected.getBytes() : new byte[0];
    }
    
    /**
     * Format token for display
     */
    private String formatTokenDisplay(JWTToken token) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== JWT Token Analysis ===\n\n");
        
        // Header
        sb.append("HEADER:\n");
        sb.append("  Algorithm: ").append(token.getHeader().getAlg()).append("\n");
        if (token.getHeader().getTyp() != null) {
            sb.append("  Type: ").append(token.getHeader().getTyp()).append("\n");
        }
        if (token.getHeader().getKid() != null) {
            sb.append("  Key ID: ").append(token.getHeader().getKid()).append("\n");
        }
        
        // Payload
        sb.append("\nPAYLOAD:\n");
        for (String claim : token.getAllClaims()) {
            sb.append("  ").append(claim).append(": ").append(token.getClaim(claim)).append("\n");
        }
        
        // Token info
        sb.append("\nTOKEN INFO:\n");
        sb.append("  Subject: ").append(token.getSubject()).append("\n");
        sb.append("  Issuer: ").append(token.getIssuer()).append("\n");
        sb.append("  Expires: ").append(token.getExpirationDate()).append("\n");
        sb.append("  Expired: ").append(token.isExpired()).append("\n");
        sb.append("  Size: ").append(token.getTokenSize()).append(" bytes\n");
        
        return sb.toString();
    }
}
