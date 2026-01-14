package burp.jwt;

import burp.*;
import javax.swing.*;

/**
 * JWT Editor Tab Factory for Burp Suite
 * Automatically recognizes and displays JWT tokens in HTTP messages
 */
public class JWTEditorTabFactory implements IMessageEditorTabFactory {
    
    private IBurpExtenderCallbacks callbacks;
    
    public JWTEditorTabFactory(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }
    
    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, 
                                               boolean editable) {
        return new JWTEditorTab(controller, editable, callbacks);
    }
}
