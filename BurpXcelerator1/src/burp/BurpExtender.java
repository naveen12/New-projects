package burp;

import burp.core.CoreEngine;
import burp.ui.MainUI;
import java.io.PrintWriter;

/**
 * BurpExtender: The main entry point for the BurpXcelerator extension.
 * Implements IBurpExtender and coordinates all modules.
 */
public class BurpExtender implements IBurpExtender {
    public static final String EXTENSION_NAME = "BurpXcelerator";
    public static final String EXTENSION_VERSION = "1.0.0";
    
    private IBurpExtenderCallbacks callbacks;
    private CoreEngine coreEngine;
    private MainUI mainUI;
    private PrintWriter stdout;
    private PrintWriter stderr;

    /**
     * Register extension callbacks and initialize all modules.
     */
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);

        try {
            // Log initialization
            stdout.println("[*] Initializing " + EXTENSION_NAME + " v" + EXTENSION_VERSION);

            // Create core engine first
            this.coreEngine = new CoreEngine(callbacks);
            stdout.println("[+] Core Engine initialized");

            // Create UI
            this.mainUI = new MainUI(callbacks, coreEngine);
            stdout.println("[+] Main UI initialized");

            // Register extension
            callbacks.setExtensionName(EXTENSION_NAME);
            
            // Register HTTP listener for traffic capture
            callbacks.registerHttpListener(coreEngine);
            stdout.println("[+] HTTP Listener registered");
            
            // Register context menu factory for access control testing
            callbacks.registerContextMenuFactory(mainUI.getContextMenuFactory());
            stdout.println("[+] Context Menu Factory registered");
            
            // Add main UI as tab
            callbacks.addSuiteTab(mainUI);
            stdout.println("[+] Extension Tab added");

            stdout.println("[✓] " + EXTENSION_NAME + " initialized successfully!");
            stdout.println("[+] Ready to analyze HTTP traffic...");
            
        } catch (Exception e) {
            stderr.println("[!] Error initializing " + EXTENSION_NAME + ": " + e.getMessage());
            e.printStackTrace(stderr);
        }
    }
}
