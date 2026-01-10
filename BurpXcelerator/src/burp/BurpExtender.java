package burp;

import burp.core.CoreEngine;
import burp.ui.MainUI;
import burp.IContextMenuFactory;

import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender {
    public static final String EXTENSION_NAME = "BurpXcelerator";
    private IBurpExtenderCallbacks callbacks;
    private CoreEngine coreEngine;
    private MainUI mainUI;
    private PrintWriter stdout;
    private PrintWriter stderr;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);

        stdout.println("Initializing " + EXTENSION_NAME);

        this.mainUI = new MainUI(callbacks); // Create MainUI first
        this.coreEngine = new CoreEngine(callbacks, mainUI); // Pass MainUI to CoreEngine
        this.mainUI.setCoreEngine(coreEngine); // Set CoreEngine in MainUI

        callbacks.setExtensionName(EXTENSION_NAME);
        callbacks.registerHttpListener(coreEngine);
        callbacks.registerContextMenuFactory(mainUI.getContextMenuFactory());
        callbacks.registerMessageEditorTabFactory(mainUI.getMessageEditorTabFactory());
        callbacks.addSuiteTab(mainUI);

        stdout.println(EXTENSION_NAME + " initialized successfully.");
    }
}
