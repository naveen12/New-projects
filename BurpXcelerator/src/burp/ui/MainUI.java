package burp.ui;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.IMessageEditorTabFactory;
import burp.ITab;
import burp.accesstrol.AccessControlTester;
import burp.accesstrol.AccessControlUI;
import burp.core.CoreEngine;
import burp.integrations.IntegrationsUI;
import burp.parameters.ParameterAnalyzerUI;
import burp.relevance.URLRelevanceUI;
import burp.reporting.ReportingUI;

import javax.swing.*;
import java.awt.BorderLayout;
import java.awt.Component;

public class MainUI extends JPanel implements ITab {
    private final IBurpExtenderCallbacks callbacks;
    private CoreEngine coreEngine;
    private JTabbedPane tabbedPane;
    private URLRelevanceUI urlRelevanceUI;
    private ParameterAnalyzerUI parameterAnalyzerUI;
    private AccessControlUI accessControlUI;
    private AccessControlTester accessControlTester;

    public MainUI(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        initComponents();
    }
    
    public void setCoreEngine(CoreEngine coreEngine) {
        this.coreEngine = coreEngine;
        this.urlRelevanceUI = new URLRelevanceUI(callbacks, coreEngine);
        this.parameterAnalyzerUI = new ParameterAnalyzerUI(callbacks, coreEngine);
        this.accessControlUI = new AccessControlUI();
        this.accessControlTester = new AccessControlTester(callbacks, coreEngine, accessControlUI);
        tabbedPane.setComponentAt(0, this.urlRelevanceUI);
        tabbedPane.setComponentAt(1, this.parameterAnalyzerUI);
        tabbedPane.setComponentAt(2, this.accessControlUI);
        tabbedPane.setComponentAt(3, new IntegrationsUI());
        tabbedPane.setComponentAt(4, new ReportingUI());
    }

    private void initComponents() {
        setLayout(new BorderLayout());
        tabbedPane = new JTabbedPane();

        // Add tabs for each module
        tabbedPane.addTab("URL Relevance", new JPanel()); // Placeholder, will be replaced
        tabbedPane.addTab("Parameter Analyzer", new JPanel()); // Placeholder
        tabbedPane.addTab("Access Control", new JPanel()); // Placeholder
        tabbedPane.addTab("Integrations", new JPanel()); // Placeholder
        tabbedPane.addTab("Reporting", new JPanel()); // Placeholder

        add(tabbedPane, BorderLayout.CENTER);
    }

    @Override
    public String getTabCaption() {
        return BurpExtender.EXTENSION_NAME;
    }

    @Override
    public Component getUiComponent() {
        return this;
    }

    public IContextMenuFactory getContextMenuFactory() {
        return accessControlTester;
    }

    public IMessageEditorTabFactory getMessageEditorTabFactory() {
        // Placeholder for the message editor tab factory
        return null;
    }
    
    public URLRelevanceUI getURLRelevanceUI() {
        return urlRelevanceUI;
    }

    public ParameterAnalyzerUI getParameterAnalyzerUI() {
        return parameterAnalyzerUI;
    }
}
