package burp.ui;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.ITab;
import burp.accesstrol.AccessControlTester;
import burp.accesstrol.AccessControlUI;
import burp.core.CoreEngine;
import burp.integrations.IntegrationsUI;
import burp.parameters.ParameterAnalyzerUI;
import burp.relevance.URLRelevanceUI;
import burp.reporting.ReportingUI;

import javax.swing.*;
import java.awt.*;

/**
 * MainUI: The primary UI component for BurpXcelerator.
 * Provides a tabbed interface with all extension modules:
 * - URL Relevance Engine
 * - Parameter Analyzer
 * - Access Control Tester
 * - Integrations (Nuclei, Semgrep, OWASP Mapping)
 * - Reporting
 */
public class MainUI extends JPanel implements ITab {
    private final IBurpExtenderCallbacks callbacks;
    private CoreEngine coreEngine;
    private JTabbedPane tabbedPane;
    
    // Module UI components
    private URLRelevanceUI urlRelevanceUI;
    private ParameterAnalyzerUI parameterAnalyzerUI;
    private AccessControlUI accessControlUI;
    private AccessControlTester accessControlTester;
    private IntegrationsUI integrationsUI;
    private ReportingUI reportingUI;

    /**
     * Constructor for MainUI.
     */
    public MainUI(IBurpExtenderCallbacks callbacks, CoreEngine coreEngine) {
        this.callbacks = callbacks;
        this.coreEngine = coreEngine;
        coreEngine.setMainUI(this);
        
        initComponents();
    }
    
    /**
     * Initialize all UI components and tabs.
     */
    private void initComponents() {
        setLayout(new BorderLayout());
        tabbedPane = new JTabbedPane();

        // URL Relevance tab
        urlRelevanceUI = new URLRelevanceUI(callbacks, coreEngine);
        tabbedPane.addTab("URL Relevance", urlRelevanceUI);

        // Parameter Analyzer tab
        parameterAnalyzerUI = new ParameterAnalyzerUI(callbacks, coreEngine);
        tabbedPane.addTab("Parameter Analyzer", parameterAnalyzerUI);

        // Access Control tab
        accessControlUI = new AccessControlUI();
        accessControlTester = new AccessControlTester(callbacks, coreEngine, accessControlUI);
        tabbedPane.addTab("Access Control", accessControlUI);

        // Integrations tab
        integrationsUI = new IntegrationsUI();
        tabbedPane.addTab("Integrations", integrationsUI);

        // Reporting tab
        reportingUI = new ReportingUI();
        tabbedPane.addTab("Reporting", reportingUI);

        add(tabbedPane, BorderLayout.CENTER);
    }

    /**
     * Get the tab caption for Burp Suite.
     */
    @Override
    public String getTabCaption() {
        return BurpExtender.EXTENSION_NAME;
    }

    /**
     * Get the UI component.
     */
    @Override
    public Component getUiComponent() {
        return this;
    }

    /**
     * Get the context menu factory for access control testing.
     */
    public IContextMenuFactory getContextMenuFactory() {
        return accessControlTester;
    }

    /**
     * Get the URL Relevance UI.
     */
    public URLRelevanceUI getURLRelevanceUI() {
        return urlRelevanceUI;
    }

    /**
     * Get the Parameter Analyzer UI.
     */
    public ParameterAnalyzerUI getParameterAnalyzerUI() {
        return parameterAnalyzerUI;
    }

    /**
     * Get the Access Control UI.
     */
    public AccessControlUI getAccessControlUI() {
        return accessControlUI;
    }

    /**
     * Get the Integrations UI.
     */
    public IntegrationsUI getIntegrationsUI() {
        return integrationsUI;
    }

    /**
     * Get the Reporting UI.
     */
    public ReportingUI getReportingUI() {
        return reportingUI;
    }
}
