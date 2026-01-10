package burp.accesstrol;

import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import burp.core.CoreEngine;

import burp.IRequestInfo;
import burp.IResponseInfo;

import javax.swing.JMenuItem;
import java.util.ArrayList;
import java.util.List;

public class AccessControlTester implements IContextMenuFactory {
    private final IBurpExtenderCallbacks callbacks;
    private final CoreEngine coreEngine;
    private final AccessControlUI accessControlUI;

    public AccessControlTester(IBurpExtenderCallbacks callbacks, CoreEngine coreEngine, AccessControlUI accessControlUI) {
        this.callbacks = callbacks;
        this.coreEngine = coreEngine;
        this.accessControlUI = accessControlUI;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuItems = new ArrayList<>();
        IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();

        if (selectedMessages != null && selectedMessages.length > 0) {
            JMenuItem menuItem = new JMenuItem("Test Access Control");
            menuItem.addActionListener(e -> {
                for (IHttpRequestResponse message : selectedMessages) {
                    new Thread(() -> testAccessControl(message)).start();
                }
            });
            menuItems.add(menuItem);
        }

        return menuItems;
    }

    private void testAccessControl(IHttpRequestResponse originalMessage) {
        IRequestInfo requestInfo = callbacks.getHelpers().analyzeRequest(originalMessage);
        List<String> headers = requestInfo.getHeaders();
        
        // Test 1: Remove cookies
        List<String> headersNoCookies = new ArrayList<>();
        for (String header : headers) {
            if (!header.toLowerCase().startsWith("cookie:")) {
                headersNoCookies.add(header);
            }
        }
        byte[] requestNoCookies = callbacks.getHelpers().buildHttpMessage(headersNoCookies, callbacks.getHelpers().analyzeRequest(originalMessage.getRequest()).getBodyOffset() == 0 ? new byte[0] : originalMessage.getRequest());
        IHttpRequestResponse responseNoCookies = callbacks.makeHttpRequest(originalMessage.getHttpService(), requestNoCookies);

        // Test 2: Remove Authorization header
        List<String> headersNoAuth = new ArrayList<>();
        for (String header : headers) {
            if (!header.toLowerCase().startsWith("authorization:")) {
                headersNoAuth.add(header);
            }
        }
        byte[] requestNoAuth = callbacks.getHelpers().buildHttpMessage(headersNoAuth, callbacks.getHelpers().analyzeRequest(originalMessage.getRequest()).getBodyOffset() == 0 ? new byte[0] : originalMessage.getRequest());
        IHttpRequestResponse responseNoAuth = callbacks.makeHttpRequest(originalMessage.getHttpService(), requestNoAuth);

        // Analyze results
        analyzeAndReport(originalMessage, responseNoCookies, "No Cookies");
        analyzeAndReport(originalMessage, responseNoAuth, "No Authorization");
    }

    private void analyzeAndReport(IHttpRequestResponse original, IHttpRequestResponse modified, String testName) {
        if(modified == null || modified.getResponse() == null) {
            return;
        }
        IResponseInfo originalResponseInfo = callbacks.getHelpers().analyzeResponse(original.getResponse());
        IResponseInfo modifiedResponseInfo = callbacks.getHelpers().analyzeResponse(modified.getResponse());
        
        int originalStatus = originalResponseInfo.getStatusCode();
        int modifiedStatus = modifiedResponseInfo.getStatusCode();
        int originalLength = original.getResponse().length;
        int modifiedLength = modified.getResponse().length;
        String result = "Inconclusive";

        if (originalStatus != modifiedStatus) {
            result = "Status code differs";
        } else if (Math.abs(originalLength - modifiedLength) > originalLength * 0.1) { // 10% difference
            result = "Response length differs significantly";
        }

        String url = callbacks.getHelpers().analyzeRequest(original).getUrl().toString();
        accessControlUI.addTestResult(url + " (" + testName + ")", originalStatus, modifiedStatus, originalLength, modifiedLength, result);
    }
}
