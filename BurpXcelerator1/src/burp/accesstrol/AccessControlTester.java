package burp.accesstrol;

import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.core.CoreEngine;

import javax.swing.JMenuItem;
import java.util.ArrayList;
import java.util.List;

/**
 * AccessControlTester: Tests for broken access control vulnerabilities.
 * Provides right-click context menu option to replay requests without cookies
 * or with modified authorization headers, detecting anomalies via status codes,
 * response lengths, and content differences.
 */
public class AccessControlTester implements IContextMenuFactory {
    private final IBurpExtenderCallbacks callbacks;
    private final CoreEngine coreEngine;
    private final AccessControlUI accessControlUI;
    
    // Constants for analysis thresholds
    private static final double RESPONSE_LENGTH_THRESHOLD = 0.15; // 15% difference
    
    public AccessControlTester(IBurpExtenderCallbacks callbacks, CoreEngine coreEngine, AccessControlUI accessControlUI) {
        this.callbacks = callbacks;
        this.coreEngine = coreEngine;
        this.accessControlUI = accessControlUI;
    }

    /**
     * Create context menu items for access control testing.
     */
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuItems = new ArrayList<>();
        IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();

        if (selectedMessages != null && selectedMessages.length > 0) {
            JMenuItem testACMenuItem = new JMenuItem("Test Access Control");
            testACMenuItem.addActionListener(e -> {
                for (IHttpRequestResponse message : selectedMessages) {
                    new Thread(() -> testAccessControl(message)).start();
                }
            });
            menuItems.add(testACMenuItem);
        }

        return menuItems;
    }

    /**
     * Test access control by replaying requests with various modifications.
     */
    private void testAccessControl(IHttpRequestResponse originalMessage) {
        try {
            IRequestInfo requestInfo = callbacks.getHelpers().analyzeRequest(originalMessage);
            String url = requestInfo.getUrl().toString();
            
            // Test 1: Remove cookies
            IHttpRequestResponse responseNoCookies = testWithoutCookies(originalMessage, requestInfo);
            if (responseNoCookies != null && responseNoCookies.getResponse() != null) {
                analyzeAndReport(originalMessage, responseNoCookies, "No Cookies", url);
            }
            
            // Test 2: Remove Authorization header
            IHttpRequestResponse responseNoAuth = testWithoutAuth(originalMessage, requestInfo);
            if (responseNoAuth != null && responseNoAuth.getResponse() != null) {
                analyzeAndReport(originalMessage, responseNoAuth, "No Authorization", url);
            }
            
            // Test 3: Modified User ID (if numeric ID parameters exist)
            IHttpRequestResponse responseModifiedID = testWithModifiedID(originalMessage, requestInfo);
            if (responseModifiedID != null && responseModifiedID.getResponse() != null) {
                analyzeAndReport(originalMessage, responseModifiedID, "Modified ID", url);
            }
        } catch (Exception e) {
            callbacks.printError("Error during access control testing: " + e.getMessage());
        }
    }

    /**
     * Test by removing all cookies from the request.
     */
    private IHttpRequestResponse testWithoutCookies(IHttpRequestResponse originalMessage, IRequestInfo requestInfo) {
        try {
            List<String> headers = new ArrayList<>(requestInfo.getHeaders());
            headers.removeIf(h -> h.toLowerCase().startsWith("cookie:"));
            
            int bodyOffset = requestInfo.getBodyOffset();
            byte[] body = originalMessage.getRequest().length > bodyOffset ? 
                    java.util.Arrays.copyOfRange(originalMessage.getRequest(), bodyOffset, originalMessage.getRequest().length) : 
                    new byte[0];
            
            byte[] modifiedRequest = callbacks.getHelpers().buildHttpMessage(headers, body);
            return callbacks.makeHttpRequest(originalMessage.getHttpService(), modifiedRequest);
        } catch (Exception e) {
            callbacks.printError("Error testing without cookies: " + e.getMessage());
            return null;
        }
    }

    /**
     * Test by removing Authorization header from the request.
     */
    private IHttpRequestResponse testWithoutAuth(IHttpRequestResponse originalMessage, IRequestInfo requestInfo) {
        try {
            List<String> headers = new ArrayList<>(requestInfo.getHeaders());
            headers.removeIf(h -> h.toLowerCase().startsWith("authorization:"));
            
            int bodyOffset = requestInfo.getBodyOffset();
            byte[] body = originalMessage.getRequest().length > bodyOffset ? 
                    java.util.Arrays.copyOfRange(originalMessage.getRequest(), bodyOffset, originalMessage.getRequest().length) : 
                    new byte[0];
            
            byte[] modifiedRequest = callbacks.getHelpers().buildHttpMessage(headers, body);
            return callbacks.makeHttpRequest(originalMessage.getHttpService(), modifiedRequest);
        } catch (Exception e) {
            callbacks.printError("Error testing without auth: " + e.getMessage());
            return null;
        }
    }

    /**
     * Test by modifying numeric ID parameters in the request.
     */
    private IHttpRequestResponse testWithModifiedID(IHttpRequestResponse originalMessage, IRequestInfo requestInfo) {
        try {
            List<burp.IParameter> parameters = requestInfo.getParameters();
            
            // Find a numeric parameter that looks like an ID
            burp.IParameter idParam = null;
            for (burp.IParameter param : parameters) {
                String name = param.getName().toLowerCase();
                if ((name.contains("id") || name.endsWith("_id")) && param.getValue().matches("\\d+")) {
                    idParam = param;
                    break;
                }
            }
            
            if (idParam == null) {
                return null; // No ID parameter to modify
            }
            
            // Modify the ID
            int originalID = Integer.parseInt(idParam.getValue());
            int modifiedID = originalID > 1 ? originalID - 1 : originalID + 1;
            
            burp.IParameter modifiedParam = callbacks.getHelpers().buildParameter(
                    idParam.getName(),
                    String.valueOf(modifiedID),
                    idParam.getType()
            );
            
            byte[] modifiedRequest = callbacks.getHelpers().removeParameter(originalMessage.getRequest(), idParam);
            modifiedRequest = callbacks.getHelpers().addParameter(modifiedRequest, modifiedParam);
            
            return callbacks.makeHttpRequest(originalMessage.getHttpService(), modifiedRequest);
        } catch (Exception e) {
            callbacks.printError("Error testing with modified ID: " + e.getMessage());
            return null;
        }
    }

    /**
     * Analyze responses and detect access control anomalies.
     */
    private void analyzeAndReport(IHttpRequestResponse original, IHttpRequestResponse modified, 
                                  String testName, String url) {
        try {
            IResponseInfo originalResponseInfo = callbacks.getHelpers().analyzeResponse(original.getResponse());
            IResponseInfo modifiedResponseInfo = callbacks.getHelpers().analyzeResponse(modified.getResponse());
            
            int originalStatus = originalResponseInfo.getStatusCode();
            int modifiedStatus = modifiedResponseInfo.getStatusCode();
            int originalLength = original.getResponse().length;
            int modifiedLength = modified.getResponse().length;
            
            // Analyze for access control issues
            AccessControlIssue issue = null;
            
            // Status code change indicates potential issue
            if (originalStatus != modifiedStatus) {
                if ((originalStatus == 200 || originalStatus == 201) && modifiedStatus == 200) {
                    issue = new AccessControlIssue(url, testName, "Status Code Different", 
                            AccessControlIssue.Severity.HIGH, originalStatus, modifiedStatus, originalLength, modifiedLength);
                } else if (modifiedStatus >= 400) {
                    issue = new AccessControlIssue(url, testName, "Status Code Reveals Access Control",
                            AccessControlIssue.Severity.MEDIUM, originalStatus, modifiedStatus, originalLength, modifiedLength);
                }
            }
            
            // Response length change
            long lengthDiff = Math.abs(originalLength - modifiedLength);
            double percentDiff = (double) lengthDiff / originalLength;
            
            if (percentDiff > RESPONSE_LENGTH_THRESHOLD) {
                if (issue == null) {
                    issue = new AccessControlIssue(url, testName, "Response Length Differs Significantly",
                            AccessControlIssue.Severity.MEDIUM, originalStatus, modifiedStatus, originalLength, modifiedLength);
                }
            }
            
            // Report to UI
            if (issue != null) {
                accessControlUI.addTestResult(issue);
            } else {
                // No anomaly detected, still log for reference
                accessControlUI.addTestResult(new AccessControlIssue(url, testName, "No Anomaly Detected",
                        AccessControlIssue.Severity.LOW, originalStatus, modifiedStatus, originalLength, modifiedLength));
            }
        } catch (Exception e) {
            callbacks.printError("Error analyzing access control test: " + e.getMessage());
        }
    }
}
