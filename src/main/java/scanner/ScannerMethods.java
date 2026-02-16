package scanner;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.clientapi.core.*;

import java.io.File;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDate;

public class ScannerMethods {
    private static String scanId = null;
    private static String user = "VOLUser";
    private static int progress;

    private final ClientApi clientApi;
    private ApiResponse response;

    private String reportURL;
    private String userId;
    private final String CONTEXT_ID = "1";
    private final String CONTEXTS = "Default Context";


    private static final Logger LOGGER = LogManager.getLogger(ScannerMethods.class);

    public ScannerMethods(String ZAP_IP_ADDRESS, int ZAP_PORT) {
        this.clientApi = new ClientApi(ZAP_IP_ADDRESS, ZAP_PORT);
    }

    /**
     * Method for creating summary table for HTML report
     */
    private String createReportSummaryTable() {
        return """
                <table width=45%% border=0>
                <tr bgcolor=#666666>
                <td width=45%% height=24>
                <strong>
                <font color=#FFFFFF size=2 face=Arial, Helvetica, sans-serif>URLs SCANNED</font>
                </strong>
                </td>
                </tr>
                <tr bgcolor=#e8e8e8>
                <td><font size=2 face=Arial, Helvetica, sans-serif><a href=#%s>%s</a></font></td>
                </tr>
                <p></p>
                <p></p>
                <p></p>
                <p></p>""".formatted(this.reportURL, this.reportURL);
    }

    /**
     * Method for creating header response and requests summary table for HTML report
     */
    private String headersAndResponseSummaryTable() throws ClientApiException {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("""
                <table width=45%% border=0>
                <tr bgcolor=#666666>
                <h3>Server Requests and Responses</h3><div class=spacer></div>
                <td width=50%%>Request</td>
                <td width=50%%><p>Response</p></td>""");

        response = this.clientApi.core.messages(this.reportURL, "-1", "-1");
        ApiResponseList apiResponseList = (ApiResponseList) response;
        for (ApiResponse apiResponse : apiResponseList.getItems()) {
            if (apiResponse instanceof ApiResponseSet serverResponse) {
                stringBuilder.append("""
                        <tr bgcolor=#e8e8e8>
                        <td width=100><p>%s</p></td>
                        <td width=100><p>%s</p></td>
                        </tr>""".formatted(
                        serverResponse.getStringValue("requestHeader"),
                        serverResponse.getStringValue("responseHeader")));
            }
        }
        return stringBuilder.toString();
    }

    /**
     * Method for generating the scan HTML Report
     */

    public void createReport(String reportName, String reportURL) {
        this.reportURL = reportURL;
        long seconds = Instant.now().getEpochSecond();
        LocalDate date = LocalDate.now();
        File dir = new File("Reports");
        if (!dir.exists()) {
            dir.mkdir();
        }
        try {
            this.clientApi.reports.generate(reportName, "traditional-html", null, null, null,
                    null, null, null, null, "%s%s -%d".formatted(reportName, date, seconds), null, 
                    "%s/%s".formatted(System.getProperty("user.dir"), dir), null);
        } catch (ClientApiException e) {
            LOGGER.info(e);
        }
    }

    /**
     * Method for downloading the latest major stable release
     */

    public void downLoadLatestRelease() throws Exception {
        this.clientApi.autoupdate.downloadLatestRelease();
    }

    /**
     * Method for stopping ZAP
     */

    public void stopZap() {
        try {
            this.clientApi.core.shutdown();
        } catch (ClientApiException e) {
            LOGGER.info(e);
        }
    }

    /**
     * @param urlRegex
     * @throws Exception
     */
    public void excludeUrlFromSpiderScan(String urlRegex) throws Exception {
        this.clientApi.spider.excludeFromScan(urlRegex);
    }

    /**
     * @param urlRegex
     * @throws Exception
     */
    public void excludeUrlFromActiveScan(String urlRegex) throws Exception {
        this.clientApi.ascan.excludeFromScan(urlRegex);
    }

    /**
     * @param CONTEXT_NAME
     * @throws Exception
     */
    public void createContext(String CONTEXT_NAME) throws Exception {
        this.clientApi.context.newContext(CONTEXT_NAME);
    }

    /**
     * @param CONTEXT_NAME
     * @throws ClientApiException
     */
    public void useExistingContext(String CONTEXT_NAME) throws ClientApiException {
        this.clientApi.context.context(CONTEXT_NAME);
    }

    /**
     * @param url
     * @throws ClientApiException
     */
    public void includeInContext(String CONTEXT_NAME, String url) throws ClientApiException {
        this.clientApi.context.includeInContext(CONTEXT_NAME, url);
    }

    /**
     * @param siteUrl
     * @param loginRequest
     * @throws Exception Method for creating a user and setting an auth method <a href="https://github.com/zaproxy/zap-core-help/wiki/HelpStartConceptsAuthentication">...</a>
     *                   Supported Auth methods: manualAuthentication,formBasedAuthentication,jsonBasedAuthentication,http_ntlm_Authentication,scriptBasedAuthentication
     */
    public void setAuthenticationMethod(String siteUrl, String loginRequest, String authentication) throws Exception {

        String formBasedConfig = "loginUrl=%s&loginRequestData=%s".formatted(
                URLEncoder.encode(siteUrl, StandardCharsets.UTF_8),
                URLEncoder.encode(loginRequest, StandardCharsets.UTF_8));
        this.clientApi.authentication.setAuthenticationMethod(CONTEXT_ID, authentication, formBasedConfig);
        // Check if everything is set up ok
        LOGGER.info("Authentication Setup: {}", clientApi.authentication.getAuthenticationMethod(CONTEXT_ID).toString(0));
    }

    public void createUser(String userName) throws ClientApiException {
        this.clientApi.users.newUser(CONTEXT_ID, userName);
    }

    public void enableUser() throws ClientApiException {
        this.clientApi.users.setUserEnabled(CONTEXT_ID, userId, "true");
    }

    public void enableForcedUser() throws ClientApiException {
        this.clientApi.forcedUser.setForcedUserModeEnabled(true);
    }


    /**
     * @param setStatus
     * @throws ClientApiException Method for starting in active scanner mode
     */

    public void allowAttackOnStart(boolean setStatus) throws ClientApiException {
        this.clientApi.ascan.setOptionAllowAttackOnStart(setStatus);
    }


    /**
     * @param setStatus
     * @throws ClientApiException Method for rescanning
     */
    public void allowRescan(boolean setStatus) throws ClientApiException {
        this.clientApi.ascan.setOptionRescanInAttackMode(setStatus);
    }


    /**
     * @param username
     * @param password
     * @throws Exception Method for authenticating a user, used for sites that require authentication
     */

    public void authenticateUser(String username, String password) throws Exception {
        user = "VOLUser";

        String userAuthConfig = "username=%s&password=%s".formatted(
                URLEncoder.encode(username, StandardCharsets.UTF_8),
                URLEncoder.encode(password, StandardCharsets.UTF_8));

        userId = extractUserId(clientApi.users.newUser(CONTEXT_ID, user));

        enableUser();
        this.clientApi.users.setAuthenticationCredentials(CONTEXT_ID, userId, userAuthConfig);

        // Check if everything is set up ok
        LOGGER.info("Authentication config: {}", clientApi.users.getUserById(CONTEXT_ID, userId).toString(0));
    }

    public void authenticateAsUser(String contextId, String userId) throws ClientApiException {
        this.clientApi.users.authenticateAsUser(contextId, userId);
    }

    private static String extractUserId(ApiResponse response) {
        return switch (response) {
            case ApiResponseElement element -> element.getValue();
            default -> throw new IllegalArgumentException("Unexpected response type: " + response.getClass());
        };
    }


    /**
     * @param loginIndicator the text that you expect to find on a page once logged in e.g. 'Your account'
     * @throws Exception
     */
    public void loggedInIndicator(String loginIndicator) throws ClientApiException {
        this.clientApi.authentication.setLoggedInIndicator(CONTEXT_ID, loginIndicator);
    }

    public void loggedOutIndicator(String loginIndicator) throws ClientApiException {
        this.clientApi.authentication.setLoggedOutIndicator(CONTEXT_ID, loginIndicator);
    }

    /**
     * @throws ClientApiException
     */
    public void removeContext() throws ClientApiException {
        this.clientApi.context.removeContext("Default Context");
    }

    /**
     * @param ruleId
     * @param newLevel
     * @throws Exception
     */
    public void filterAlerts(String ruleId, String newLevel) throws Exception {
        this.clientApi.alertFilter.addAlertFilter(CONTEXT_ID, ruleId, newLevel, "http://a.b.c.*", "true", null, "true");
    }


    /**
     * @param policyName Policy Ids to be used when scanning
     */
    public String setPolicyId(String policyName) {
        return switch (policyName) {
            case "directory-browsing" -> "0";
            case "cross-site-scripting" -> "40012,40014,40016,40017";
            case "sql-injection" -> "40018";
            case "path-traversal" -> "6";
            case "remote-file-inclusion" -> "7";
            case "server-side-include" -> "40009";
            case "script-active-scan-rules" -> "50000";
            case "server-side-code-injection" -> "90019";
            case "remote-os-command-injection" -> "90020";
            case "external-redirect" -> "20019";
            case "crlf-injection" -> "40003";
            case "source-code-disclosure" -> "42,10045,20017";
            case "shell-shock" -> "10048";
            case "remote-code-execution" -> "20018";
            case "ldap-injection" -> "40015";
            case "xpath-injection" -> "90021";
            case "xml-external-entity" -> "90023";
            case "padding-oracle" -> "90024";
            case "el-injection" -> "90025";
            case "insecure-http-methods" -> "90028";
            case "parameter-pollution" -> "20014";
            case "parameter-tampering" -> "40008";
            case "SOAP XML Injection" -> "90029";
            default -> throw new RuntimeException("No policy id found for: " + policyName);
        };
    }

    public void enableAllPassiveScanners() throws Exception {
        this.clientApi.pscan.enableAllScanners();
    }

    public void enableAllActiveScanners(String policyName) throws Exception {
        this.clientApi.ascan.enableAllScanners(policyName);
    }

    public void enableActiveScannerByName(String policyName) throws Exception {
        this.clientApi.ascan.enableScanners(setPolicyId(policyName), policyName);
    }

    public void addDomainThatIsAlwaysInScope(String domain) throws ClientApiException {
        this.clientApi.spider.addDomainAlwaysInScope(domain, "", "true");
    }

    /**
     * @param policyName
     * @param attackStrength LOW,MEDIUM,HIGH,INSANE
     */
    public void setScannerAttackStrengthAndPolicy(String policyName, String alertThreshold,String attackStrength) throws Exception {
        this.clientApi.ascan.addScanPolicy(policyName, alertThreshold.toUpperCase(),attackStrength.toUpperCase());
    }

    public void setPolicyAttackStrength(String policyId, String attackStrength) throws Exception {
        String DEFAULT_POLICY = "Default Policy";
        this.clientApi.ascan.setPolicyAttackStrength(policyId, attackStrength.toUpperCase(), DEFAULT_POLICY);
    }
    /**
     * @param option true or false
     */
    public void setOptionHandleAntiCSRFTokens(boolean option) throws Exception {
        clientApi.ascan.setOptionHandleAntiCSRFTokens(option);
    }


    /**
     * @param url
     * @throws Exception Only logged-in users can see this feature
     */
    public void performSpiderCrawlAsUser(String url) throws Exception {
        response = clientApi.spider.scanAsUser(CONTEXT_ID, userId, url, null, "false", "true");
        scanId = ((ApiResponseElement) response).getValue();
        while (true) {
            progress = Integer.parseInt(((ApiResponseElement) this.clientApi.spider.status(scanId)).getValue());
            LOGGER.info("Static scan in progress : {}%", progress);
            if (progress == 100) {
                break;
            }
            try {
                Thread.sleep(5000);
            } catch (InterruptedException e) {
                LOGGER.info(e);
            }
        }
    }

    /**
     * @param url
     */
    public void performActiveAttackAsUser(String url, String policy) throws ClientApiException {
        response = clientApi.ascan.scanAsUser(url, CONTEXT_ID, userId, "false", policy, null, null);
        scanId = ((ApiResponseElement) response).getValue();
        while (true) {
            progress = Integer.parseInt(((ApiResponseElement) clientApi.ascan.status(scanId)).getValue());
            LOGGER.info("Authenticated Dynamic scan in progress : {}%", progress);
            if (progress == 100) {
                break;
            }
            try {
                Thread.sleep(3000);
            } catch (InterruptedException e) {
                LOGGER.info(e);
            }
        }
    }

    /**
     * @param url
     * @throws Exception Only logged-in users can see this feature
     */
    public void performAJAXSpiderCrawlAsUser(String username, String url) throws Exception {
        response = clientApi.ajaxSpider.scanAsUser(CONTEXT_ID, user, url, "true");
        scanId = ((ApiResponseElement) response).getValue();
        while (true) {
            progress = Integer.parseInt(((ApiResponseElement) this.clientApi.ajaxSpider.status()).getValue());
            LOGGER.info("Ajax scan in progress : {}%", progress);
            if (progress == 100) {
                break;
            }
            try {
                Thread.sleep(5000);
            } catch (InterruptedException e) {
                LOGGER.info(e);
            }
        }
    }

    /**
     * @param url
     * @param CONTEXT_NAME
     * @throws Exception
     */
    public void performSpiderCrawl(String url, String CONTEXT_NAME) throws Exception {
        response = clientApi.spider.scan(url, null, "false", CONTEXT_NAME, "true");
        scanId = ((ApiResponseElement) response).getValue();
        while (true) {
            progress = Integer.parseInt(((ApiResponseElement) this.clientApi.spider.status(scanId)).getValue());
            LOGGER.info("Spider Static scan in progress : {}%", progress);
            if (progress == 100) {
                break;
            }
            try {
                Thread.sleep(5000);
            } catch (InterruptedException e) {
                LOGGER.info(e);
            }
        }
    }

    /**
     * @param url
     * @throws Exception
     */
    public void performActiveAttack(String url, String policy) throws Exception {
        response = this.clientApi.ascan.scan(url, "false", "true", policy, null, null);
        scanId = ((ApiResponseElement) response).getValue();
        while (true) {
            progress = Integer.parseInt(((ApiResponseElement) this.clientApi.ascan.status(scanId)).getValue());
            LOGGER.info("Dynamic scan in progress : {}%", progress);
            if (progress == 100) {
                break;
            }
            try {
                Thread.sleep(3000);
            } catch (InterruptedException e) {
                LOGGER.info(e);
            }
        }
    }
}