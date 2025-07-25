package burp.Utils;

import burp.*;

import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.Utils.Date_tidy.extractRequestUrl;

public class Poc_Scan {
    // 去重
    private static final Set<String> scannedHosts = ConcurrentHashMap.newKeySet();
    
    // POC 列表
    private static final List<String> BASE_POC_LIST = Arrays.asList(
            "GET / HTTP/1.1",
            "GET /?acl HTTP/1.1",
            "GET /?policy HTTP/1.1",
            "PUT /123.html HTTP/1.1",
            "PUT /123.png HTTP/1.1"
    );
    
    private static final String HOST_HEADER = "\r\nHost: ";
    private static final String USER_AGENT_HEADER = "\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36";
    private static final String SEC_CH_UA_PLATFORM_HEADER = "\r\nSec-Ch-Ua-Platform: \"Windows\"";
    private static final String CONNECTION_HEADER = "\r\nConnection: keep-alive";
    private static final String REFERER_HEADER = "\r\nReferer: ";
    
    // 云服务提供商常量
    private static final String CLOUD_HUAWEI = "Cloud_HuaWei";
    private static final String CLOUD_TENCENT = "Cloud_TengXun";

    /**
     * 被动扫描方法，基于代理流量进行漏洞检测
     */
    public static List<RequestResponseWrapper> buildHttpServiceFromUrl(
            IBurpExtenderCallbacks callbacks, 
            IExtensionHelpers helpers, 
            HashMap<String, ArrayList> couldHashMap, 
            IHttpRequestResponse messageInfo,
            String modifiedUrl) {
        
        List<RequestResponseWrapper> results = new ArrayList<>();
        List<String> currentPocList = new ArrayList<>(BASE_POC_LIST);
        
        // 仅当 modifiedUrl 有效时添加
        if (modifiedUrl != null && !modifiedUrl.trim().isEmpty()) {
            currentPocList.add("GET " + modifiedUrl + " HTTP/1.1");
        }

        boolean includePath = true;
        String referer = extractRequestUrl(messageInfo, includePath);

        // 获取Map中所有的key
        for (Map.Entry<String, ArrayList> entry : couldHashMap.entrySet()) {
            String cloudProvider = entry.getKey();
            ArrayList<String> hosts = entry.getValue();
            
            for (String host : hosts) {
                if (!scannedHosts.contains(host)) { // 检查是否已经扫描过该主机名
                    scannedHosts.add(host); // 将主机名添加到已经扫描过的集合中
                    
                    String[] hostParts = host.split(":");
                    String hostName = hostParts[0];
                    int targetPort = hostParts.length > 1 ? Integer.parseInt(hostParts[1]) : 443;
                    boolean useHttps = targetPort == 443 || targetPort == 8443;

                    // 对每个POC进行测试
                    for (int i = 0; i < currentPocList.size(); i++) {
                        String poc = currentPocList.get(i);
                        
                        String requestString = buildRequestString(poc, host, referer);
                        String requestBody = buildRequestBody(i, cloudProvider);

                        IHttpRequestResponse response = sendHttpRequest(helpers, callbacks, hostName, targetPort, useHttps, requestString, requestBody);
                        
                        if (response != null && response.getResponse() != null) {
                            // 分析响应
                            boolean isHtmlResponse = checkHtmlResponse(helpers, response.getResponse(), modifiedUrl, poc, i);
                            String message = analyzeResponse(helpers, response, cloudProvider, poc);
                            
                            if (isHtmlResponse) {
                                message = "存储桶解析漏洞";
                            }
                            
                            // 记录漏洞
                            if (message != null && !message.isEmpty()) {
                                results.add(new RequestResponseWrapper(response, message, host));
                            }
                        }
                    }
                }
            }
        }

        return results;
    }
    
    /**
     * 主动扫描方法
     */
    public static List<RequestResponseWrapper> hostScan(
            IBurpExtenderCallbacks callbacks, 
            IExtensionHelpers helpers, 
            String host) {

        List<RequestResponseWrapper> results = new ArrayList<>();
        String modifiedUrl = null;
        String hostName = host;
        int port = 443; // 默认HTTPS端口
        boolean useHttps = true; // 默认使用HTTPS
        
        // 解析URL和构建modifiedUrl
        try {
            URL urlObj = new URL(host);
            String basePath = urlObj.getPath();

            // 定义需要处理的扩展名列表
            String[] targetExtensions = {".txt", ".js", ".json", ".png", ".jpg", ".pdf", ".zip"};
            String regex = ".*(" + String.join("|", targetExtensions) + ")$";
            Pattern pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
            Matcher matcher = pattern.matcher(basePath);
            boolean isTargetFile = matcher.find(); // 判断路径是否匹配目标扩展名
            
            // 定义poc
            String newParam = "response-content-type=text/html";
            // url.getQuery();判断url中是否存在？
            String currentQuery = urlObj.getQuery();
            if (isTargetFile) {
                if (currentQuery == null) {
                    // 无参数时拼接 ?param
                    modifiedUrl = basePath + "?" + newParam;
                } else {
                    // 已有参数时拼接 &param
                    modifiedUrl = basePath + "&" + newParam;
                }
            }
            
            hostName = urlObj.getHost(); // 提取纯主机名
            port = urlObj.getPort();
            port = (port == -1) ? urlObj.getDefaultPort() : port; // 如果端口号为-1，使用默认端口
            useHttps = "https".equalsIgnoreCase(urlObj.getProtocol());
        } catch (MalformedURLException e) {
            // 处理非URL格式的输入
            String[] parts = host.split(":");
            if (parts.length > 1) {
                try {
                    hostName = parts[0];
                    port = Integer.parseInt(parts[1]);
                    useHttps = port == 443; // 如果端口是443，我们认为它是HTTPS
                } catch (NumberFormatException ex) {
                    throw new RuntimeException("Invalid port format in host: " + host, ex);
                }
            } else {
                // 如果输入没有协议或端口，假设是HTTPS
                hostName = host;
            }
        }
        
        // 去掉可能存在的路径部分
        int pathIndex = hostName.indexOf("/");
        if (pathIndex != -1) {
            hostName = hostName.substring(0, pathIndex);
        }
        
        // 构建POC列表
        List<String> currentPocList = new ArrayList<>(BASE_POC_LIST);
        if (modifiedUrl != null && !modifiedUrl.trim().isEmpty()) {
            currentPocList.add("GET " + modifiedUrl + " HTTP/1.1");
        }

        // 发送请求并分析响应
        for (String poc : currentPocList) {
            String requestString = buildRequestString(poc, hostName, null);
            String requestBody = poc.contains("PUT") ? "<div style=\"display:none;\">Hidden Element</div><script>console.log('XSS Test');</script>" : "";

            IHttpRequestResponse response = sendHttpRequest(helpers, callbacks, hostName, port, useHttps, requestString, requestBody);
            
            String message = null;
            if (response != null && response.getResponse() != null) {
                boolean isHtmlResponse = checkHtmlResponse(helpers, response.getResponse(), modifiedUrl, "GET " + modifiedUrl + " HTTP/1.1", -1);
                message = analyzeResponse(helpers, response, null, poc);
                
                if (isHtmlResponse) {
                    message = "存储桶解析漏洞";
                }
                
                if (message != null) {
                    results.add(new RequestResponseWrapper(response, message, hostName));
                } else {
                    results.add(new RequestResponseWrapper(response, "未发现漏洞", hostName));
                }
            } else {
                results.add(new RequestResponseWrapper(null, "Destination is unreachable", hostName));
            }
        }
        
        return results;
    }
    
    /**
     * 构建HTTP请求字符串
     */
    private static String buildRequestString(String poc, String host, String referer) {
        StringBuilder requestBuilder = new StringBuilder(poc);
        requestBuilder.append(HOST_HEADER).append(host);
        requestBuilder.append(SEC_CH_UA_PLATFORM_HEADER);
        requestBuilder.append(USER_AGENT_HEADER);
        requestBuilder.append(CONNECTION_HEADER);
        if (referer != null) {
            requestBuilder.append(REFERER_HEADER).append(referer);
        }
        return requestBuilder.toString();
    }
    
    /**
     * 构建请求体
     */
    private static String buildRequestBody(int pocIndex, String cloudProvider) {
        // PUT 请求需要请求体，但华为云除外
        if (pocIndex == 3 && !CLOUD_HUAWEI.equals(cloudProvider)) {
            return "<div style=\"display:none;\">Hidden Element</div><script>console.log('XSS Test');</script>";
        }
        return "";
    }
    
    /**
     * 发送HTTP请求
     */
    private static IHttpRequestResponse sendHttpRequest(
            IExtensionHelpers helpers,
            IBurpExtenderCallbacks callbacks,
            String hostName,
            int targetPort,
            boolean useHttps,
            String requestString,
            String requestBody) {
        
        try {
            byte[] requestBytes = requestString.getBytes(StandardCharsets.UTF_8);
            IRequestInfo analyzedRequest = helpers.analyzeRequest(requestBytes);
            List<String> headers = analyzedRequest.getHeaders();
            byte[] request = helpers.buildHttpMessage(headers, requestBody.getBytes(StandardCharsets.UTF_8));
            
            // 构建HTTP服务
            IHttpService httpService = helpers.buildHttpService(hostName, targetPort, useHttps);
            // 发送请求并获取响应
            return callbacks.makeHttpRequest(httpService, request);
        } catch (Exception e) {
            return null;
        }
    }
    
    /**
     * 检查是否为HTML响应（用于检测解析漏洞）
     */
    private static boolean checkHtmlResponse(
            IExtensionHelpers helpers, 
            byte[] responseBytes, 
            String modifiedUrl, 
            String poc, 
            int pocIndex) {
        
        if (modifiedUrl == null) {
            return false;
        }
        
        // 只有特定的POC才检查
        if (poc.equals("GET " + modifiedUrl + " HTTP/1.1")) {
            IResponseInfo analyzeResponse = helpers.analyzeResponse(responseBytes);
            List<String> responseHeaders = analyzeResponse.getHeaders();
            
            for (String header : responseHeaders) {
                if (header.contains("Content-Type: text/html")) {
                    return true;
                }
            }
        }
        return false;
    }
    
    /**
     * 分析响应并判断是否存在漏洞
     */
    private static String analyzeResponse(
            IExtensionHelpers helpers, 
            IHttpRequestResponse response, 
            String cloudProvider, 
            String poc) {
        
        try {
            byte[] responseBytes = response.getResponse();
            String responseString = new String(responseBytes, "UTF-8");
            IResponseInfo analyzeResponse = helpers.analyzeResponse(responseBytes);
            int statusCode = analyzeResponse.getStatusCode();
            
            if (statusCode == 200) {
                if (responseString.contains("</ListBucketResult>")) {
                    return "Bucket遍历";
                } else if (responseString.contains("<AccessControlPolicy>")) {
                    return "Bucket ACL可读";
                } else if (responseString.contains("\"Effect\": \"allow\"")) {
                    return "Bucket 权限策略为允许";
                } else if ((poc.contains("PUT /123.html HTTP/1.1") || poc.contains("PUT /123.png HTTP/1.1"))) {
                    // 华为云不支持文件上传检测
                    if (cloudProvider == null || !CLOUD_HUAWEI.equals(cloudProvider)) {
                        return "Bucket文件上传";
                    }
                }
            } else if (statusCode == 404 && poc.equals("GET / HTTP/1.1") && responseString.contains("The specified bucket does not exist")) {
                // 腾讯云例外处理
                if (cloudProvider == null || !CLOUD_TENCENT.equals(cloudProvider)) {
                    return "Bucket可接管";
                }
            }
        } catch (UnsupportedEncodingException e) {
            // 忽略编码异常
        }
        return null;
    }
    
    /**
     * 提取路径层级
     */
    public static List<String> extractPaths(String uri) {
        // 去除末尾斜杠
        if (uri.endsWith("/")) {
            uri = uri.substring(0, uri.length() - 1);
        }

        // 拆分路径段
        String[] segments = uri.split("/");

        // 动态生成不同层级的路径并存储到列表中
        List<String> paths = new ArrayList<>();
        StringBuilder basePathBuilder = new StringBuilder();

        for (String segment : segments) {
            if (!segment.isEmpty()) {  // 跳过空字符串
                basePathBuilder.append('/').append(segment);
                paths.add(basePathBuilder.toString());  // 不再添加额外的斜杠
            }
        }

        // 添加根路径（空字符串）
        paths.add("");

        // 反转列表以得到从详细到基础的顺序
        Collections.reverse(paths);

        return paths;
    }

    /**
     * 请求响应包装类
     */
    public static class RequestResponseWrapper {
        private final IHttpRequestResponse requestResponse;
        private final String message;
        private final String hosts;

        public RequestResponseWrapper(IHttpRequestResponse requestResponse, String message, String hosts) {
            this.requestResponse = requestResponse;
            this.message = message;
            this.hosts = hosts;
        }

        public IHttpRequestResponse getRequestResponse() {
            return requestResponse;
        }

        public String getMessage() {
            return message;
        }

        public String getHosts(){
            return hosts;
        }
    }
}
