package burp.Utils;

import burp.*;

import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static burp.Utils.Date_tidy.extractRequestUrl;

public class Poc_Scan {
    //去重
    private static Set<String> scannedHosts = Collections.synchronizedSet(new HashSet<>());
    public  static  List<RequestResponseWrapper> buildHttpServiceFromUrl(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, HashMap<String, ArrayList> CouldHashMap, IHttpRequestResponse messageInfo,String modifiedUrl) {

        String[] poc_HTTP = {
                "GET / HTTP/1.1",
                "GET /?acl HTTP/1.1",
                "GET /?policy HTTP/1.1",
                "PUT /123.html HTTP/1.1",
                "GET "+modifiedUrl+" HTTP/1.1"
        };
        List<RequestResponseWrapper> results = new ArrayList<>();

        boolean includePath = true;
        String Referer = extractRequestUrl(messageInfo, includePath);

        //获取Map中所有的key
        for (String keys : CouldHashMap.keySet()) {
            List list = CouldHashMap.get(keys);
            for (Object host : list) {
                if (!scannedHosts.contains(host)) { // 检查是否已经扫描过该主机名
                    scannedHosts.add((String) host); // 将主机名添加到已经扫描过的集合中
                    for (int i = 0; i < poc_HTTP.length; i++) {
                        String requestString = poc_HTTP[i] + "\r\nHost: " + host + "\r\nSec-Ch-Ua-Platform: \"Windows\""
                                + "\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36\r\n"
                                + "\r\nConnection: keep-alive\r\n"
                                + "\r\nReferer: " + Referer + "\r\n";
                        // 添加请求体（如果有）
                        String requestBody = (i == 3 && !"Cloud_HuaWei".equals(keys)) ? "<div style=\"display:none;\">Hidden Element</div><script>console.log('XSS Test');</script>" : ""; // PUT 请求需要请求体

                        byte[] requestBytes = requestString.getBytes(StandardCharsets.UTF_8);
                        IRequestInfo analyzedRequest = helpers.analyzeRequest(requestBytes);
                        List<String> headers = analyzedRequest.getHeaders();
                        byte[] request = helpers.buildHttpMessage(headers, requestBody.getBytes(StandardCharsets.UTF_8));
                        // 构建HTTP服务
                        IHttpService httpService = helpers.buildHttpService((String) host, 443, true);
                        // 发送请求并获取响应
                        IHttpRequestResponse response = callbacks.makeHttpRequest(httpService, request);
                        byte[] responseBytes = response.getResponse();
                        // 响应头判断是否解析漏洞
                        Boolean IsResponseheaders = false;
                        IResponseInfo analyzeResponse = helpers.analyzeResponse(responseBytes);
                        List<String> Responseheaders = analyzeResponse.getHeaders();
                        //"GET "+modifiedUrl+" HTTP/1.1"  必须是这个请求才会判断
                        if (poc_HTTP[i].equals("GET "+modifiedUrl+" HTTP/1.1")){
                            for (String header : Responseheaders) {
                                if (header.contains("Content-Type: text/html")) {
                                    IsResponseheaders = true;
                                    break;
                                }
                            }
                        }
                        // 响应状态码
                        int statusCode = getStatusCode(callbacks, response.getResponse());
                        // 响应内容
                        byte[] response1 = response.getResponse();
                        // 检测漏洞条件
                        String message = null;
                        String responseString = null;
                        try {
                            responseString = new String(response1, "UTF-8");
                            if (statusCode == 200) {
                                if (poc_HTTP[i].equals("GET / HTTP/1.1") && responseString.contains("</ListBucketResult>")) {
                                    message = "Bucket遍历";
                                } else if (poc_HTTP[i].equals("GET /?acl HTTP/1.1") && responseString.contains("<AccessControlPolicy>")) {
                                    message = "Bucket ACL可读";
                                } else if (poc_HTTP[i].equals("GET /?policy HTTP/1.1") && responseString.contains("\"Effect\": \"allow\"")) {
                                    message = "Bucket 权限策略为允许";
                                } else if (poc_HTTP[i].equals("PUT /123.html HTTP/1.1") && !"Cloud_HuaWei".equals(keys)) {
                                    message = "Bucket文件上传";
                                }
                            } else if (statusCode == 404 && poc_HTTP[i].equals("GET / HTTP/1.1") && responseString.contains("The specified bucket does not exist") && !"Cloud_TengXun".equals(keys)) {
                                message = "Bucket可接管";
                            }
                            if (IsResponseheaders) {
                                message = "存储桶解析漏洞";
                            }
                            //记录漏洞
                            if (message != null) {
                                results.add(new RequestResponseWrapper(response, message, (String) host));
                            }
                        } catch (UnsupportedEncodingException e) {
                            throw new RuntimeException(e);
                        }
                    }
                }
            }
        }

        return results;
    }
    //主动扫描
    public  static  List<RequestResponseWrapper> hostScan(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,String host) {

        List<RequestResponseWrapper> results = new ArrayList<>();
//        String message = null;

        String hostName = host;
        int port = 443; // 默认HTTPS端口
        boolean useHttps = true; // 默认使用HTTPS
        String[] poc = {
                "GET / HTTP/1.1",
                "GET /?acl HTTP/1.1",
                "GET /?policy HTTP/1.1",
                "PUT /123.html HTTP/1.1"
        };
        // 存储拼接后的请求
        List<String> newRequests = new ArrayList<>();
        URL urls = null;
        try {
            urls = new URL(host);
            String basePath = urls.getPath();

            // 提取路径层级
            List<String> paths = extractPaths(basePath);
            for (String request : poc) {
                // 分割请求行以提取方法和路径
                String[] parts = request.split(" ");
                String method = parts[0];
                String originalPath = parts[1];
                String protocol = parts[2];
                for (String path : paths) {
                    // 如果路径是根路径（"/"），直接使用path
                    if ("/".equals(originalPath)) {
                        // 如果path为空，则手动添加根路径斜杠
                        String formattedPath = path.isEmpty() ? "/" : path;
                        newRequests.add(method + " " + formattedPath + " " + protocol);
                    } else if (originalPath.startsWith("/")) {
                        // 如果路径是以斜杠开头，则直接拼接
                        newRequests.add(method + " " + path + originalPath + " " + protocol);
                    } else {
                        // 如果路径不是以斜杠开头，则假设它是相对路径，需要拼接
                        newRequests.add(method + " " + path + "/" + originalPath + " " + protocol);
                    }
                }
            }
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }

        try {
            URL url = new URL(host);
            hostName = url.getHost(); // 提取纯主机名
            port = url.getPort();
            port = (port == -1) ? url.getDefaultPort() : port; // 如果端口号为-1，使用默认端口
            useHttps = "https".equalsIgnoreCase(url.getProtocol());
        } catch (MalformedURLException e) {
            // 处理非URL格式的输入
            String[] parts = host.split(":");
            if (parts.length > 1) {
                try {
                    hostName = parts[0];
                    port = Integer.parseInt(parts[1]);
                    useHttps = port == 443; // 如果端口是443，我们认为它是HTTPS
                } catch (NumberFormatException ex) {
                    throw new RuntimeException("Invalid port format in host: " + host);
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
        //扫描
        StringBuilder allMessages = new StringBuilder();
        IHttpRequestResponse finalResponse = null;  // 初始化最终响应
        String hosts=null;

        for (String newRequest : newRequests) {
            String requestString = newRequest + "\r\nHost: " + hostName + "\r\nSec-Ch-Ua-Platform: \"Windows\""
                    + "\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36\r\n"
                    + "\r\nConnection: keep-alive\r\n";
            // 添加请求体（如果有）
            String requestBody = "";
            if (newRequest.contains("PUT")) {// PUT 请求需要请求体
                requestBody = "<div style=\"display:none;\">Hidden Element</div><script>console.log('XSS Test');</script>";
            }
            byte[] requestBytes = requestString.getBytes(StandardCharsets.UTF_8);
            IRequestInfo analyzedRequest = helpers.analyzeRequest(requestBytes);
            List<String> headers = analyzedRequest.getHeaders();
            byte[] request = helpers.buildHttpMessage(headers, requestBody.getBytes(StandardCharsets.UTF_8));
            // 构建HTTP服务
            IHttpService httpService = helpers.buildHttpService(hostName, port, useHttps);
            // 发送请求并获取响应
            IHttpRequestResponse response = callbacks.makeHttpRequest(httpService, request);
            //如果响应为空
            String message = null;
            if (response != null &&  response.getResponse() != null){
            int statusCode = getStatusCode(callbacks, response.getResponse());
            byte[] response1 = response.getResponse();
                try {
                    String responseString = new String(response1, "UTF-8");
                    if (statusCode == 200  && responseString.contains("</ListBucketResult>")) {
                        message = "Bucket遍历";
                    } else if (statusCode == 404 && responseString.contains("The specified bucket does not exist")) {
                        message = "Bucket桶可接管";
                    } else if (statusCode == 200 && responseString.contains("<AccessControlPolicy>")) {
                        message = "Bucket ACL可读";
                    } else if (statusCode == 200  && responseString.contains("\"Effect\": \"allow\"")) {
                        message = "Bucket 权限策略为允许";
                    } else if (statusCode == 200 && newRequest.contains("PUT")) {
                        message = "Bucket文件上传";
                    }
                    if (message != null) {
                        results.add(new RequestResponseWrapper(response, message, hostName));
                    }
                } catch (UnsupportedEncodingException e) {
                    throw new RuntimeException(e);
                }
            }else {
                results.add(new RequestResponseWrapper(null, "Destination is unreachable", hostName));
            }
        }
        return results;
    }
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

    public static class RequestResponseWrapper {
        private IHttpRequestResponse requestResponse;
        private String message;
        private String hosts;

        public RequestResponseWrapper(IHttpRequestResponse requestResponse, String message,String hosts) {
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

    private static int getStatusCode(IBurpExtenderCallbacks callbacks,byte[] response) {
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        if (response == null || response.length == 0) {
            return -1;
        }
        String responseString = new String(response, StandardCharsets.UTF_8);
        String[] lines = responseString.split("\r\n|\r|\n", 2);
        if (lines.length > 0) {
            String statusLine = lines[0];
            String[] parts = statusLine.split("\\s+", 3);
            if (parts.length > 1) {
                try {
                    return Integer.parseInt(parts[1]);
                } catch (NumberFormatException e) {
                    stdout.println("Failed to parse status code: " + e.getMessage());
                }
            }
        }
        return -1;
    }
}
