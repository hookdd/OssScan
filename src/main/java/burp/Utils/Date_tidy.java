package burp.Utils;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class Date_tidy {

    //根据不同云之间的漏洞定义不同的漏洞标识
    public static final String Cloud_Alibaba ="Cloud_Alibaba";
    public static final String Cloud_TengXun = "Cloud_TengXun";
    public static final String Cloud_HuaWei = "Cloud_HuaWei";
    public static final String Cloud_AWS = "Cloud_AWS";
    public static final String Cloud_CTYUN = "Cloud_CTYUN";
    public static final String Cloud_JDCloud = "Cloud_JDCloud";
    public static final String Cloud_Qnm = "Cloud_Qnm";

    // 修改正则表达式以匹配完整的URL路径（不包括查询参数）- 限制重复次数避免ReDoS
    private static final Pattern HUAWEI_PATTERN = Pattern.compile("https?://([a-zA-Z0-9-]+\\.obs\\.[a-zA-Z0-9-.]+\\.myhuaweicloud\\.com(?:/[a-zA-Z0-9._-]{1,100}){0,10})", Pattern.CASE_INSENSITIVE);
    private static final Pattern TENCENT_PATTERN = Pattern.compile("https?://([a-zA-Z0-9-]+-[0-9]+\\.cos\\.[a-zA-Z0-9-.]+\\.myqcloud\\.com(?:/[a-zA-Z0-9._-]{1,100}){0,10})", Pattern.CASE_INSENSITIVE);
    private static final Pattern ALIBABA_PATTERN = Pattern.compile("https?://([a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+\\.aliyuncs\\.com(?:/[a-zA-Z0-9._-]{1,100}){0,10})", Pattern.CASE_INSENSITIVE);
    private static final Pattern AWS_PATTERN = Pattern.compile("https?://([a-zA-Z0-9.-]+\\.(?:s3(?:-website)?\\.?[a-zA-Z0-9.-]*\\.amazonaws\\.com(?:/[a-zA-Z0-9._-]{1,100}){0,10}))",Pattern.CASE_INSENSITIVE);
    private static final Pattern CTYUN_PATTERN = Pattern.compile("https?://([a-zA-Z0-9-]+\\.[a-zA-Z0-9-]+\\.zos\\.ctyun\\.cn(?:/[a-zA-Z0-9._-]{1,100}){0,10})",Pattern.CASE_INSENSITIVE);
    private static final Pattern JDCLOUD_PATTERN = Pattern.compile("https?://([a-zA-Z0-9-]+\\.[a-zA-Z0-9-]+\\.jcloud\\.com(?:/[a-zA-Z0-9._-]{1,100}){0,10})",Pattern.CASE_INSENSITIVE);
    private static final Pattern QNM_PATTERN = Pattern.compile("https?://([a-zA-Z0-9-]+\\.[a-zA-Z0-9.-]+\\.qnssl\\.com(?:/[a-zA-Z0-9._-]{1,100}){0,10})",Pattern.CASE_INSENSITIVE);

    // 用于匹配主机名的正则表达式（向后兼容）
    private static final Pattern HUAWEI_HOST_PATTERN = Pattern.compile("([a-zA-Z0-9-]+\\.obs\\.[a-zA-Z0-9-.]+\\.myhuaweicloud\\.com)", Pattern.CASE_INSENSITIVE);
    private static final Pattern TENCENT_HOST_PATTERN = Pattern.compile("([a-zA-Z0-9-]+-[0-9]+\\.cos\\.[a-zA-Z0-9-.]+\\.myqcloud\\.com)", Pattern.CASE_INSENSITIVE);
    private static final Pattern ALIBABA_HOST_PATTERN = Pattern.compile("([a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+\\.aliyuncs\\.com)", Pattern.CASE_INSENSITIVE);
    private static final Pattern AWS_HOST_PATTERN = Pattern.compile("([a-zA-Z0-9.-]+\\.(?:s3(?:-website)?\\.?[a-zA-Z0-9.-]*\\.amazonaws\\.com))",Pattern.CASE_INSENSITIVE);
    private static final Pattern CTYUN_HOST_PATTERN = Pattern.compile("([a-zA-Z0-9-]+\\.[a-zA-Z0-9-]+\\.zos\\.ctyun\\.cn)",Pattern.CASE_INSENSITIVE);
    private static final Pattern JDCLOUD_HOST_PATTERN = Pattern.compile("([a-zA-Z0-9-]+\\.[a-zA-Z0-9-]+\\.jcloud\\.com)",Pattern.CASE_INSENSITIVE);
    private static final Pattern QNM_HOST_PATTERN = Pattern.compile("([a-zA-Z0-9-]+\\.[a-zA-Z0-9.-]+\\.qnssl\\.com)",Pattern.CASE_INSENSITIVE);

    //合并数据
    /**
     * 合并两个Map，将source中的条目添加到target
     * @param target 目标Map（被合并的对象）
     * @param source 来源Map（提供新数据）
     */
    public static void mergeMaps(Map<String, ArrayList<String>> target,  Map<String, ArrayList<String>> source) {
        Set<String> allHosts = new HashSet<>();

        // 收集 target 中已有的所有 host
        target.forEach((key, hosts) -> allHosts.addAll(hosts));
        // 合并 source，过滤已存在的 host
        source.forEach((key, hosts) -> {
            List<String> filtered = hosts.stream()
                    .filter(host -> {
                        boolean isNew = !allHosts.contains(host);
                        if (isNew) {
                            allHosts.add(host); // 记录已合并的 host
                        }
                        return isNew;
                    })
                    .collect(Collectors.toList());
            if (!filtered.isEmpty()) {
                target.computeIfAbsent(key, k -> new ArrayList<>()).addAll(filtered);
            }
        });
    }
    public static HashMap<String, ArrayList<String>> ExtractHeaders(List<String> headers,String host) {
        HashMap<String, ArrayList<String>> Cnamehost = new HashMap<>();
        for (String header : headers) {
            String headerLower = header.toLowerCase(); // 统一转为小写
            if (headerLower.contains("x-obs")){
                Cnamehost.computeIfAbsent(Cloud_HuaWei, k -> new ArrayList<>()).add(host);
            } else if (headerLower.contains("x-cos")) {
                Cnamehost.computeIfAbsent(Cloud_TengXun, k -> new ArrayList<>()).add(host);
            } else if (headerLower.contains("x-oss")) {
                Cnamehost.computeIfAbsent(Cloud_Alibaba, k -> new ArrayList<>()).add(host);
            } else if (headerLower.contains("x-amz")) {
                Cnamehost.computeIfAbsent(Cloud_AWS, k -> new ArrayList<>()).add(host);
            } else if (headerLower.contains("x-qiniu") || headerLower.contains("x-qnm")) {
                Cnamehost.computeIfAbsent(Cloud_Qnm, k -> new ArrayList<>()).add(host);
            }
        }
        return Cnamehost;
    }
    public static HashMap<String, ArrayList<String>> extractCloudHosts(String text) {
        HashMap<String, ArrayList<String>> CouldHashMap = new HashMap<>();
        // 匹配并提取华为云 OBS (完整URL)
        Matcher huaweiObsMatcher = HUAWEI_PATTERN.matcher(text);
        while (huaweiObsMatcher.find()) {
            CouldHashMap.computeIfAbsent(Cloud_HuaWei, k -> new ArrayList<>()).add(huaweiObsMatcher.group(1));
        }
        // 匹配并提取腾讯云 COS (完整URL)
        Matcher tencentCosMatcher = TENCENT_PATTERN.matcher(text);
        while (tencentCosMatcher.find()) {
            CouldHashMap.computeIfAbsent(Cloud_TengXun, k -> new ArrayList<>()).add(tencentCosMatcher.group(1));
        }
        // 匹配并提取阿里云 OSS (完整URL)
        Matcher aliYunOssMatcher = ALIBABA_PATTERN.matcher(text);
        while (aliYunOssMatcher.find()) {
            CouldHashMap.computeIfAbsent(Cloud_Alibaba, k -> new ArrayList<>()).add(aliYunOssMatcher.group(1));
        }
        // 匹配并提取 AWS S3 (完整URL)
        Matcher awsS3Matcher = AWS_PATTERN.matcher(text);
        while (awsS3Matcher.find()) {
            CouldHashMap.computeIfAbsent(Cloud_AWS, k -> new ArrayList<>()).add(awsS3Matcher.group(1));
        }
        // 匹配并提取天翼云 (完整URL)
        Matcher ctyunMatcher = CTYUN_PATTERN.matcher(text);
        while (ctyunMatcher.find()) {
            CouldHashMap.computeIfAbsent(Cloud_CTYUN, k -> new ArrayList<>()).add(ctyunMatcher.group(1));
        }
        // 匹配并提取京东云 (完整URL)
        Matcher jdCloudMatcher = JDCLOUD_PATTERN.matcher(text);
        while (jdCloudMatcher.find()) {
            CouldHashMap.computeIfAbsent(Cloud_JDCloud, k -> new ArrayList<>()).add(jdCloudMatcher.group(1));
        }
        // 匹配并提取七牛云 (完整URL)
        Matcher qiniuMatcher = QNM_PATTERN.matcher(text);
        while (qiniuMatcher.find()) {
            CouldHashMap.computeIfAbsent(Cloud_Qnm, k -> new ArrayList<>()).add(qiniuMatcher.group(1));
        }
        
        // 如果没有匹配到完整URL，则尝试匹配主机名（向后兼容）
        if (CouldHashMap.isEmpty()) {
            // 匹配并提取华为云 OBS 主机名
            Matcher huaweiObsHostMatcher = HUAWEI_HOST_PATTERN.matcher(text);
            while (huaweiObsHostMatcher.find()) {
                CouldHashMap.computeIfAbsent(Cloud_HuaWei, k -> new ArrayList<>()).add(huaweiObsHostMatcher.group(1));
            }
            // 匹配并提取腾讯云 COS 主机名
            Matcher tencentCosHostMatcher = TENCENT_HOST_PATTERN.matcher(text);
            while (tencentCosHostMatcher.find()) {
                CouldHashMap.computeIfAbsent(Cloud_TengXun, k -> new ArrayList<>()).add(tencentCosHostMatcher.group(1));
            }
            // 匹配并提取阿里云 OSS 主机名
            Matcher aliYunOssHostMatcher = ALIBABA_HOST_PATTERN.matcher(text);
            while (aliYunOssHostMatcher.find()) {
                CouldHashMap.computeIfAbsent(Cloud_Alibaba, k -> new ArrayList<>()).add(aliYunOssHostMatcher.group(1));
            }
            // 匹配并提取 AWS S3 主机名
            Matcher awsS3HostMatcher = AWS_HOST_PATTERN.matcher(text);
            while (awsS3HostMatcher.find()) {
                CouldHashMap.computeIfAbsent(Cloud_AWS, k -> new ArrayList<>()).add(awsS3HostMatcher.group(1));
            }
            // 匹配并提取天翼云 主机名
            Matcher ctyunHostMatcher = CTYUN_HOST_PATTERN.matcher(text);
            while (ctyunHostMatcher.find()) {
                CouldHashMap.computeIfAbsent(Cloud_CTYUN, k -> new ArrayList<>()).add(ctyunHostMatcher.group(1));
            }
            // 匹配并提取京东云 主机名
            Matcher jdCloudHostMatcher = JDCLOUD_HOST_PATTERN.matcher(text);
            while (jdCloudHostMatcher.find()) {
                CouldHashMap.computeIfAbsent(Cloud_JDCloud, k -> new ArrayList<>()).add(jdCloudHostMatcher.group(1));
            }
            // 匹配并提取七牛云 主机名
            Matcher qiniuHostMatcher = QNM_HOST_PATTERN.matcher(text);
            while (qiniuHostMatcher.find()) {
                CouldHashMap.computeIfAbsent(Cloud_Qnm, k -> new ArrayList<>()).add(qiniuHostMatcher.group(1));
            }
        }
        
        return CouldHashMap;
    }
}