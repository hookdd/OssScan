## 项目介绍
Oss Scan 一款基于burp存储桶漏洞探测插件，针对存储桶通用漏洞进行被动扫描识别，也可以进行主动扫描。
![image](https://github.com/user-attachments/assets/2778d81e-3962-4a97-a93f-8e55220fb341)# Oss-Scan

### 显示信息
ID:编号
SourceURL：oss地址的来源
Oss：漏洞oss域名
Issue：漏洞名称
![image](https://github.com/user-attachments/assets/223620f9-5017-410c-83d9-d0a72954f2ad)

### 识别存储桶方式
1、通过返回包响应头，例如 x-oss、x-cos等信息判断为不同厂商的存储桶
2、通过正则匹配请求hosts、响应包内容
![image](https://github.com/user-attachments/assets/ce72c1eb-dbe4-4444-bff9-bf6f233d336e)

### 漏洞类型
1.存储桶遍历：
2.Bucket接管
3.任意文件上传（需要自己测试是否存在覆盖问题）
4.acl策略可读
5.存储桶解析漏洞

### 涉及厂商
阿里云、腾讯云、华为云、aws、七牛云、天翼云、京东云
