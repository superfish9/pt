## 信息收集

### 主机信息收集

#### 敏感目录文件收集

- 目录爆破
  - [字典](https://github.com/rootphantomer/Blasting_dictionary)
  - BurpSuite 

- 搜索引擎语法
  - [Google Hack](https://support.google.com/websearch/answer/2466433?hl=en)
  - [DuckDuckgo](https://duck.co/help/results/syntax)  可搜索微博、人人网等屏蔽了主流搜索引擎的网站
  - [Bing](https://help.bingads.microsoft.com/#apex/18/zh-CHS/10001/-1)

- js文件泄漏后台或接口信息
  - 快捷搜索第三方资源
    - [findjs](./%E4%BF%A1%E6%81%AF%E6%94%B6%E9%9B%86/findjs.js)

- robots.txt

- 目录可访问（ autoindex ）

- iis短文件名
  - [IIS-ShortName-Scanner](https://github.com/irsdl/IIS-ShortName-Scanner)

- 爬虫
  - BurpSuite Site map

- 编辑器
  - [编辑器利用总结.pdf](./%E4%BF%A1%E6%81%AF%E6%94%B6%E9%9B%86/%E7%BC%96%E8%BE%91%E5%99%A8%E5%88%A9%E7%94%A8%E6%80%BB%E7%BB%93.pdf)

- 源码泄漏

  - [常见Web源码泄露总结](https://www.secpulse.com/archives/55286.html)


- Git 代码泄露
    - [Githack](https://github.com/lijiejie/GitHack)
- SVN 代码泄露
    - [svnHack](https://github.com/callmefeifei/SvnHack)
- 备份文件
    - xxx.php.swp
    - \*www*.(zip|tar.gz|rar|7z)
- xxx.php.bak
    - API
      - [Aliyun](https://developer.aliyun.com/api)
      - [Amazon AWS](https://docs.amazonaws.cn/apigateway/latest/developerguide/welcome.html)
      - [Google Cloud](https://cloud.google.com/apis/)
      - [Tencent Cloud](https://cloud.tencent.com/document/api)
      - [微信公众号](https://mp.weixin.qq.com/wiki?t=resource/res_main&id=mp1421140183)

- 探针文件

#### 端口扫描及Banner识别

- 本地工具
  - [nmap](https://nmap.org/)
  - [Metasploit](https://github.com/rapid7/metasploit-framework) auxiliary/scanner/portscan/tcp
  - [zmap](https://zmap.io/)
  - [masscan](https://github.com/robertdavidgraham/masscan)
- 第三方平台
  - [zoomeye](https://www.zoomeye.org/)
  - [shodan](https://www.shodan.io/)
  - [fofa](https://fofa.so/)
  - [微步在线](https://x.threatbook.cn/)

#### WEB组件识别

- 平台识别
  - [云悉](http://www.yunsee.cn/)
  - [shodan](https://www.shodan.io/)
- 浏览器插件
  - [Wappalyzer](https://www.wappalyzer.com/)
- http://whatweb.bugscaner.com

#### 漏洞信息收集

- 手动挖掘
- 扫描器
  - AWVS WEB 漏洞扫描器
  - [Nussus](https://www.tenable.com/downloads/nessus) 主机漏洞扫描器

#### WAF测试

- [Tor](https://www.torproject.org/)	防止 IP 被 ban
- 特殊的 HTTP 请求
  - 同时包含 GET 与 POST
  - chunked 请求
  - HTTP 参数污染
  - 超大的请求包
  - 文件上传类型的参数传播
- WAF 规则漏洞
  - 白名单
  - 控制字符拦截
  - 规则库不完全
  - 通配符绕过
  - 字符串分割
- 协议
  - SSL Cipher 导致绕过
    - [abuse-ssl-bypass-waf](https://github.com/LandGrey/abuse-ssl-bypass-waf)
  - Keeplive 绕过
    - BurpSuite 
- Fuzz
  - [wfuzz](https://github.com/xmendez/wfuzz)
  - [fuzzdb](https://github.com/xmendez/wfuzz)

#### C 段 IP 信息

- 与主机信息收集相同，侧重点应放在漏洞信息收集上。

#### IP 反查域名

- https://dns.aizhan.com
- https://viewdns.info
- http://www.114best.com/ip/114.aspx?w=IP

#### 目标网络结构

- tracert

#### Nday 信息收集

- [exploit-db](https://www.exploit-db.com)
- [seebug](https://www.seebug.org)
- 乌云镜像站

### 域名信息收集

#### 域名信息

- 域名注册人
- DNS 提供商
- 域名到期时间
- txt 记录中的 spf 字段（邮件伪造）
- MX 记录中邮件服务器地址
- 工具
  - whois
  - nslookup
  - dig

#### 子域名收集

- 本地工具
  - [dnsenum](https://github.com/fwaeytens/dnsenum)
  - [subDomainsBrute](https://github.com/lijiejie/subDomainsBrute)
  - [wydomain](https://github.com/ring04h/wydomain)
- 搜索引擎
  - [Google Hack](https://support.google.com/websearch/answer/2466433?hl=en)
  - [DuckDuckgo](https://duck.co/help/results/syntax)  可搜索微博、人人网等屏蔽了主流搜索引擎的网站
  - [Bing](https://help.bingads.microsoft.com/#apex/18/zh-CHS/10001/-1)
- 第三方平台
  - [微步在线](https://x.threatbook.cn/)
  - [站长之家](http://i.links.cn/subdomain/)
- DNS域传送
  - nslookup
  - dig
  - nmap
- C/S程序逆向及抓包
  - 逆向平台依据语言与平台来选择，移动端建议使用 [mobsf](https://github.com/MobSF/Mobile-Security-Framework-MobSF) ，可以半自动化的发现链接与 IP ，抓包可以使用 wireshark 抓取所有流量来进行筛选。
- 网站爬虫
  - BurpSuite Site map
- 第三方代码平台
  - [github](https://github.com)
  - [gitlab](https://gitlab.com)

#### CDN寻找真实IP

- [CDN 2021 完全攻击指南（一）](https://www.anquanke.com/post/id/227818)


- 子域名未设置泛解析，检测未添加 CDN 的子域名 *详见子域名收集
- 网站探针
- 网站根页面响应内容中存在指纹
  - [zoomeye](https://www.zoomeye.org)
  - [shodan](https://www.shodan.io/)
  - [fofa](https://fofa.so)
- 网站存在 SSRF 或者 XXE 漏洞
  - [ceye](http://ceye.io)
- CDN 配置有特定证书
  - [censys](http://censys.io)
- 网站存在邮件功能
  - 查询 eml 文件中邮件节点 IP
- 自建 CDN 机房且未做国外加速
  - [站长之家](http://ping.chinaz.com/)
  - [奇云测](http://ce.cloud.360.cn)
- DNS 解析记录查询
  - [微步在线](https://x.threatbook.cn/)
  - [viewdns](https://viewdns.info/)
- 添加 Host 做全网扫描
  - [zmap](https://zmap.io/)
- F5 负载均衡查看内网 IP
  - http://blog.51cto.com/showing/1841564
- 组件可能存在安全问题 [HTTP 盲攻击](./Papers/HTTP盲攻击的几种思路v2.0.pdf)
  - [ceye](http://ceye.io)
  - [Collaborator Everywhere](https://github.com/PortSwigger/collaborator-everywhere)
- C/S 程序逆向或抓包
- *采用第三方 CDN 可用肉鸡耗尽 CDN 资源后获取真实 IP
- *社工

### 目标信息收集

#### 现场收集

- 物理安全
  - 机房/办公区是否可以随意进出 
  - 员工PC及服务器是否可控制，是否可插入 badUSB
  - 门禁系统是否存在安全问题
- 无线安全/RF频率扫描
  - [aircrack-ng](https://www.aircrack-ng.org/)
  - 万能钥匙
- 其他信息
  - 目标所使用的系统版本
  - 目标使用的杀毒软件
  - 目标使用的浏览器
  - 办公区黑板上是否留有敏感信息
  - 垃圾桶或办公桌上是否存在敏感文件
  - 内部使用的平台
  - 常用的邮件格式体
  - oa 及其他平台用户名格式
  - 企业邮件用户名命名规则
  - 目标网络中的其他资产
    - 摄像头
    - 打印机 
    - 门禁系统
    - 条形码扫描器

#### 非现场收集

- 员工信息收集
  - 搜索引擎
    - [theHarvester](https://github.com/laramies/theHarvester)
  - 招聘网站
    - [百度招聘](https://zhaopin.baidu.com) 爬取了市面上的绝大多数招聘网站的信息
  - [Duckduckgo](https://duckduckgo.com/) 可以搜索微博、人人网等禁止主流搜索引擎爬虫爬取的网站
  - QQ、微信、 telegram 等即时聊天群
  - [国家企业信用信息公示系统](http://www.gsxt.gov.cn/index.html)
  - [天眼查](https://www.tianyancha.com/)
  - [微步在线](http://x.threatbook.cn)
- 敏感文件收集
  - 第三方代码平台	#大部分可用 Google 进行搜索，但需要将代码 clone 到本地后才可以查看 commit history
    - [github](https://github.com/)
    - [gitlab](https://gitlab.com/)
  - 网盘搜索
    - http://www.pansoso.com/
    - https://www.lingfengyun.com/
  - 搜索引擎
  - QQ、微信、 telegram 等即时聊天群
- 邮件系统信息收集
  - 目标使用的邮件系统供应商
  - 目标使用的邮件系统
  - 邮件服务器（域名 MX 记录）
- 其他信息
  - XSS 盲打后台获取后台地址

#### 其他

- 社工库
- 支付宝查询姓名
- 微博、抖音、微信、QQ搜索手机号
- 社工

## 漏洞挖掘与利用

### Web应用

- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [“冰蝎”动态二进制加密网站管理客户端](https://github.com/rebeyond/Behinder)
- PortSwigger知识点及实验环境
  - [All learning materials](https://portswigger.net/web-security/all-materials)
  - [All labs](https://portswigger.net/web-security/all-labs)

#### Server端

##### 架构

- Path处理
  - [Take Your Path Normalization Off And Pop 0days Out! - Orange Tsai](https://www.youtube.com/watch?reload=9&v=R_4edL7YDcg)
  - [web服务器分层架构的资源文件映射安全以及在J2EE应用中的利用与危害](https://juejin.im/post/5aa1142cf265da238f121fa4)
  - [Attacking Secondary Contexts in Web Applications](./Web%E5%BA%94%E7%94%A8/Server%E7%AB%AF/Attacking Secondary Contexts in Web Applications.pdf)
  - [Middleware, middleware everywhere - and lots of misconfigurations to fix](https://labs.detectify.com/2021/02/18/middleware-middleware-everywhere-and-lots-of-misconfigurations-to-fix/)


- HTTP盲攻击
  - [HTTP盲攻击的几种思路最终版](./Web%E5%BA%94%E7%94%A8/Server%E7%AB%AF/HTTP%E7%9B%B2%E6%94%BB%E5%87%BB%E7%9A%84%E5%87%A0%E7%A7%8D%E6%80%9D%E8%B7%AF%E6%9C%80%E7%BB%88%E7%89%88.pdf)
  - [Cracking the Lens: Targeting HTTP's Hidden Attack-Surface](https://portswigger.net/blog/cracking-the-lens-targeting-https-hidden-attack-surface)
  - [collaborator-everywhere](https://github.com/PortSwigger/collaborator-everywhere)
- HTTP请求走私
  - [HTTP Desync Attacks: Request Smuggling Reborn](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
  - [HTTP Desync Attacks: what happened next](https://portswigger.net/research/http-desync-attacks-what-happened-next)
  - [Breaking the chains on HTTP Request Smuggler](https://portswigger.net/research/breaking-the-chains-on-http-request-smuggler)
  - [h2c Smuggling: Request Smuggling Via HTTP/2 Cleartext(h2c)](h2c Smuggling: Request Smuggling Via HTTP/2 Cleartext(h2c))
- Web缓存投毒
  - [Practical Web Cache Poisoning](https://portswigger.net/research/practical-web-cache-poisoning)
  - [Bypassing Web Cache Poisoning Countermeasures](https://portswigger.net/research/bypassing-web-cache-poisoning-countermeasures)
  - [Web Cache Entanglement: Novel Pathways to Poisoning](https://portswigger.net/research/web-cache-entanglement)
- Web缓存欺骗
  - [详解Web缓存欺骗攻击](./Web%E5%BA%94%E7%94%A8/Server%E7%AB%AF/%E8%AF%A6%E8%A7%A3Web%E7%BC%93%E5%AD%98%E6%AC%BA%E9%AA%97%E6%94%BB%E5%87%BB.pdf)
  - [Web Cache Deception Attack](https://omergil.blogspot.com/2017/02/web-cache-deception-attack.html)
- 相对路径覆盖
  - [RPO攻击方式的探究](https://www.freebuf.com/articles/web/166731.html)
  - [Detecting and exploiting path-relative stylesheet import (PRSSI) vulnerabilities](https://portswigger.net/research/detecting-and-exploiting-path-relative-stylesheet-import-prssi-vulnerabilities)
- CDN
  - [CDN安全，DDos攻击](https://blog.csdn.net/sinat_38631725/article/details/107160761)
  - [CDN安全-论文复现-RangeAmp攻击](https://www.anquanke.com/post/id/235832)

##### 组件

- [Web中间件常见漏洞总结](https://www.freebuf.com/articles/web/192063.html)


- [解析漏洞总结](https://www.secpulse.com/archives/3750.html)

- Nginx
  - [Nginx不安全配置可能导致的安全漏洞](https://www.freebuf.com/articles/web/149761.html)
  - CVE-2016-1247（本地提权）

- Apache
  - CVE-2019-0211（本地提权）

- IIS
  - IIS PUT
  - CVE-2017-7269（RCE）

- F5

  - CVE-2021-22986（RCE）


- CVE-2020-5902（RCE，[scanv-poc](https://gitlab.com/sfish/pt/-/blob/master/Web%E5%BA%94%E7%94%A8/Server%E7%AB%AF/F5/_f5_big_ip_rce_cve_2020_5902.py)）

##### 基础库

- ImageMagick

  - [imagemagick 邂逅 getimagesize 的那点事儿](https://paper.seebug.org/969/)
  - CVE-2019-6116（GhostScript沙箱绕过 RCE）
  - CVE-2018-17961（GhostScript沙箱绕过 RCE）
  - [ghostscript: multiple critical vulnerabilities, including remote command execution](https://bugs.chromium.org/p/project-zero/issues/detail?id=1640)
  - CVE-2016-5118（命令注入 RCE）
  - CVE-2016-3714（[“ImageTragick”漏洞](https://imagetragick.com) RCE）
- FFmpeg
  - CVE-2017-9993（任意文件读取）
  - CVE-2016-1897/8（SSRF & 任意文件读取）

##### 应用

- Zabbix
  - 弱口令
  - [Zabbix 2.2.x, 3.0.x latest.php SQL注入漏洞](https://blog.csdn.net/cd_xuyue/article/details/52240944)
  - [Zabbix 2.2.x, 3.0.x jsrpc.php SQL注入漏洞](http://blog.qingteng.cn/2016/08/20/zabbix-sqljsrpc-php-注入漏洞分析-（以3-0-2为例）/)
  - CVE-2014-9450（SQL注入）
  - CVE-2013-5743（SQL注入）
- Nagios
  - CVE-2016-9566（本地提权）

#### Java Web

- [Java Web 漏洞生態食物鏈](http://blog.orange.tw/2016/12/java-web.html)


- [JavaWeb.png](./Web%E5%BA%94%E7%94%A8/Java%20Web/JavaWeb.png)
- [攻击Java Web应用](https://javasec.org)
- [一种新的攻击方法——Java Web表达式注入](https://blog.csdn.net/renfengmei/article/details/44754329)
  - [搜狗某系统存在远程EL表达式注入漏洞(命令执行)](http://www.anquan.us/static/bugs/wooyun-2016-0195845.html)
  - [工商银行某系统存在远程EL表达式注入漏洞(命令执行)](http://www.anquan.us/static/bugs/wooyun-2016-0196160.html)
- [J2EEScan](https://github.com/ilmila/J2EEScan)
- [Java中RMI、JNDI、LDAP、JRMP、JMX、JMS那些事儿（上）](https://paper.seebug.org/1091/)
- JNDI注入
  - [us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE-wp](./Web%E5%BA%94%E7%94%A8/Java%20Web/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE-wp.pdf)
  - [深入理解JNDI注入与Java反序列化漏洞利用](https://www.freebuf.com/column/189835.html)
  - [如何绕过高版本JDK的限制进行JNDI注入](https://www.freebuf.com/column/207439.html)
  - [JAVA JNDI注入知识详解](https://paper.seebug.org/1207/)
- 反序列化
  - [ysoserial](https://github.com/frohoff/ysoserial)

##### WebServer

- [常见WebServer弱口令及getshell方法总结](https://www.cnblogs.com/shellr00t/p/5965727.html)

- [解密JBoss和Weblogic数据源连接字符串和控制台密码](http://www.vuln.cn/7068)

- Tomcat

  - [中间件安全-Tomcat安全测试概要](https://www.secpulse.com/archives/68746.html)


-   CVE-2017-12616（信息泄漏）

-   CVE-2017-12615（PUT RCE）
    - CVE-2016-8735（反序列化 RCE）
    - CVE-2016-1240（本地提权）

-   Resin（待整理）
    - 未授权访问
    - 任意文件读取
    - 目录遍历

-   WebLogic

    - CVE-2021-2109（RCE）
    - CVE-2020-14882/14883（RCE）


    - CVE-2020-13935（DoS）
    - CVE-2019-2888（XXE）
    - CVE-2019-2729（wls9-async反序列化RCE）
    - CVE-2019-2725（CNVD-C-2019-48814，wls9-async反序列化RCE，[scanv-poc](./Web%E5%BA%94%E7%94%A8/Java%20Web/WebLogic/CVE-2019-2725/scanv-CVE-2019-2725.py)）
    - CVE-2019-2647（XXE [Weblogic xxe漏洞复现及攻击痕迹分析](./Web%E5%BA%94%E7%94%A8/Java%20Web/WebLogic/CVE-2019-2647/Weblogic_xxe%E6%BC%8F%E6%B4%9E%E5%A4%8D%E7%8E%B0%E5%8F%8A%E6%94%BB%E5%87%BB%E7%97%95%E8%BF%B9%E5%88%86%E6%9E%90_CVE-2019-2647_.pdf)）
    - CVE-2018-3252（反序列化RCE）
    - CVE-2018-3246（XXE）
    - CVE-2018-2894（文件上传）
    - CVE-2017-10271（反序列化RCE）
    - CVE-2017-3506（反序列化RCE）
    - CVE-2015-4852、CVE-2016-0638、CVE-2016-3510、CVE-2017-3248、CVE-2018-2628、CVE-2018-2983、CVE-2018-3191、CVE-2018-3245、CVE-2020-2801、CVE-2020-2884（反序列化RCE via T3）
    - CVE-2014-4210（SSRF）


-   WebSphere

    - CVE-2020-4949（XXE）


    - [Java反序列化RCE](https://www.seebug.org/vuldb/ssvid-89727)
    - CVE-2014-0823（任意文件读取）

-   GlassFish
    - [任意文件读取](https://www.anquanke.com/post/id/83306)

-   JBoss
    - CVE-2017-12149（JBoss AS 6.x反序列化RCE）
    - [Java反序列化RCE（JMXInvokerServlet）](https://www.seebug.org/vuldb/ssvid-89723)
    - jmx-console未授权访问
    - [JBoss安全问题总结](http://www.vuln.cn/6300)

##### 开发框架

- [《Attacking Java Web》](https://www.inbreak.net/archives/477)

- Spring

  - [有趣的SpEL注入](https://xz.aliyun.com/t/9245)


- CVE-2018-1271（Spring MVC目录遍历）
- CVE-2018-1270（Spring Messaging RCE）
    - CVE-2018-1259（Spring Data集成XMLBeam XXE）
    - CVE-2017-8046（Spring REST Data SpEL表达式注入RCE）
    - CVE-2016-4977（Spring Security OAuth RCE）
    - [Jndi注入及Spring RCE漏洞分析](https://www.freebuf.com/vuls/115849.html)
    - CVE-2011-2730（Spring EL表达式执行RCE）
    - CVE-2010-1622（Spring MVC [DOS&RCE](https://www.inbreak.net/archives/377)）

- Struts2
    - s2-016、s2-019、s2-032、s2-037、s2-045、s2-046、s2-devmode（RCE）

##### 应用

- Jenkins

  - [Compromising Jenkins and extracting credentials](https://www.n00py.io/2017/01/compromising-jenkins-and-extracting-credentials/)
  - 未授权访问
  - CVE-2019-1003000（RCE）
  - CVE-2018-1999002（任意文件读取）
  - CVE-2018-1999001（配置文件路径改动导致管理员权限开放）
  - CVE-2017-1000353（反序列化RCE）
  - CVE-2016-9299（[Jenkins-Ldap反序列化](http://rinige.com/index.php/archives/697/)）
  - CVE-2016-0792（XStream反序列化RCE）
  - CVE-2015-8103（[Java反序列化RCE](https://www.seebug.org/vuldb/ssvid-89725)）
- ElasticSearch
  - 未授权访问
  - CVE-2015-3337（任意文件读取）
  - CVE-2015-1427（RCE）
  - CVE-2014-3120（RCE）
- Hadoop
  - [Apache Hadoop远程命令执行](https://www.secpulse.com/archives/14677.html)
  - [Hadoop Yarn REST API未授权漏洞利用挖矿分析](https://www.freebuf.com/vuls/173638.html)

##### 组件

- WxJava
  - CVE-2018-20318、CVE-2019-5312（XXE）
- Fastjson
  - [浅谈Fastjson RCE漏洞的绕过史](https://www.freebuf.com/vuls/208339.html)
  - [Fastjson反序列化漏洞史](https://paper.seebug.org/1192/)
  - [红队武器库:fastjson小于1.2.68全漏洞RCE利用exp复现](https://blog.csdn.net/god_zzZ/article/details/107122487)
  - [fastjson_rce_tool](https://github.com/Hacker-One/fastjson_rce_tool)

- Apache Shiro
  - 反序列化
    - [Apache Shiro Java反序列化漏洞分析](https://blog.knownsec.com/2016/08/apache-shiro-java/)
    - [Apache Shiro反序列化识别那些事](https://mp.weixin.qq.com/s/q5sexARASK2TI6ihnRzYjg)
    - [shiro_tool.jar](https://github.com/wyzxxz/shiro_rce)

#### PHP

- [PHP绕过open_basedir限制操作文件的方法](https://www.jb51.net/article/141767.htm)
- [Bypass_Disable_functions_Shell](https://www.cnblogs.com/hookjoy/p/10395317.html)
  - [无需 sendmail：巧用 LD_PRELOAD 突破 disable_functions](https://www.freebuf.com/articles/web/192052.html)
- [PHP FastCGI 的远程利用](http://www.voidcn.com/article/p-aqdyinaj-kh.html)
- [文件包含漏洞小结](https://www.cnblogs.com/iamstudy/articles/include_file.html)
  - [LFI_With_PHPInfo_Assitance](./pt/blob/master/Web%E5%BA%94%E7%94%A8/PHP/LFI_With_PHPInfo_Assitance.pdf)
  - [RFI绕过URL包含限制getshell](https://paper.seebug.org/923/)
  - PHP文件包含漏洞利用思路与Bypass总结手册
    - [1](https://mp.weixin.qq.com/s?__biz=MjM5MTYxNjQxOA==&mid=2652854852&idx=1&sn=0154f9bc04d0eccf7069c4a70a55edef&chksm=bd5926898a2eaf9fd700b394150a34ce46b663f8cc018015559d99517aae8cdb2d2d1c687d95&scene=21#wechat_redirect)
    - [2](https://mp.weixin.qq.com/s?__biz=MjM5MTYxNjQxOA==&mid=2652854862&idx=1&sn=cad6b970d2a7837358e1a29dc5b661b5&chksm=bd5926838a2eaf95f0f228164ee4d56455ae00ef14667eb4c3250ec63bab84aac26c407b6dcf&scene=21#wechat_redirect)
    - [3](https://mp.weixin.qq.com/s?__biz=MjM5MTYxNjQxOA==&mid=2652854950&idx=1&sn=b04867a22cdef2fb7ce7a3c6ccad2985&chksm=bd59266b8a2eaf7d99d12dc18c19929f0765cf8b461b4b54271b22657232bda9d28e69fb698e&scene=21#wechat_redirect)
    - [完结](https://mp.weixin.qq.com/s/cOJbC9bm31fH0lOahFfGYw)
- CVE-2019-11043（Nginx + php-fpm RCE）
- [PHP Object Injection](https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection)
  - [php对象注入-pop链的构造](https://www.cnblogs.com/iamstudy/articles/php_object_injection_pop_chain.html)
  - [利用phar拓展php反序列化漏洞攻击面](https://paper.seebug.org/680/)
  - [phpggc](https://github.com/ambionics/phpggc)

##### 开发框架

- ThinkPHP
  - RCE
    - [ThinkPHP5框架缺陷导致远程命令执行（POC整合帖）](https://www.cnblogs.com/ichunqiujishu/archive/2018/12/14/10118432.html)
    - [ThinkPHP 5.0.x-5.0.23、5.1.x、5.2.x 全版本远程代码执行漏洞分析](http://blog.nsfocus.net/thinkphp-full-version-rce-vulnerability-analysis/?tdsourcetag=s_pctim_aiomsg)
    - [ThinkPHP框架任意代码执行漏洞的利用及其修复方法](https://blog.csdn.net/zqsqrlqd/article/details/68923320)
  - SQL注入
    - [ThinkPHP v5.1.22 SQL注入漏洞](https://www.secfree.com/a/1028.html)
    - [Thinkphp3.2.3最新版update注入漏洞](https://paper.seebug.org/573/)
    - [框架filterExp函数过滤不严格导致SQL注入](https://xz.aliyun.com/t/58)
    - [ThinkPHP最新版本SQL注入漏洞](http://www.anquan.us/static/bugs/wooyun-2014-087731.html)
    - [ThinkPHP框架架构上存在SQL注入](https://bugs.leavesongs.com/php/thinkphp框架架构上存在sql注入/)
    - [ThinkPHP架构设计不合理极易导致SQL注入](https://www.secpulse.com/archives/29827.html)
    - [ThinkPHP一处过滤不当造成SQL注入漏洞](http://www.anquan.us/static/bugs/wooyun-2015-0100225.html)
    - [thinkphp 某处缺陷可造成sql注射](http://www.anquan.us/static/bugs/wooyun-2015-0115580.html)
    - [ThinkPHP框架特性引发的SQL注入漏洞](http://www.anquan.us/static/bugs/wooyun-2015-0150649.html)
    - [ThinkPHP 5.0版本 SQL注入漏洞分析](http://blog.nsfocus.net/thinkphp-5-0-sql/)
    - [ThinkPHP5.0.16&5.1.6最新版 SQL注入漏洞](https://www.cesafe.com/3631.html)
    - [ThinkPHP 框架SQL注入技术分析](https://www.freebuf.com/articles/web/169098.html)
  - 其他
    - [Thinkphp5.X设计缺陷泄漏数据库账户和密码](https://www.secpulse.com/archives/59127.html)
- CodeIgniter
  - [CodeIgniter框架内核设计缺陷可能导致任意代码执行](https://www.secpulse.com/archives/49197.html)
- Yii
  - [Yii Framework Search SQL Injection Vulnerability](https://www.anquanke.com/vul/id/1046085)
- Laravel
  - [LARVEL <= V8.4.2 DEBUG MODE: REMOTE CODE EXECUTION](https://www.ambionics.io/blog/laravel-debug-rce)

##### 应用

- WordPress
  - [wpscan](https://github.com/wpscanteam/wpscan)
  - [WORDPRESS后台拿WEBSHELL的2个方法](https://blog.csdn.net/hicube/article/details/6294315)


- Joomla

  - [joomscan](https://github.com/rezasp/joomscan)

- Drupal

  - CVE-2020-28948/28949（RCE/文件重写）


- CVE-2019-6340（反序列化RCE）
- CVE-2018-7600、CVE-2018-7602（RCE）
    - CVE-2017-6926（越权查看评论）
    - CVE-2017-6920（反序列化RCE）
    - [Drupal 7.x Service模块SQLI & RCE 漏洞分析](https://www.cnblogs.com/pa-pa-pa/p/6670411.html)
    - [Drupal Core Full config export 配置文件未授权下载漏洞](https://www.seebug.org/vuldb/ssvid-92436)
    - [Drupal 7.x RESTWS 模块命令执行漏洞](https://www.seebug.org/vuldb/ssvid-92174)
    - CVE-2015-7877（SQL注入）
    - CVE-2014-3704（SQL注入）



- Discuz!

  - CVE-2018-14729（[Dz! 1.5-2.5 后台RCE](https://www.anquanke.com/post/id/158270)）
  - [Discuz!X前台任意文件删除漏洞](https://www.freebuf.com/articles/system/149810.html)
  - 后台getshell

    - [Discuz X3.3 authkey生成算法的安全性漏洞和后台任意代码执行漏洞](https://www.anquanke.com/post/id/86679)
    - 后台 getshell合集（待整理）
  - SSRF利用
    - [discuz利用ssrf+缓存应用getshell漏洞分析](http://chengable.net/index.php/archives/46/)
    - Discuz! SSRF合集（待整理）
  - uc_key利用
    - [DZ论坛uc_key的利用](http://admin-yuku.lofter.com/post/1cbd1826_3d2ef01)
    - [Discuz的利用UC_KEY进行getshell](http://www.anquan.us/static/bugs/wooyun-2014-048137.html)
    - [Discuz利用UC_KEY进行前台getshell2](http://www.anquan.us/static/bugs/wooyun-2015-0137991.html)
  - SQL注入
    - [Discuz7存在一处SQL注射漏洞（无需登录即可触发）](http://www.anquan.us/static/bugs/wooyun-2014-066095.html)
    - [Discuz! 7.2的SQL注射漏洞与代码执行漏洞](http://www.anquan.us/static/bugs/wooyun-2014-068707.html)
    - [Discuz某版本SQL注射漏洞](http://www.anquan.us/static/bugs/wooyun-2014-080359.html)
    - [Discuz! X2 SQL注射漏洞](http://www.anquan.us/static/bugs/wooyun-2011-02330.html)
    - [Discuz! 7.2 插件/manyou/sources/notice.php sql注入](Discuz! 7.2 插件/manyou/sources/notice.php sql注入)


##### 组件

- PHPMailer
  - CVE-2016-10033（命令执行）

#### Python

- [Python Pickle的任意代码执行漏洞实践和Payload构造](http://www.polaris-lab.com/index.php/archives/178/)

##### 开发框架

- Django
  - [Django的Secret Key泄漏导致的命令执行实践](http://www.polaris-lab.com/index.php/archives/426/)
  - [python和django的目录遍历漏洞（任意文件读取）](http://www.lijiejie.com/python-django-directory-traversal/)
  - [Django渗透测试与代码安全漫谈（一）](./Web%E5%BA%94%E7%94%A8/Python/Django/Django%E6%B8%97%E9%80%8F%E6%B5%8B%E8%AF%95%E4%B8%8E%E4%BB%A3%E7%A0%81%E5%AE%89%E5%85%A8%E6%BC%AB%E8%B0%88_%E4%B8%80_.pdf)
  - [Django渗透测试与代码安全漫谈（二）](./Web%E5%BA%94%E7%94%A8/Python/Django/Django%E6%B8%97%E9%80%8F%E6%B5%8B%E8%AF%95%E4%B8%8E%E4%BB%A3%E7%A0%81%E5%AE%89%E5%85%A8%E6%BC%AB%E8%B0%88_%E4%BA%8C_.pdf)
- Flask

  - [乱弹Flask注入](https://www.freebuf.com/articles/web/88768.html)
  - Flask/Jinja2 SSTI
    - [探索Flask/Jinja2中的服务端模版注入（一）](https://www.freebuf.com/articles/web/98619.html)
    - [探索Flask/Jinja2中的服务端模版注入（二）](https://www.freebuf.com/articles/web/98928.html)
  - [Werkzeug - Debug Shell Command Execution(Metasploit)](https://www.anquanke.com/vul/id/1066340)


#### Ruby

##### 开发框架

- Ruby on Rails
  - CVE-2019-5418（任意文件读取）
  - CVE-2018-3760（路径穿越与任意文件读取）
  - CVE-2016-2098（RCE）
  - CVE-2016-0752（RCE）
  - CVE-2015-3224（Web Console IP 白名单绕过 RCE）
  - CVE-2013-0333（RCE [Rails PoC exploit for CVE-2013-0333](http://ronin-ruby.github.io/blog/2013/01/28/new-rails-poc.html)）
  - CVE-2013-3221（数据类型注入）
  - CVE-2013-0156（RCE）


#### Node.js

- [Node.js 模块 node-serialize 反序列化任意代码执行漏洞](https://www.seebug.org/vuldb/ssvid-92674)
- JavaScript Prototype Pollution
  - [深入理解 JavaScript Prototype 污染攻击](https://www.leavesongs.com/PENETRATION/javascript-prototype-pollution-attack.html)
  - [从一道CTF题看Node.js的prototype pollution attack](https://xz.aliyun.com/t/2802)
  - [Prototype Pollution in Kibana](https://slides.com/securitymb/prototype-pollution-in-kibana)

##### 开发框架

- Express
  - [Express黑盒安全测试](./Web%E5%BA%94%E7%94%A8/Node.js/Express/Express%E9%BB%91%E7%9B%92%E5%AE%89%E5%85%A8%E6%B5%8B%E8%AF%95.pdf)
  - CVE-2017-14849（任意文件读取）

#### 企业应用

- Zimbra
  - [A Saga of Code Executions on Zimbra](https://blog.tint0.com/2019/03/a-saga-of-code-executions-on-zimbra.html)（[Zimbra xxe+ssrf导致getshell](./Web%E5%BA%94%E7%94%A8/%E4%BC%81%E4%B8%9A%E5%BA%94%E7%94%A8/Zimbra/Zimbra_xxe+ssrf%E5%AF%BC%E8%87%B4getshell.pdf)）

- Confluence
  - CVE-2019-3396（RCE [SSTI and RCE in Confluence](./Web%E5%BA%94%E7%94%A8/%E4%BC%81%E4%B8%9A%E5%BA%94%E7%94%A8/Confluence/CVE-2019-3396/SSTI%20and%20RCE%20in%20Confluence.pdf)，[scanv-poc](./Web%E5%BA%94%E7%94%A8/%E4%BC%81%E4%B8%9A%E5%BA%94%E7%94%A8/Confluence/CVE-2019-3396/scanv-CVE-2019-3396.py)）

- Exchange

  - [渗透测试中的Exchange](https://zhuanlan.zhihu.com/p/339329927)

  - CVE-2018-8581


    - [MICROSOFT EXCHANGE漏洞分析 – CVE-2018-8581](https://0kee.360.cn/blog/microsoft-exchange-cve-2018-8581/)
    - [利用 Exchange SSRF 漏洞和 NTLM 中继沦陷域控](https://paper.seebug.org/833/)

- CVE-2020-0688（RCE）

    - [CVE-2020-0688_exchange漏洞复现](./Web%E5%BA%94%E7%94%A8/%E4%BC%81%E4%B8%9A%E5%BA%94%E7%94%A8/Exchange/CVE-2020-0688_exchange%E6%BC%8F%E6%B4%9E%E5%A4%8D%E7%8E%B0.pdf)

- CVE-2020-17144（RCE）

    - [从CVE-2020-17144看实战环境的漏洞武器化](https://mp.weixin.qq.com/s?__biz=MzI2NDk0MTM5MQ==&mid=2247483712&idx=1&sn=0b2cc3c9692f5c58a4eeb246d4b392fc&chksm=eaa5bb60ddd23276baf4cfd3fc59ca847c28f350c65ef98a17d49bc9944d653fad95dec4fd14&mpshare=1&scene=1&srcid=1209jtbQLVJIgr3VT0Ut1TM9&sharer_sharetime=1607483575995&sharer_shareid=dc9cecc79ba34e4bbb700a43a16153fd#rd)

- Proxylogon（RCE）

    - [Reproducing the Microsoft Exchange Proxylogon Exploit Chain](https://www.praetorian.com/blog/reproducing-proxylogon-exploit/)


    - [Microsoft Exchange Server CVE-2021-26855漏洞利用](https://mp.weixin.qq.com/s/iQhgQ0JkmR6pUfDxIQph1Q)
    - [Exchange攻击链CVE-2021-26855&CVE-2021-27065分析](https://blog.csdn.net/weixin_44058342/article/details/114677966)

#### 常见漏洞类型

- [接口安全道亦有道 – sm0nk](./Web%E5%BA%94%E7%94%A8/%E5%B8%B8%E8%A7%81%E6%BC%8F%E6%B4%9E%E7%B1%BB%E5%9E%8B/%E6%8E%A5%E5%8F%A3%E5%AE%89%E5%85%A8%E9%81%93%E4%BA%A6%E6%9C%89%E9%81%93___sm0nk.pdf)
- [API接口渗透测试](https://xz.aliyun.com/t/2412)

##### 未授权访问

- [未授权访问的tips](https://xz.aliyun.com/t/2320)

##### SQL注入

- [sqlmap](https://github.com/sqlmapproject/sqlmap)
- [谈一谈ORM的安全](./Web%E5%BA%94%E7%94%A8/%E5%B8%B8%E8%A7%81%E6%BC%8F%E6%B4%9E%E7%B1%BB%E5%9E%8B/SQL%E6%B3%A8%E5%85%A5/%E8%B0%88%E4%B8%80%E8%B0%88ORM%E7%9A%84%E5%AE%89%E5%85%A8.pdf)
- Bypass WAF
  - [Bypass WAF Cookbook - MayIKissYou](http://www.vuln.cn/6105)
    - [多角度对抗.WAF.的思路与实例](./Web%E5%BA%94%E7%94%A8/%E5%B8%B8%E8%A7%81%E6%BC%8F%E6%B4%9E%E7%B1%BB%E5%9E%8B/SQL%E6%B3%A8%E5%85%A5/5.%E5%A4%9A%E8%A7%92%E5%BA%A6%E5%AF%B9%E6%8A%97.WAF.%E7%9A%84%E6%80%9D%E8%B7%AF%E4%B8%8E%E5%AE%9E%E4%BE%8B.pdf)
  - [我的WafBypass之道（SQL注入篇）](https://www.secpulse.com/archives/53328.html)
- OOB
  - [隐蔽的渗出：在SQL注入中使用DNS获取数据](http://netsecurity.51cto.com/art/201503/469621.htm)
- 常见关系型数据库
  - [SQL Injection Cheat Sheet](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/)
    - [SQL注入速查表（上）](http://www.anquan.us/static/drops/tips-7840.html)
    - [SQL注入速查表（下）与Oracle注入速查表](http://www.anquan.us/static/drops/tips-8242.html)
  - Mysql
    - [Mysql注入科普](https://www.cnblogs.com/qing123/p/4443082.html)
    - [Mysql Hacking](https://github.com/nixawk/pentest-wiki/tree/master/2.Vulnerability-Assessment/Database-Assessment/mysql)
    - CVE-2016-6662、CVE-2016-6663、CVE-2016-6664（本地提权 [组合利用](https://xz.aliyun.com/t/1122)）
    - [TSec-Comprehensive analysis of the mysql client attack chain](./Web%E5%BA%94%E7%94%A8/%E5%B8%B8%E8%A7%81%E6%BC%8F%E6%B4%9E%E7%B1%BB%E5%9E%8B/SQL%E6%B3%A8%E5%85%A5/20190801-TSec-Comprehensive_analysis_of_the_mysql_client_attack_chain_%E5%85%AC%E5%BC%80%E7%89%88_.pdf)
  - PostgreSql
    - [POSTGRESQL HACK](https://github.com/nixawk/pentest-wiki/blob/master/2.Vulnerability-Assessment/Database-Assessment/postgresql/postgresql_hacking.md)
    - CVE-2019-9193
  - Sqlite
    - [SQLITE HACKING](https://github.com/nixawk/pentest-wiki/blob/master/2.Vulnerability-Assessment/Database-Assessment/sqlite/sqlite_hacking.md)
  - SQL Server
    - [MSSQL注射知识库 v 1.0](https://blog.csdn.net/weixin_33871366/article/details/87981818)
  - Oracle
    - [Hacking Oracle with Sql Injection](http://www.anquan.us/static/drops/tips-57.html)
    - CVE-2014-6577（XXE [Oracle盲注结合XXE漏洞远程获取数据](http://www.anquan.us/static/drops/papers-6035.html)）

##### NoSQL注入

- [冷门知识 — NoSQL注入知多少](https://blog.csdn.net/qq_27446553/article/details/79379481)
- [NoSQLMap](https://github.com/codingo/NoSQLMap)
- Mongodb
  - [Mongodb注入攻击](https://www.secpulse.com/archives/3278.html)
  - [Ruby-China Mongodb注入可导致盗用管理员(他人)身份发帖](https://www.secpulse.com/archives/27004.html)

##### 文件上传

- [文件上传漏洞（绕过姿势）](https://blog.csdn.net/fly_hps/article/details/80781196)
- [我的WafBypass之道（upload篇）](https://www.secpulse.com/archives/53533.html)

##### SSTI

- [Server-Side Template Injection](https://portswigger.net/blog/server-side-template-injection)
- [tplmap](https://github.com/epinna/tplmap)

##### SSRF

- [SSRF安全指北](https://mp.weixin.qq.com/s/EYVFHgNClgNGrk_92PZ90A)


- [SSRF漏洞(原理&绕过姿势)](https://www.t00ls.net/articles-41070.html)
- [利用Gopher协议拓展攻击面](https://blog.chaitin.cn/gopher-attack-surfaces/)
- [build_your_ssrf_exp_autowork--20160711](./Web%E5%BA%94%E7%94%A8/%E5%B8%B8%E8%A7%81%E6%BC%8F%E6%B4%9E%E7%B1%BB%E5%9E%8B/SSRF/build_your_ssrf_exp_autowork--20160711.pdf)
- [When TLS Hacks You](https://xz.aliyun.com/t/9177)

##### XXE

- [一篇文章带你深入理解漏洞之 XXE 漏洞](https://xz.aliyun.com/t/3357)
- [XML实体攻击：从内网探测到命令执行步步惊心-张天琪](./Web%E5%BA%94%E7%94%A8/%E5%B8%B8%E8%A7%81%E6%BC%8F%E6%B4%9E%E7%B1%BB%E5%9E%8B/XXE/5-XML%E5%AE%9E%E4%BD%93%E6%94%BB%E5%87%BB_%E4%BB%8E%E5%86%85%E7%BD%91%E6%8E%A2%E6%B5%8B%E5%88%B0%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%E6%AD%A5%E6%AD%A5%E6%83%8A%E5%BF%83-%E5%BC%A0%E5%A4%A9%E7%90%AA.pdf)
- [玩转JSON节点的Content-Type XXE攻击](https://www.secpulse.com/archives/6256.html)
- [JAVA常见的XXE漏洞写法和防御](https://blog.spoock.com/2018/10/23/java-xxe/)
- [XXEinjector](https://github.com/enjoiz/XXEinjector)

##### SSI

- [服务器端包含注入SSI分析总结](https://www.secpulse.com/archives/66934.html)

##### 自动绑定

- [浅析自动绑定漏洞](https://www.colabug.com/2017/0629/267305/)


- [自动绑定漏洞和Spring MVC](https://www.anquanke.com/post/id/86278)

##### 未授权访问

- [常见未授权访问漏洞总结](https://xz.aliyun.com/t/6103)

##### 前端相关

- Misc

  - [HTML5 Security Cheatsheet](http://html5sec.org/)
  - [URL Hacking - 前端猥琐流](https://wooyun.js.org/drops/URL%20Hacking%20-%20前端猥琐流.html)
  - [GET来的漏洞](http://www.vuln.cn/6213)
    - [我的通行你的证](http://www.vuln.cn/6894)
    - [你上了我的账号](./Web%E5%BA%94%E7%94%A8/%E5%B8%B8%E8%A7%81%E6%BC%8F%E6%B4%9E%E7%B1%BB%E5%9E%8B/%E5%89%8D%E7%AB%AF%E7%9B%B8%E5%85%B3/Misc/%E4%BD%A0%E4%B8%8A%E4%BA%86%E6%88%91%E7%9A%84%E8%B4%A6%E5%8F%B7.pptx)
  - [JS敏感信息泄露：不容忽视的WEB漏洞](https://www.secpulse.com/archives/35877.html)
    - [信息收集很重要](./Web%E5%BA%94%E7%94%A8/%E5%B8%B8%E8%A7%81%E6%BC%8F%E6%B4%9E%E7%B1%BB%E5%9E%8B/%E5%89%8D%E7%AB%AF%E7%9B%B8%E5%85%B3/Misc/%E4%BF%A1%E6%81%AF%E6%94%B6%E9%9B%86%E5%BE%88%E9%87%8D%E8%A6%81.pdf)
- [跨域方法总结](https://xz.aliyun.com/t/224)
  - JSONP
    - [JSONP安全攻防技术](http://blog.knownsec.com/2015/03/jsonp_security_technic/)
    - [Taking down the SSO, Account Takeover in the Websites of Kolesa due to Insecure JSONP Call](https://medium.com/bugbountywriteup/taking-down-the-sso-account-takeover-in-3-websites-of-kolesa-due-to-insecure-jsonp-call-facd79732e45)
  - CORS
    - [跨域资源共享(CORS)安全性浅析](https://www.freebuf.com/articles/web/18493.html)
    - [Exploiting CORS Misconfigurations for Bitcoins and Bounties](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
    - [高级CORS利用技术](http://www.hackdig.com/06/hack-52260.htm)
  - PostMessage
    - [对方不想说话并扔了个message](./Web%E5%BA%94%E7%94%A8/%E5%B8%B8%E8%A7%81%E6%BC%8F%E6%B4%9E%E7%B1%BB%E5%9E%8B/%E5%89%8D%E7%AB%AF%E7%9B%B8%E5%85%B3/Misc/%E5%AF%B9%E6%96%B9%E4%B8%8D%E6%83%B3%E8%AF%B4%E8%AF%9D%E5%B9%B6%E6%89%94%E4%BA%86%E4%B8%AAmessage.pptx)
    - [PostMessage跨域漏洞分析](https://www.secpulse.com/archives/56637.html)
  - WebSocket
    - [【技术分享】WebSocket漏洞与防护详解](https://www.anquanke.com/post/id/85999)
    - [黑客是如何攻击 WebSockets 和 Socket.io的](https://xz.aliyun.com/t/2572)
  - Flash
    - [Flash安全的一些总结](https://blog.csdn.net/ycpanda/article/details/17769405)
    - [flash跨域策略文件crossdomain.xml配置详解](https://www.cnblogs.com/-yan/p/4529269.html)
    - [上传文件的陷阱](http://www.mottoin.com/detail/3549.html)
      - [Flash应用安全系列[5]--QQ邮箱永久劫持漏洞](http://www.hackdig.com/?03/hack-1917.htm)
- 框架
  - [现代前端框架的信息泄露问题](https://xz.aliyun.com/t/192)
  - [前端打包编译时代来临对漏洞挖掘的影响](https://www.freebuf.com/articles/web/193230.html)
  - AngularJS
    - [XSS without HTML: Client-Side Template Injection with AngularJS](https://portswigger.net/blog/xss-without-html-client-side-template-injection-with-angularjs)
    - [AngularJS沙箱绕过：反射型XSS导致麦当劳用户密码泄露](https://www.freebuf.com/vuls/125932.html)
- XSS

  - [XSS Filter Evasion Cheat Sheet](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)
  - [find_xss.png](./Web%E5%BA%94%E7%94%A8/%E5%B8%B8%E8%A7%81%E6%BC%8F%E6%B4%9E%E7%B1%BB%E5%9E%8B/%E5%89%8D%E7%AB%AF%E7%9B%B8%E5%85%B3/XSS/find_xss.png)
    - [那些年我们一起学XSS](./Web%E5%BA%94%E7%94%A8/%E5%B8%B8%E8%A7%81%E6%BC%8F%E6%B4%9E%E7%B1%BB%E5%9E%8B/%E5%89%8D%E7%AB%AF%E7%9B%B8%E5%85%B3/XSS/%E9%82%A3%E4%BA%9B%E5%B9%B4%E6%88%91%E4%BB%AC%E4%B8%80%E8%B5%B7%E5%AD%A6XSS.pdf)
    - [先知XSS挑战赛 - L3m0n Writeup](https://mp.weixin.qq.com/s?__biz=MzI5MzY2MzM0Mw==&mid=2247484070&idx=1&sn=673e20a08d9ae6c3de60ca48110b920a&scene=21#wechat_redirect)
    - [浅析白盒安全审计中的XSS Fliter](https://www.freebuf.com/articles/web/30201.html)
    - [mXSS攻击的成因及常见种类](http://www.vuln.cn/6361)
  - 编码技巧
    - [XSS与字符编码的那些事儿 ——科普文](http://www.anquan.us/static/drops/tips-689.html)
    - [XSS和字符集的那些事儿](http://www.vuln.cn/6602)
  - CSP绕过
    - [初探CSPBypass一些细节总结](https://xz.aliyun.com/t/318)

  - 利用
    - [小松鼠的黑魔法-XSS利用](http://bobao.360.cn/learning/detail/159.html)
    - [XSS自动化入侵内网](https://www.freebuf.com/column/133411.html)
    - [常见Flash XSS攻击方式](http://www.anquan.us/static/drops/tips-2924.html)


- CSRF
  - 结合Flash
    - [Flash+Upload Csrf攻击技术](http://blog.knownsec.com/tag/flashupload-csrf/)
    - [Flash CSRF](http://www.vuln.cn/6205)
    - [使用Flash进行JSON CSRF攻击](https://www.jianshu.com/p/d063a222f5a5)
  - 结合CORS
    - [一种新型蠕虫：花瓣CORSBOT蠕虫](http://www.hackdig.com/01/hack-42979.htm)
  - 结合XSS
    - [Uber三个鸡肋漏洞的妙用](http://www.vuln.cn/6530)
  - 结合URL跳转
    - [[Uber 8k Bug] Login CSRF + Open Redirect = Account Take Over](https://ngailong.wordpress.com/2017/08/07/uber-login-csrf-open-redirect-account-takeover/)
- XSSI
  - [揭开XSSI攻击的神秘面纱](https://www.freebuf.com/articles/web/87374.html)
  - [挖洞经验|看我如何发现雅虎XSSi漏洞实现用户信息窃取](https://www.freebuf.com/articles/web/179851.html)

- DOM Clobbering
  - [DOM Clobbering strikes back](https://portswigger.net/research/dom-clobbering-strikes-back)

##### 业务逻辑

- [业务安全漏洞挖掘归纳总结](https://www.secpulse.com/archives/34540.html)
- 登陆
  - OAuth
    - [OAuth 2.0攻击方法及案例总结](https://blog.csdn.net/cd_xuyue/article/details/52084220)
  - Json Web Token
    - [Json Web Token历险记](https://zhuanlan.zhihu.com/p/37305980)
    - [JWT Tool](https://github.com/ticarpi/jwt_tool)
    - [MyJWT](https://github.com/mBouamama/MyJWT)
- 密码找回
  - [密码找回逻辑漏洞总结](http://www.anquan.us/static/drops/web-5048.html)
  - [任意用户密码重置系列](https://yangyangwithgnu.github.io/)
- 越权
  - [我的越权之道](http://www.vuln.cn/6893)
- 支付
  - [挖洞技巧：支付漏洞之总结](https://www.secpulse.com/archives/67080.html)
  - [支付漏洞总结／在线支付流程安全分析](https://blog.csdn.net/omnispace/article/details/50814408)
  - [百度安全实验室 | 支付安全不能说的那些事](https://www.leiphone.com/news/201702/8SDTdJWpOeUxlQ3h.html)
- 信息泄露
  - [挖洞技巧：信息泄露之总结](https://www.secpulse.com/archives/67123.html)

### 其他

#### Java RMI

- [JMX RMI Exploit实例](https://www.secpulse.com/archives/6203.html)
- [Java反序列化漏洞被忽略的大规模杀伤利用](http://blog.nsfocus.net/java-deserialization-vulnerability-overlooked-mass-destruction/)
- CVE-2017-3241（[反序列化RCE](https://blog.csdn.net/LeeHDsniper/article/details/71599504)）

#### Redis

- [Redis 未授权访问配合 SSH key 文件利用分析](http://blog.knownsec.com/2015/11/analysis-of-redis-unauthorized-of-expolit/)

- [Redis基于主从复制的RCE利用方式](https://paper.seebug.org/975/)

  - [redis-post-exploitation](./%E5%85%B6%E4%BB%96/Redis/15-redis-post-exploitation.pdf)
  - [redis-rce](https://github.com/Ridter/redis-rce)
  - [redis-rogue-server](https://github.com/Dliv3/redis-rogue-server)
  - [通过SSRF操作Redis主从复制写Webshell](https://www.t00ls.net/articles-56339.html)

#### AJP

- [Tomcat的8009端口AJP的利用 – mickey](http://www.vuln.cn/6523)
- CNVD-2020-10487（LFI）

#### Mongodb

- [我通过mongodb未授权访问拿下整个分片集群及其解决方案](https://www.2cto.com/article/201502/375901.html)

#### DNS

- [DNS域传送漏洞利用](https://www.waitalone.cn/dns-domain-transfer-exploits.html)

#### Rsync

- [rsync未授权访问漏洞](https://www.cnblogs.com/leixiao-/p/10227086.html)

#### Docker

- [CDK - Zero Dependency Container Penetration Toolkit](https://github.com/Xyntax/CDK)


- [Hacking_Docker_the_Easy_Way](./%E5%85%B6%E4%BB%96/Docker/Hacking_Docker_the_Easy_Way.pdf)
- [Docker安全.从入门到实战](./%E5%85%B6%E4%BB%96/Docker/Docker%E5%AE%89%E5%85%A8.%E4%BB%8E%E5%85%A5%E9%97%A8%E5%88%B0%E5%AE%9E%E6%88%98.pdf)


- [新姿势之Docker Remote API未授权访问漏洞分析和利用](http://www.anquan.us/static/drops/papers-15892.html)
  - [技术讨论|通过SSRF漏洞攻击Docker远程API获取服务器Root权限](https://www.freebuf.com/articles/web/179910.html)
- [Docker-LXC 原理与绕过](./%E5%85%B6%E4%BB%96/Docker/Docker-LXC_%E5%8E%9F%E7%90%86%E4%B8%8E%E7%BB%95%E8%BF%87.pdf)
- [红蓝对抗中的云原生漏洞挖掘及利用实录](https://mp.weixin.qq.com/s/Aq8RrH34PTkmF8lKzdY38g)
- Kubernetes

  - [K0otkit：Hack K8s in a K8s Way](https://mp.weixin.qq.com/s/H48WNRRtlJil9uLt-O9asw)
  - [攻击容器集群管理平台](https://0x0d.im/archives/attack-container-management-platform.html)
  - [kubernetes集群渗透测试](https://www.freebuf.com/news/196993.html)
  - [Advanced Lateral Movement on Kubernetes Cluster](./其他/Docker/Advanced_Lateral_Movement_on_Kubernetes_Cluster.pdf)
  - CVE-2018-1002105（k8s特权提升）
  - [kube-hunter](https://github.com/aquasecurity/kube-hunter)


