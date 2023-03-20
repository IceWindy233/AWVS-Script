import argparse
import json
import sys
import requests
import urllib3

# 屏蔽SSL安全警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

awvs_address = 'https://127.0.0.1:13443'
awvs_api = '1986ad8c0a5b3df4d7028d5f3c06e936c749b43eb6b9e41e5926df14eb92c8077'


# 读取文件
def read_file(file_name):
    targets = {}

    with open(file_name) as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) == 1:
                targets[parts[0]] = 10
            else:
                targets[parts[0]] = int(parts[1])

    return targets


# 选择扫描等级
def switch_profile():
    print("0)Full Scan（完全扫描） 1)High Risk Vulnerabilities（高风险漏洞） 2)Cross-site Scripting Vulnerabilities（XSS漏洞）")
    print("3)SQL Injection Vulnerabilities（SQL注入漏洞） 4)Weak Passwords（弱口令检测） 5)Crawl Only（仅爬虫） 6)Malware Scan（恶意软件扫描）")
    level = input("选择扫描等级:（默认为0）") or "0"

    options = ['Full Scan', 'High Risk Vulnerabilities', 'Cross-site Scripting Vulnerabilities',
               'SQL Injection Vulnerabilities', 'Weak Passwords', 'Crawl Only', 'Malware Scan']

    return options[int(level)]


class Awvs:
    # API
    login_api = awvs_address + '/api/v1/info'
    targets_api = awvs_address + '/api/v1/targets'
    scaner_api = awvs_address + '/api/v1/scans'

    # 请求头信息
    headers = {
        'X-Auth': awvs_api,
        'Content-type': 'application/json'
    }

    # 测试API与地址是否正确
    def __init__(self):
        try:
            login_info: dict = requests.get(url=self.login_api, headers=self.headers, verify=False).json()  # 测试信息请求返回对象
        except:
            sys.exit('awvs服务器设置错误')
        if login_info.get('message') == 'Unauthorized':
            sys.exit('API设置错误')

    # 添加目标
    def add_target(self, address, criticality):
        # 构建请求内容
        req = json.dumps({
            "address": address,
            "description": "",
            "criticality": criticality
        })

        res = requests.post(url=self.targets_api, headers=self.headers, data=req, verify=False).json()
        return res['target_id']

    # 从文件中读取批量添加目标
    def batch_add_targets(self, file):
        targets_id_list = []
        targets_list = read_file(file)
        for website, criticality in targets_list.items():
            targets_id_list.append(self.add_target(website, criticality))

        return targets_id_list

    # 删除目标
    def del_target(self, target_id):
        # 构造删除目标的url
        req_url = self.targets_api + '/' + target_id

        requests.delete(url=req_url, headers=self.headers, verify=False)

    # 删除所有目标
    def del_all_target(self):
        target_ids = self.get_targets_id_list()

        for target_id in target_ids:
            self.del_target(target_id)

    # 获得所有目标
    def get_targets_list(self):
        res = requests.get(url=self.targets_api, headers=self.headers, verify=False).json()
        return res

    # 获取所有目标的id
    def get_targets_id_list(self):
        all_target = self.get_targets_list()
        return [target['target_id'] for target in all_target['targets']]

    # 添加扫描
    def add_scaner(self, target_id, profile):
        # 扫描类型id
        profile_id = {
            "Full Scan": "11111111-1111-1111-1111-111111111111",
            "High Risk Vulnerabilities": "11111111-1111-1111-1111-111111111112",
            "Cross-site Scripting Vulnerabilities": "11111111-1111-1111-1111-111111111116",
            "SQL Injection Vulnerabilities": "11111111-1111-1111-1111-111111111113",
            "Weak Passwords": "11111111-1111-1111-1111-111111111115",
            "Crawl Only": "11111111-1111-1111-1111-111111111117",
            "Malware Scan": "11111111-1111-1111-1111-111111111120"
        }

        # 构造请求内容
        req = json.dumps({
            "target_id": target_id,
            "profile_id": profile_id[profile],
            "schedule": {
                "disable": False,
                "start_date": None,
                "time_sensitive": False
            }
        })

        res = requests.post(url=self.scaner_api, headers=self.headers, data=req, verify=False).json()
        return res


if __name__ == '__main__':
    awvs = Awvs()

    parser = argparse.ArgumentParser(description='AWVS简易脚本')
    parser.add_argument('-d', metavar='target_id', help='删除目标, 输入ALL为删除全部')
    parser.add_argument('-t', action='store_true', help='查询所有目标简略信息')
    parser.add_argument('-s', metavar='target_id', help='启动扫描目标(target_id), 输入ALL为扫描全部')
    parser.add_argument('-f', metavar='file', help='导入并扫描文件内全部地址')

    args = parser.parse_args()

    if args.d:
        if args.d.upper() == 'ALL':
            awvs.del_all_target()
        else:
            awvs.del_target(args.d)

    if args.t:
        targets_info = awvs.get_targets_list()

        # 提取出两个数组
        target_id_info = [target['target_id'] for target in targets_info['targets']]
        address_info = [target['address'] for target in targets_info['targets']]

        # 打印表头
        print("{:<35}{}".format("目标地址", "目标ID"))
        print('-' * 75)
        # 打印内容
        for address_single, target_id_single in zip(address_info, target_id_info):
            print("{:<35}{}".format(address_single, target_id_single))

    if args.s:
        option = switch_profile()

        if args.s.upper() == 'ALL':
            target_info = awvs.get_targets_id_list()
            for target_id_single in target_info:
                awvs.add_scaner(target_info, option)
        else:
            awvs.add_scaner(args.s, option)

    if args.f:
        ret = awvs.batch_add_targets(args.f)

        option = switch_profile()
        for ret_id in ret:
            awvs.add_scaner(ret_id, option)
