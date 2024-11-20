import hashlib
import logging
import socket
import time
import random
import threading
from bitarray import bitarray
from concurrent.futures import ThreadPoolExecutor
import requests
from urllib.parse import urlparse, urljoin, urlunparse
from bs4 import BeautifulSoup
from webscan.payloads import (
    SQL_INJECTION_PAYLOADS,
    XSS_PAYLOADS,
    DIRECTORY_TRAVERSAL_PAYLOADS,
    FILE_UPLOAD_PAYLOADS
)

# 设置日志记录
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class BloomFilter:
    """布隆过滤器类，用于快速判断 URL 是否已被爬取过。"""

    def __init__(self, size=1000, num_hashes=5, num_buckets=10):
        self.size = size
        self.num_hashes = num_hashes
        self.num_buckets = num_buckets
        self.bucket_size = self.size // self.num_buckets
        self.bit_array = bitarray(self.size)
        self.bit_array.setall(False)
        self.locks = [threading.Lock() for _ in range(self.num_buckets)]
        self.encoded_template = "{}".encode('utf-8')

    def _hashes(self, item):
        """生成多个哈希值。"""
        return [int(hashlib.sha256((str(i) + item).encode('utf-8')).hexdigest(), 16) % self.size for i in
                range(self.num_hashes)]

    def add(self, item):
        """将项目添加到布隆过滤器中。"""
        hash_values = self._hashes(item)
        for hash_value in hash_values:
            bucket_index = hash_value // self.bucket_size
            with self.locks[bucket_index]:
                self.bit_array[hash_value] = True

    def contains(self, item):
        """检查项目是否在布隆过滤器中。"""
        hash_values = self._hashes(item)
        for hash_value in hash_values:
            bucket_index = hash_value // self.bucket_size
            with self.locks[bucket_index]:
                if not self.bit_array[hash_value]:
                    return False
        return True


class WebCrawler:
    """网页爬虫类，用于抓取网页并提取链接。"""

    def __init__(self, start_url, max_depth=3, max_threads=10):
        self.start_url = start_url
        self.max_depth = max_depth
        self.bloom_filter = BloomFilter()
        self.visited = set()
        self.lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=max_threads)
        self.page_count = 0  # 新增用于统计页面数量的变量
        self.crawled_urls = []  # 新增，用于记录所有成功爬取的URL

    def normalize_url(self, url, base_url):
        """将相对链接转换为绝对链接。"""
        return urljoin(base_url, url)

    def crawl(self, url, depth=0):
        """爬取网页的核心方法，优化后返回包含爬取结果的字典。"""
        result = {"url": url, "depth": depth, "visited_count": 0, "success":"False","total_pages":0}

        if depth > self.max_depth or self.bloom_filter.contains(url):
            result["reason"] = "达到深度限制或已访问过"
            return result

        with self.lock:
            if url in self.visited:
                result["reason"] = "已访问过"
                return result

            self.visited.add(url)
            self.bloom_filter.add(url)
            result["visited_count"] = len(self.visited)


        logger.info(f"Crawling: {url} (Depth: {depth})")
        time.sleep(random.uniform(1, 3))

        try:
            response = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
            if response.status_code != 200:
                raise requests.RequestException(f"HTTP Error: {response.status_code}")
            response.raise_for_status()
            self.process_page(response.text, url, depth)
            result["success"] = True
            self.page_count += 1  # 成功爬取并处理页面后，页面数量加1
            self.crawled_urls.append(url)  # 将成功爬取的URL添加到列表中
        except requests.RequestException as e:
            logger.error(f"Error fetching {url}: {e}")
            result["reason"] = f"网络请求错误: {e}"

        result["total_pages"] = self.page_count  # 将页面数量添加到返回结果字典中
        return result

    def process_page(self, html, base_url, depth):
        """处理抓取的网页，提取链接并启动新的爬取线程。"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            links = {self.normalize_url(a_tag['href'], base_url) for a_tag in soup.find_all('a', href=True) if
                     urlparse(self.normalize_url(a_tag['href'], base_url)).netloc == urlparse(base_url).netloc}

            for link in links:
                if not self.bloom_filter.contains(link):
                    self.executor.submit(self.crawl, link, depth + 1)

        except Exception as e:
            logger.error(f"Error processing page {base_url}: {e}")

    def shutdown_executor(self):
        """关闭线程池"""
        self.executor.shutdown(wait=True)


def is_https_supported(domain):
    """判断域名是否支持HTTPS。"""
    try:
        # 尝试解析HTTPS的IP地址
        socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)
        return True
    except socket.error:
        return False

def add_protocol(input_str, timeout=5):
    """根据连通性判断为输入的域名或IP添加正确的协议前缀（http或https）。"""
    # 解析输入字符串，获取域名或IP
    parsed_url = urlparse(input_str)
    domain = parsed_url.netloc or parsed_url.path

    # 判断域名是否支持HTTPS
    if is_https_supported(domain):
        protocol = 'https://'
    else:
        protocol = 'http://'

    full_url = protocol + domain

    try:
        response = requests.get(full_url, timeout=timeout)
        if response.status_code == 200:
            return full_url
    except requests.RequestException as e:
        print(f"Error connecting to {full_url}: {e}")

    return None  # 如果无法确定协议，则返回None

class VulnerabilityScanner:
    """用于执行漏洞扫描的类，针对给定的目标URL进行多种安全测试。"""

    UPLOAD_RISK_KEYWORDS = [
        "error", "failed", "improper", "corrupt",
        "malicious", "virus", "warning", "unauthorized"
    ]

    def __init__(self, target_url):
        self.target_url = self.validate_url(target_url)
        self.scanned_pages = set()
        self.last_request = None
        self.last_response = None

    @staticmethod
    def validate_url(url):
        """验证并返回有效的URL。"""
        parsed_url = urlparse(url)
        if not all([parsed_url.scheme, parsed_url.netloc]):
            logger.error(f"无效的URL: {url}. 该URL必须包含协议和域名。")
            raise ValueError(f"无效的URL: {url}. 请检查URL并重试。")

        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            return url
        except requests.exceptions.RequestException as e:
            logger.error(f"网络请求错误: {e}，无效URL: {url}.")
            raise ValueError(f"无效的URL: {url}. 请检查URL并重试。")

    def perform_scan(self, scan_type, target_url, scan_id):
        """根据扫描类型执行漏洞检测。"""
        logger.info(f"开始执行漏洞扫描 - 目标网址: {target_url}, 扫描类型: {scan_type}")
        # 用于存储结果的字典，key 为 URL，value 为结果
        results = {
            'scan_id': scan_id,
            'url': target_url,
            'vulnerabilities': []
        }
        vulnerability_checks = self.get_vulnerability_checks(scan_type)

        if not vulnerability_checks:
            logger.warning(f"没有找到适合扫描类型 '{scan_type}' 的漏洞检测函数。")
            return results
        for check in vulnerability_checks:
            try:
                if check():
                    vulnerability_detail = {
                        'vulnerability_name': check.__name__,
                        'description': self.get_vulnerability_description(check.__name__),
                        'severity': self.get_vulnerability_severity(check.__name__),
                        'discovery_time': time.time(),
                        'request': self.last_request,
                        'response': {
                            'status_code':self.last_response.status_code,
                            'headers': self.last_response.headers,
                        }
                    }
                    results['vulnerabilities'].append(vulnerability_detail)
                    self.scanned_pages.add(target_url)
            except Exception as e:
                logger.error(f"执行漏洞检测 {check.__name__} 时发生异常: {e}")

        if not results['vulnerabilities']:
            logger.error(f"扫描结果为空列表，可能是扫描过程未获取到有效数据，请检查扫描工具或网络连接。")

        logger.info(f"漏洞扫描完成 - 目标网址: {target_url}, 扫描类型: {scan_type}")
        return results

    def get_scanned_pages(self):
        """获取已扫描的页面数量。"""
        return len(self.scanned_pages)

    def get_vulnerability_checks(self, scan_type):
        """获取根据扫描类型的漏洞检测函数列表。"""
        checks = {
            "quick": [self.check_sql_injection, self.check_xss],
            "deep": [
                self.check_sql_injection,
                self.check_xss,
                self.check_directory_traversal,
                self.check_file_upload_risk,
                self.check_exposed_api,
            ]
        }
        return checks.get(scan_type, [])

    def check_sql_injection(self):
        """检查 SQL 注入漏洞。"""
        return self.execute_payloads(SQL_INJECTION_PAYLOADS, self.test_payload)

    def check_xss(self):
        """检查 XSS 攻击漏洞。"""
        return self.execute_payloads(XSS_PAYLOADS, self.test_payload)

    def check_directory_traversal(self):
        """检查目录遍历漏洞。"""
        return self.execute_payloads(DIRECTORY_TRAVERSAL_PAYLOADS, self.send_request_and_check)

    def check_file_upload_risk(self):
        """检查文件上传风险漏洞。"""
        return any(self.test_file_upload(filename, content, filetype) for filename, content, filetype in FILE_UPLOAD_PAYLOADS)

    def execute_payloads(self, payloads, test_function):
        """执行有效载荷检查。"""
        return any(test_function(payload) for payload in payloads)

    def send_request_and_check(self, payload):
        """发送请求并检查是否存在敏感信息。"""
        return any(self.send_request(method, payload) for method in (requests.get, requests.post))

    def send_request(self, method, payload, param_name='input', retries=3):
        """发送HTTP请求，并实现重试机制。"""
        logger.info(f"发送请求到 {self.target_url}，有效载荷: {payload}")
        for attempt in range(retries):
            try:
                response = method(self.target_url, params={param_name: payload}, timeout=5)
                response.raise_for_status()
                self.last_request = {param_name: payload}
                self.last_response = response
                return response
            except requests.RequestException as e:
                logger.error(f"请求错误: {e}")
                time.sleep(2)
        logger.error(f"所有尝试失败: {payload}")
        return None

    def test_payload(self, payload):
        """一般载荷测试函数。"""
        for method in (requests.get, requests.post):
            response = self.send_request(method, payload)
            if response and (
                    (method == requests.get and self.check_sql_error(response)) or
                    self.check_xss_in_response(response.text, payload)
            ):
                logger.info(f"发现漏洞: {payload} via {method.__name__}")
                return True
        return False

    @staticmethod
    def check_sql_error(response):
        """检查SQL错误信息。"""
        if response is None:
            return False
        error_keywords = [
            "mysql", "sql", "database", "error", "syntax",
            "database error", "invalid query", "unrecognized",
            "warning", "fatal"
        ]
        return response.status_code == 500 or any(keyword in response.text.lower() for keyword in error_keywords)

    @staticmethod
    def check_xss_in_response(response_text, payload):
        """检查响应文本中是否包含XSS有效载荷。"""
        escaped_payloads = [
            payload.replace("<", "&lt;").replace(">", "&gt;"),
            payload.replace("'", "&#39;"),
            payload.replace('"', "&quot;")
        ]
        return any(escaped_payload in response_text for escaped_payload in escaped_payloads) or payload in response_text

    def test_file_upload(self, filename, content, filetype):
        """测试文件上传是否存在风险。"""
        upload_url = self.find_upload_url()
        if not upload_url:
            logger.error(f"未找到文件上传的URL。")
            return False

        files = {'file': (filename, content, filetype)}
        try:
            response = requests.post(upload_url, files=files, timeout=5)
            response.raise_for_status()
            return self.check_file_upload_response(response)
        except requests.RequestException as e:
            logger.error(f"文件上传请求错误: {e}")
            return False

    def find_upload_url(self):
        """查找文件上传的URL。"""
        try:
            response = requests.get(self.target_url, timeout=5)
            response.raise_for_status()  # 增加错误处理
            soup = BeautifulSoup(response.text, 'html.parser')
            upload_form = soup.find('form', {'enctype': 'multipart/form-data'})
            return upload_form.attrs.get('action') if upload_form else None
        except requests.RequestException as e:
            logger.error(f"查找文件上传URL请求错误: {e}")
            return None

    def check_file_upload_response(self, response):
        """检查文件上传后的响应是否存在风险。"""
        return response.status_code == 200 and any(keyword in response.text.lower() for keyword in self.UPLOAD_RISK_KEYWORDS)

    def check_exposed_api(self):
        """检查API是否暴露敏感信息。"""
        api_endpoints = [
            "/api/protected-endpoint", "/api/user/data",
            "/api/admin/logs", "/api/orders",
            "/api/settings", "/api/v1/users"
        ]
        return any(self.test_exposed_api(urljoin(self.target_url, endpoint)) for endpoint in api_endpoints)

    def test_exposed_api(self, endpoint):
        """测试API端点是否返回敏感信息。"""
        try:
            response = requests.get(endpoint, timeout=5)
            return response.status_code == 200 and self.is_sensitive_api_response(response.text)
        except requests.RequestException as e:
            logger.error(f"检查API端点请求错误 {endpoint}: {e}")
            return False

    @staticmethod
    def is_sensitive_api_response(response_text):
        """检查API响应内容是否包含敏感信息。"""
        sensitive_keywords = [
            "password", "secret", "api_key", "token",
            "credit", "ssn", "email", "address",
            "user", "profile"
        ]
        return any(keyword in response_text.lower() for keyword in sensitive_keywords)

    @staticmethod
    def get_vulnerability_severity(vulnerability_name):
        """根据漏洞名称判断漏洞等级。"""
        severity_map = {
            'check_sql_injection': 'high_vul',
            'check_file_upload_risk': 'high_vul',
            'check_xss': 'medium_vul',
            'check_directory_traversal': 'medium_vul',
            'check_exposed_api': 'medium_vul'
        }
        return severity_map.get(vulnerability_name, 'unknown_vul')

    @staticmethod
    def get_vulnerability_description(vulnerability_name):
        """获取漏洞的详细描述。"""
        details = {
            "check_sql_injection": "攻击者可以通过修改SQL查询访问数据库。",
            "check_xss": "攻击者可以向用户呈现恶意脚本。",
            "check_directory_traversal": "允许访问不应公开的文件。",
            "check_file_upload_risk": "允许上传恶意文件。",
            "check_exposed_api": "可能导致数据泄露。",
        }
        return details.get(vulnerability_name, "未知漏洞")

