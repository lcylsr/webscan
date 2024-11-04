import logging
import hashlib
import requests
from bs4 import BeautifulSoup
import mmh3
import threading
import time
import random
from urllib.parse import urljoin, urlparse
from .payloads import (
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
    def __init__(self, size=100, num_hashes=5):
        self.size = size
        self.num_hashes = num_hashes
        self.bit_array = [0] * size

    def _hashes(self, item):
        hashes = []
        for i in range(self.num_hashes):
            hash_digest = hashlib.md5((str(i) + item).encode('utf-8')).hexdigest()
            hashes.append(int(hash_digest, 16) % self.size)
        return hashes

    def add(self, item):
        for hash_value in self._hashes(item):
            self.bit_array[hash_value] = 1

    def contains(self, item):
        return all(self.bit_array[hash_value] == 1 for hash_value in self._hashes(item))


class WebCrawler:
    """网页爬虫类，用于抓取网页并提取链接。"""

    def __init__(self, start_url, max_depth=2):
        self.start_url = start_url
        self.max_depth = max_depth
        self.bloom_filter = BloomFilter()
        self.visited = set()
        self.lock = threading.Lock()

    def normalize_url(self, url, base_url):
        """将相对链接转换为绝对链接"""
        return urljoin(base_url, url)

    def crawl(self, url, depth=0):
        """爬取网页的核心方法，优化后返回包含爬取结果的字典"""
        result = {"success": False, "visited_count": 0}
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

        logger.info(f"Crawling: {url}")
        time.sleep(random.uniform(1, 3))

        try:
            response = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
            response.raise_for_status()
            self.process_page(response.text, url, depth)
            result["success"] = True
        except requests.RequestException as e:
            logger.error(f"Error fetching {url}: {e}")
            result["reason"] = f"网络请求错误: {e}"

        return result

    def process_page(self, html, base_url, depth):
        """处理抓取的网页，提取链接并启动新的爬取线程"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            links = set()
            for a_tag in soup.find_all('a', href=True):
                link = self.normalize_url(a_tag['href'], base_url)
                if urlparse(link).netloc == urlparse(base_url).netloc:
                    links.add(link)

            # 启动新线程爬取链接
            threads = []
            for link in links:
                if not self.bloom_filter.contains(link):
                    thread = threading.Thread(target=self.crawl, args=(link, depth + 1))
                    threads.append(thread)
                    thread.start()

            # 等待所有线程完成
            for thread in threads:
                thread.join()

        except Exception as e:
            logger.error(f"Error processing page {base_url}: {e}")

class VulnerabilityScanner:
    """用于执行漏洞扫描的类，针对给定的目标URL进行多种安全测试。"""

    def __init__(self, target_url):
        self.target_url = self.validate_url(target_url)

    @staticmethod
    def validate_url(url):
        """验证并返回有效的URL。"""
        parsed_url = urlparse(url)
        if not all([parsed_url.scheme, parsed_url.netloc]):
            logger.error(f"无效的URL: {url}. 该URL必须包含协议和域名。")
            raise ValueError(f"无效的URL: {url}. 请检查URL并重试。")

        # 确保URL可访问
        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            return url
        except requests.exceptions.RequestException as e:
            logger.error(f"无效的URL: {url}. 错误: {e}")
            raise ValueError(f"无效的URL: {url}. 请检查URL并重试。")

    def perform_scan(self, scan_type):
        """根据扫描类型执行漏洞检测。"""
        results = []
        vulnerability_checks = self.get_vulnerability_checks(scan_type)

        if not vulnerability_checks:
            logger.warning(f"没有找到适合扫描类型 '{scan_type}' 的漏洞检测函数。")
            return results

        for check in vulnerability_checks:
            if check():
                results.append({'description': check.__name__, 'detail': get_vulnerability_detail(check.__name__)})
        return results

    def get_vulnerability_checks(self, scan_type):
        """获取根据扫描类型的漏洞检测函数列表。"""
        checks = {
            'quick': [self.check_sql_injection, self.check_xss],
            'deep': [
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
        results = []
        for payload in payloads:
            if test_function(payload):
                results.append(payload)
        return results

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
                return response
            except requests.RequestException as e:
                logger.error(f"请求错误: {e}, 尝试: {attempt + 1}/{retries}")
                time.sleep(2)  # 增加间隔可能帮助应对短暂的网络问题
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

    def check_exposed_api(self):
        """检查API是否暴露敏感信息。"""
        api_endpoints = [
            '/api/protected-endpoint', '/api/user/data',
            '/api/admin/logs', '/api/orders',
            '/api/settings', '/api/v1/users'
        ]
        return any(self.test_exposed_api(self.target_url + endpoint) for endpoint in api_endpoints)

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
            'password', 'secret', 'api_key', 'token',
            'credit', 'ssn', 'email', 'address',
            'user', 'profile'
        ]
        return any(keyword in response_text.lower() for keyword in sensitive_keywords)


def get_vulnerability_detail(vulnerability_name):
    """获取漏洞的详细描述。"""
    details = {
        'check_sql_injection': '攻击者可以通过修改SQL查询访问数据库。',
        'check_xss': '攻击者可以向用户呈现恶意脚本。',
        'check_directory_traversal': '允许访问不应公开的文件。',
        'check_file_upload_risk': '允许上传恶意文件。',
        'check_exposed_api': '可能导致数据泄露。',
    }
    return details.get(vulnerability_name, '未知漏洞')

