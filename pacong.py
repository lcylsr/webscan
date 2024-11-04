import requests
from bs4 import BeautifulSoup
import re
import redis
import time
import random
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor
import threading

class SimpleCrawler:
    def __init__(self, max_depth):
        self.visited_urls = set()  # 已访问的URL
        self.extracted_urls = set()  # 提取的URL
        self.url_pattern = re.compile(r'https?://[^\s]+')
        self.redis_client = redis.StrictRedis(host='localhost', port=6379, db=0)
        self.max_depth = max_depth
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0'
        })
        self.lock = threading.Lock()  # 线程锁

    def is_valid_url(self, url):
        """ 验证URL格式 """
        return bool(self.url_pattern.match(url))

    def normalize_url(self, url, base_url):
        """ 规范化URL，确保可以访问 """
        return urljoin(base_url, url)

    def extract_urls(self, html, base_url):
        """ 从html中提取所有URL """
        soup = BeautifulSoup(html, 'html.parser')
        urls = {self.normalize_url(link['href'], base_url) for link in soup.find_all('a', href=True)}
        return {url for url in urls if self.is_valid_url(url)}

    def crawl(self, start_url, current_depth):
        """ 爬取指定URL，深度优先或广度优先 """
        if current_depth > self.max_depth or not self.is_valid_url(start_url):
            return

        with self.lock:
            if start_url in self.visited_urls:
                return
            self.visited_urls.add(start_url)

        try:
            response = self.session.get(start_url, timeout=10)
            response.raise_for_status()  # 检查响应状态码，如果不是200就抛出异常

            print(f"正在爬取: {start_url}")
            html = response.text
            extracted_urls = self.extract_urls(html, start_url)
            print("提取的 URL:", extracted_urls)

            with self.lock:
                self.extracted_urls.update(extracted_urls)
                if self.extracted_urls:
                    self.redis_client.sadd('crawled_urls', *self.extracted_urls)

            # 爬取提取到的每个URL（深度优先）
            with ThreadPoolExecutor(max_workers=5) as executor:  # 控制并发
                for url in extracted_urls:
                    executor.submit(self.crawl, url, current_depth + 1)
                    time.sleep(random.uniform(1, 3))  # 每次提交任务后随机休眠

        except requests.HTTPError as e:
            print(f"HTTP错误: {e} (URL: {start_url})")
        except requests.RequestException as e:
            print(f"请求错误: {e} (URL: {start_url})")
        except Exception as e:
            print(f"出现错误: {e} (URL: {start_url})")

    def save_to_file(self, filename):
        """ 将去重的URL保存到文件中 """
        with open(filename, 'w', encoding='utf-8') as f:
            f.writelines(f"{url}\n" for url in self.extracted_urls)

if __name__ == "__main__":
    start_url = "https://pikachu.bachang.org/vul/sqli/sqli_id.php"
    max_depth = 2

    crawler = SimpleCrawler(max_depth)

    if crawler.is_valid_url(start_url):
        crawler.crawl(start_url, 1)  # 从深度1开始爬取
        crawler.save_to_file('crawled_urls.txt')  # 保存结果到文件
    else:
        print("无效的URL地址")
