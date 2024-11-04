import requests
import re
import redis

def input_filter(url):
    """过滤输入的 URL，检查其可访问性并添加 User-Agent。"""
    try:
        # 添加 User-Agent 设置
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'}
        requests.get(url, headers=headers, timeout=5)
        requests.get(url.replace("http://", "https://"), headers=headers, timeout=5)
        return True
    except requests.RequestException as e:
        print(f"请求错误: {e}")
        return False

def get_domain_uri(url):
    """返回给定 URL 的域名 URI。"""
    return url

def get_page_links(html):
    """从 HTML 内容中提取链接。"""
    links = re.findall(r'href=["\'](.*?)["\']', html)
    return links

def process_uri(uris):
    """处理 URI 列表，过滤掉无效的文件类型。"""
    valid_uris = []
    for uri in uris:
        # 过滤出有效的 URI
        if not (uri.endswith('.pdf') or uri.endswith('.jpg') or uri.endswith('.png') or uri.endswith('.mp4')):
            valid_uris.append(uri)
    return valid_uris

def remove_duplicates(uris):
    """移除 URI 列表中的重复项。"""
    return list(set(uris))

def write_log_and_redis(uris):
    """将 URI 写入日志文件和 Redis 数据库。"""
    try:
        r = redis.Redis(host='localhost', port=6379, db=0)
        for uri in uris:
            r.lpush('crawled_uris', uri)
            with open('crawler_log.txt', 'a') as f:
                f.write(uri + '\n')
    except Exception as e:
        print(f"写入错误: {e}")

def crawler(url, depth, current_depth=0, visited=set()):
    """递归爬虫函数，爬取指定 URL 的链接并记录访问情况。"""
    if url in visited:  # 防止重复访问相同链接
        return
    if not input_filter(url):
        return
    if current_depth >= depth:
        return
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers)
        html = response.text
        links = get_page_links(html)
        valid_links = process_uri(links)
        unique_links = remove_duplicates(valid_links)
        write_log_and_redis(unique_links)
        visited.add(url)  # 记录已访问的 URL
        for link in unique_links:
            crawler(link, depth, current_depth + 1, visited)
    except requests.RequestException as e:
        print(f"爬取错误: {e}")
