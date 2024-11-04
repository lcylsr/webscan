from django.shortcuts import render, get_object_or_404, redirect
from django.views.decorators.http import require_http_methods
from .models import Scan
from .tests import VulnerabilityScanner, get_vulnerability_detail, WebCrawler
from .forms import ScanForm
import logging
import re

# 设置日志记录
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def index(request):
    """渲染首页视图"""
    return render(request, 'index.html', {'active': 'index'})

@require_http_methods(['GET', 'POST'])
def webscan(request):
    """处理漏洞扫描请求并返回结果"""
    form = ScanForm(request.POST or None)  # 使用 POST 数据或 None

    if request.method == 'POST' and form.is_valid():
        target_url = form.cleaned_data['target_url'].strip()
        scan_type = form.cleaned_data['scan_type'].strip()

        error_message = validate_input(target_url, scan_type)
        if error_message:
            return render_webscan_with_error(request, form, error_message)

        return perform_scan(request, target_url, scan_type, form)

    return render(request, 'webscan/webscan.html', {
        'active': 'webscan',
        'form': form,
    })

def validate_input(target_url, scan_type):
    """验证输入有效性"""
    if not all([target_url, scan_type]):
        return '请输入有效的目标 URL 和选择扫描类型。'

    if not is_valid_url(target_url):
        return '请输入有效的URL格式。'

    valid_scan_types = ['quick', 'deep']
    if scan_type not in valid_scan_types:
        return f'无效的扫描类型，请选择 {"或".join(valid_scan_types)} 中的一个。'

    return ''

def is_valid_url(url):
    """验证URL格式的辅助函数"""
    url_pattern = re.compile(r'^(http|https)://[^\s/$.?#].[^\s]*$')
    return bool(url_pattern.match(url))


def perform_scan(request, target_url, scan_type, form):
    """执行漏洞扫描并处理结果"""
    logger.info(f"正在扫描目标: {target_url}，扫描类型: {scan_type}")

    try:
        crawler = WebCrawler(start_url=target_url)
        crawl_result = crawler.crawl(target_url)
        print(crawler.visited)  # 测试用
        print(crawl_result)  # 测试用
        if not crawl_result["success"] or crawl_result["visited_count"] == 0:
            logger.warning(f"未爬取到任何链接: {target_url}")
            return render_webscan_with_error(request, form, "未爬取到任何链接，请检查目标网址或确保该网站可访问。")

    except (ConnectionError, TimeoutError) as e:
        logger.error(f"爬取过程中发生网络错误: {str(e)}，目标网址: {target_url}")
        return render_webscan_with_error(request, form, "网络错误，请检查目标网址或网络连接。")

    except Exception as e:
        logger.error(f"爬取过程中发生其他错误: {str(e)}，目标网址: {target_url}")
        return render_webscan_with_error(request, form, "发生错误，请稍后重试。")

    try:
        scan_results = execute_vulnerability_scan(target_url, scan_type)

        if not is_valid_scan_results(scan_results):
            logger.warning(f"扫描结果无效或为空: {target_url}")
            return render_webscan_with_error(request, form, "扫描结果无效，请稍后重试。")

        scan_instance = Scan.objects.create(url=target_url, scan_type=scan_type, results=scan_results)
        logger.info(f"扫描完成: {target_url}，结果: {scan_results}")

        return redirect('webscan_detail', result_id=scan_instance.id)

    except Exception as ex:
        logger.error(f"扫描过程中发生错误 - URL: {target_url}, 错误详情: {ex}", exc_info=True)
        return render_webscan_with_error(request, form, "扫描过程中发生错误，错误原因：" + str(ex))

def execute_vulnerability_scan(target_url, scan_type):
    """执行漏洞扫描并返回结果"""
    scanner = VulnerabilityScanner(target_url)
    return scanner.perform_scan(scan_type)

def is_valid_scan_results(results):
    """验证扫描结果有效性"""
    return isinstance(results, (list, dict)) and len(results) > 0

def render_webscan_with_error(request, form, error_message):
    """渲染带有错误信息的webscan页面"""
    logger.warning(error_message)  # 记录错误信息
    return render(request, 'webscan/webscan.html', {
        'active': 'webscan',
        'form': form,
        'error_message': error_message,
    })

def webscan_detail(request, result_id):
    """渲染扫描详细信息视图"""
    scan = get_object_or_404(Scan, id=result_id)
    vulnerability_details = extract_vulnerability_details(scan.results)

    return render(request, 'webscan/webscan-detail.html', {
        'scan': scan,
        'vulnerability_details': vulnerability_details,
    })

def extract_vulnerability_details(results):
    """提取漏洞详细信息的辅助函数"""
    details = []
    for result in results:
        if isinstance(result, dict) and 'description' in result:
            description = result['description']
            detail = get_vulnerability_detail(description)
            details.append({
                'description': description,
                'detail': detail,
            })
    return details
