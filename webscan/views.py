from django.utils import timezone
from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse, HttpResponse
from django.core.exceptions import ValidationError, ObjectDoesNotExist
from django.core.cache import cache
from django.db import transaction
from django.views.decorators.csrf import csrf_exempt
from .models import ScanTask, ScanTaskStatus, ScanResults
from .tests import VulnerabilityScanner, WebCrawler
from .forms import ScanForm
import logging
import re
import requests
import concurrent.futures
from functools import lru_cache
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

# 设置日志记录
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 缓存过期时间，可配置化，这里假设设置为一个默认值，单位为秒
CACHE_TIMEOUT = 60 * 5

# 更完善的验证URL格式的正则表达式（示例，可根据实际情况进一步优化）
URL_VALIDATION_REGEX = re.compile(
    r'^(https?://)?([a-zA-Z0-9.-]+(:[a-zA-Z0-9.-]+)?@)?([a-zA-Z0-9.-]+)(:\d+)?(/[a-zA-Z0-9%&=?~_.+-]+)*(/?)$'
)

def index(request):
    """渲染首页视图"""
    return render(request, 'index.html', {'active': 'index'})


def webscan(request):
    """漏洞扫描主页面的视图"""
    form = ScanForm(request.POST or None)

    if request.method == 'POST' and form.is_valid():
        target_url = form.cleaned_data['target_url'].strip()
        scan_type = form.cleaned_data['scan_type'].strip()

        try:
            validate_input(target_url, scan_type)
        except ValidationError as e:
            return render_webscan_with_error(request, form, str(e))

        return perform_scan(request, target_url, scan_type, form)

    return render(request, 'webscan/webscan.html', {
        'active': 'webscan',
        'form': form,
    })

@csrf_exempt
def get_running_scan_task_id(request):
    """获取正在运行的扫描任务ID"""
    try:
        running_task = ScanTask.objects.get(status='RUNNING')
        return JsonResponse({'scan_task_id': running_task.id})
    except ScanTask.DoesNotExist:
        return JsonResponse({'error': '没有正在运行的扫描任务'}, status=404)
    except Exception as e:
        return JsonResponse({'error': f'获取正在运行的扫描任务ID时出错: {e}'}, status=500)

def clear_running_scan_task_id(request):
    """清除正在运行的扫描任务ID"""
    request.session.pop('running_scan_task_id', None)

def render_webscan_with_error(request, form, error_message):
    """渲染带有错误信息的webscan页面"""
    logger.warning(error_message)
    return render(request, 'webscan/webscan.html', {
        'active': 'webscan',
        'form': form,
        'error_message': error_message,
    })
def validate_input(target_url, scan_type):
    """验证输入有效性"""
    if not target_url or not scan_type:
        raise ValidationError('请输入有效的目标 URL 和选择扫描类型。')

    if not is_valid_url(target_url):
        raise ValidationError('请输入有效的URL格式。')

    valid_scan_types = get_valid_scan_types()
    if scan_type not in valid_scan_types:
        raise ValidationError(f'无效的扫描类型，请选择 {"或".join(valid_scan_types)} 中的一个。')


def is_valid_url(url):
    """更完善的验证URL格式的辅助函数"""
    url_pattern = re.compile(
        r'^(https?://)?([a-zA-Z0-9.-]+(:[a-zA-Z0-9.-]+)?@)?([a-zA-Z0-9.-]+)(:\d+)?(/[a-zA-Z0-9%&=?~_.+-]+)*(/?)$')
    return bool(url_pattern.match(url))


def get_valid_scan_types():
    """从配置文件或其他可配置源获取有效地扫描类型列表"""
    from django.conf import settings
    return settings.VALID_SCAN_TYPES if hasattr(settings, 'VALID_SCAN_TYPES') else ['quick', 'deep']

def get_cache_key(scan_task_id):
    return f'scan_task_{scan_task_id}'

def set_cache_data(cache_key, cache_data):
    """设置缓存数据的辅助函数"""
    cache.set(cache_key, cache_data, timeout=CACHE_TIMEOUT)

def get_cache_data(cache_key):
    """获取缓存数据的辅助函数"""
    return cache.get(cache_key)

def clear_cache_data(cache_key):
    """清除缓存数据的辅助函数"""
    cache.delete(cache_key)

@transaction.atomic
def create_scan_task(target_url, scan_type):
    """创建扫描任务"""
    logger.info(f"创建扫描任务 - 目标网址: {target_url}, 扫描类型: {scan_type}")
    scan_task = ScanTask.objects.create(
        target_url=target_url,
        scan_type=scan_type,
        status=ScanTaskStatus.PENDING
    )

    # 缓存扫描任务信息
    cache_key = get_cache_key(scan_task.scan_id)
    cache_data = {
        'status': scan_task.status,
        'total_pages': scan_task.total_pages,
        'scanned_pages': scan_task.scanned_pages,
    }
    set_cache_data(cache_key, cache_data)

    return scan_task


def get_scan_task_status(request):
    """获取扫描任务的状态"""
    scan_task_id = request.GET.get('scan_task_id')
    if not scan_task_id:
        return JsonResponse({'success': False, 'error': '缺少scan_task_id参数'})

    cache_key = get_cache_key(scan_task_id)
    cached_data = cache.get(cache_key)

    if cached_data:
        return JsonResponse({'success': True, 'status': cached_data['status']})

    try:
        scan_task = ScanTask.objects.get(scan_id=scan_task_id)
        return JsonResponse({'success': True, 'status': scan_task.status})
    except ObjectDoesNotExist:
        return JsonResponse({'success': False, 'error': 'ScanTask not found'})

def perform_scan(request, target_url, scan_type, form):
    logger.info(f"正在扫描目标: {target_url}，扫描类型: {scan_type}")
    scan_task = create_scan_task(target_url, scan_type)

    try:
        crawl_result = crawl_target(request, target_url, scan_type, scan_task)
        crawl_urls = crawl_result.get('crawled_urls', [])

        if crawl_result is None:
            clear_cache_data(get_cache_key(scan_task.scan_id))
            return render_webscan_with_error(request, form, "爬取目标网址时发生错误，请检查目标网址或确保该网站可访问。")

        # 全面验证爬取到的URL有效性，过滤出有效的URL列表
        valid_crawl_urls = validate_crawled_urls(crawl_urls)
        if not valid_crawl_urls:
            logger.error("所有爬取到的URL均无效，请检查目标网址或网络连接等问题。")
            clear_cache_data(get_cache_key(scan_task.scan_id))
            return render_webscan_with_error(request, form, "所有爬取到的URL均无效，请检查目标网址或网络连接等问题。")

        scan_results = execute_vulnerability_scan(request, scan_task, valid_crawl_urls)

        if not is_valid_scan_results(scan_results):
            logger.error(f"扫描结果无效，具体内容为: {scan_results}")
            if isinstance(scan_results, list) and not scan_results:
                logger.error("扫描结果为空列表，可能是扫描过程未获取到有效数据，请检查扫描工具或网络连接。")
            clear_cache_data(get_cache_key(scan_task.scan_id))
            return render_webscan_with_error(request, form, "扫描结果无效，请稍后重试。")

        save_scan_results(scan_task, scan_results)
        try:
            return redirect('webscan:webscan_detail', scan_task_id=scan_task.scan_id)
        except Exception as e:
            logger.error(f"重定向到 webscan_detail 时发生错误: {e}")
            raise

    except (ConnectionError, TimeoutError) as e:
        logger.error(f"爬取过程中发生网络错误: {e}，目标网址: {target_url}")
        clear_cache_data(get_cache_key(scan_task.scan_id))
        return render_webscan_with_error(request, form, "网络错误，请检查目标网址或网络连接。")

    except Exception as e:
        logger.error(f"扫描过程中发生错误 - URL: {target_url}, 错误详情: {e}", exc_info=True)
        clear_cache_data(get_cache_key(scan_task.scan_id))
        return render_webscan_with_error(request, form, "扫描过程中发生错误，错误原因：" + str(e))

@lru_cache(maxsize=1024)
def validate_url(url):
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        return True
    except (ConnectionError, TimeoutError, requests.RequestException) as e:
        logger.warning(f"爬取到的URL {url} 无效: {e}")
        return False

def validate_crawled_urls(crawl_urls):
    return [url for url in crawl_urls if validate_url(url)]


@transaction.atomic
def crawl_target(request, target_url, scan_type, scan_task):
    """使用WebCrawler进行爬取"""
    logger.info(f"开始爬取目标网址: {target_url}")
    try:
        crawler = WebCrawler(start_url=target_url)
        crawl_results = []

        def crawl_wrapper(url, depth):
            result = crawler.crawl(url, depth)
            crawl_results.append(result)

        try:
            crawl_wrapper(target_url, 0)
        finally:
            crawler.shutdown_executor()

        # 获取准确的总页面数，使用WebCrawler实例中统计的page_count
        total_pages = crawler.page_count

        # 获取所有成功爬取的URL列表
        all_crawled_urls = crawler.crawled_urls


        # 获取ScanTask对象
        try:
            scan_task = get_object_or_404(ScanTask, scan_id=scan_task.scan_id)
            if scan_task.target_url != target_url or scan_task.scan_type != scan_type:
                logger.error(f"获取到的ScanTask对象不匹配，目标网址: {target_url}, 扫描类型: {scan_type}")
                return None
                # 可以在这里对scan_task进行一些必要的初始化或属性设置操作
        except ScanTask.DoesNotExist:
            logger.error(f"没有找到符合条件的ScanTask对象，目标网址: {target_url}, 扫描类型: {scan_type}, 扫描ID: {scan_task.scan_id}")
            return {'success': False, 'error': '没有找到符合条件的ScanTask对象'}

        # 获取唯一的scan_task对象后再进行属性设置和保存操作
        scan_task.total_pages = total_pages
        scan_task.save()

        # 更新缓存
        cache_key = get_cache_key(scan_task.scan_id)
        cache_data = {
            'status': scan_task.status,
            'scanned_pages': scan_task.scanned_pages,
            'total_pages': total_pages,
        }
        set_cache_data(cache_key, cache_data)

        logger.info(f"爬取目标网址 {target_url} 完成，总页面数量: {total_pages}")
        # 返回包含总页面数和所有爬取到的URL列表的字典
        return {
            "total_pages": total_pages,
            "crawled_urls": all_crawled_urls
        }
    except Exception as e:
        logger.error(f"爬取目标网址 {target_url} 时发生错误: {e}")
        logger.warning("未爬取到任何链接，请检查目标网址或确保该网站可访问。")

        # 返回包含错误信息的字典以便调用处更好地处理
        return {'success': False, 'error': str(e)}


@transaction.atomic
def execute_vulnerability_scan(request, scan_task, valid_crawl_urls):
    logger.info(f"开始执行漏洞扫描 - 目标网址: {scan_task.target_url}, 扫描类型: {scan_task.scan_type}")

    try:
        # 确保获取到最新的扫描任务状态（通过数据库行锁），防止并发操作导致的数据不一致问题
        scan_task = ScanTask.objects.select_for_update().get(scan_id=scan_task.scan_id)
    except ScanTask.DoesNotExist:
        logger.error(f"ScanTask not found for target URL: {scan_task.target_url}")
        return None

    try:
        scanner = VulnerabilityScanner(scan_task.target_url)

        # 更新扫描任务状态为 RUNNING，表示扫描正在进行中
        update_scan_task_status(scan_task, ScanTaskStatus.RUNNING)

        # 使用并发机制提高扫描速度
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [executor.submit(scanner.perform_scan, scan_task.scan_type, url, scan_task.scan_id) for url in valid_crawl_urls]
            scan_results = []
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result(timeout=5)  # 设置超时时间为10秒，根据实际情况调整
                    if result and is_valid_scan_results([result]):  # 验证单个结果是否有效
                        scan_results.append(result)
                    else:
                        logger.error(f"扫描URL对应的结果无效，不存入结果列表: {result}")
                except concurrent.futures.TimeoutError:
                    logger.error(f"扫描URL {result.url} 超时")
                except Exception as e:
                    logger.error(f"扫描URL对应的任务出现异常: {e}")

        # if not scan_results:
        #     logger.error(f"扫描结果为空列表，可能是扫描过程未获取到有效数据，请检查扫描工具或网络连接。")
        #     update_scan_task_status(scan_task, ScanTaskStatus.FAILED)
        #     return None

        scanned_pages = len(valid_crawl_urls)

        # 更新扫描任务的已扫描页面数量以及状态为 COMPLETED，表示扫描已完成
        update_scan_task_info(scan_task, scanned_pages, ScanTaskStatus.COMPLETED)

        # 将验证后的扫描结果存入缓存数据库
        update_scan_task_cache(scan_task)

        logger.info(f"漏洞扫描完成 - 目标网址: {scan_task.target_url}, 扫描类型: {scan_task.scan_type}")
        return scan_results

    except ObjectDoesNotExist:
        logger.error(f"ScanTask not found for target URL: {scan_task.target_url}")
        return None
    except Exception as e:
        logger.error(f"执行漏洞扫描时发生错误 - 目标网址: {scan_task.target_url}, 扫描类型: {scan_task.scan_type}, 错误详情: {e}", exc_info=True)
        # 更新扫描任务状态为 FAILED，表示扫描出现错误
        update_scan_task_status(scan_task, ScanTaskStatus.FAILED)

        # 更新与扫描任务相关的缓存信息，反映当前错误状态
        update_scan_task_cache(scan_task)

        return None



def update_scan_task_status(scan_task, new_status):
    """
    更新扫描任务的状态，并保存到数据库
    """
    scan_task.status = new_status
    scan_task.save()


def update_scan_task_info(scan_task, scanned_pages, new_status):
    """
    更新扫描任务的已扫描页面数量以及状态，并保存到数据库
    """
    scan_task.scanned_pages = scanned_pages
    scan_task.status = new_status
    scan_task.save()


def update_scan_task_cache(scan_task):
    """
    更新与扫描任务相关的缓存信息，包含状态、总页面数、已扫描页面数等关键数据
    """
    cache_key = get_cache_key(scan_task.scan_id)
    cache_data = {
        'status': scan_task.status,
        'total_pages': scan_task.total_pages,
        'scanned_pages': scan_task.scanned_pages,
    }
    set_cache_data(cache_key, cache_data)


def is_valid_scan_results(results):
    """
    验证扫描结果的有效性，确保结果符合预期的结构和内容。
    :param results: 扫描结果，期待为一个列表，每个元素是一个包含 URL 和漏洞列表的字典
    :return: 如果结果有效返回 True，否则返回 False
    """
    if not isinstance(results, list) or not results:
        logger.error(f"扫描结果类型无效: {type(results)}")
        return False

    required_keys = ['scan_id', 'url', 'vulnerabilities']
    vulnerability_required_keys = ['vulnerability_name', 'description', 'severity', 'request', 'response', 'discovery_time']
    valid_severity_values = ['low_vul', 'medium_vul', 'high_vul', 'unknown_vul']

    for result in results:
        if not isinstance(result, dict):
            logger.error("扫描结果项不是字典类型")
            return False

        if not set(required_keys).issubset(result.keys()):
            logger.error(f"扫描结果项缺少必需的字段: {set(required_keys) - set(result.keys())}")
            return False

        if not isinstance(result['url'], str):
            logger.error("结果中 'url' 字段类型不合法")
            return False

        if not isinstance(result['vulnerabilities'], list):
            logger.error("结果中 'vulnerabilities' 字段类型不合法")
            return False

        for vulnerability in result['vulnerabilities']:
            if not isinstance(vulnerability, dict):
                logger.error("漏洞项不是字典类型")
                return False

            if not set(vulnerability_required_keys).issubset(vulnerability.keys()):
                logger.error(f"漏洞项缺少必需的字段: {set(vulnerability_required_keys) - set(vulnerability.keys())}")
                return False

            if vulnerability['severity'] not in valid_severity_values:
                logger.error(f"无效的严重性值: {vulnerability['severity']}")
                return False

            # 检查请求和响应的格式
            if not isinstance(vulnerability['request'], dict):
                logger.error("请求格式不正确")
                return False

            if not isinstance(vulnerability['response'], dict):
                logger.error("响应格式不正确")
                return False

            # 进一步验证请求和响应字典中的内容
            request_keys = ['input']
            response_keys = ['status_code']

            if not set(request_keys).issubset(vulnerability['request'].keys()):
                logger.error(f"请求字典缺少必需的字段: {set(request_keys) - set(vulnerability['request'].keys())}")
                return False

            if not set(response_keys).issubset(vulnerability['response'].keys()):
                logger.error(f"响应字典缺少必需的字段: {set(response_keys) - set(vulnerability['response'].keys())}")
                return False

    return True


@transaction.atomic
def save_scan_results(scan_task, scan_results):
    """将扫描结果存入数据库"""
    try:
        scan_task_instance = ScanTask.objects.select_for_update().get(scan_id=scan_task.scan_id)
        scan_result_instances = []

        for result in scan_results:
            logger.info(f"保存扫描结果: {result}")

            # 检查 result 是否为字典类型
            if not isinstance(result, dict):
                logger.error(f"扫描结果类型错误: {result} 不是字典类型")
                continue

            # 更新 ScanTask 实例
            scan_task_instance.target_url = result.get('url', scan_task_instance.target_url)
            scan_task_instance.status = ScanTaskStatus.COMPLETED
            scan_task_instance.completed_at = timezone.now()

            # 统计漏洞数量
            for vuln in result.get('vulnerabilities', []):
                severity = vuln.get('severity')
                if severity == 'high_vul':
                    scan_task_instance.high_vulns += 1
                elif severity == 'medium_vul':
                    scan_task_instance.medium_vulns += 1
                elif severity == 'low_vul':
                    scan_task_instance.low_vulns += 1

            scan_task_instance.total_vulns = (scan_task_instance.high_vulns +
                                              scan_task_instance.medium_vulns +
                                              scan_task_instance.low_vulns)

            # 保存漏洞信息
            for vuln in result.get('vulnerabilities', []):
                scan_result_instances.append(ScanResults(
                    scan_id=scan_task_instance, # 传递 ScanTask 实例
                    url=result.get('url'),
                    vulnerability_name=vuln.get('vulnerability_name'),
                    severity=vuln.get('severity'),
                    description=vuln.get('description'),
                    discovery_time=timezone.datetime.fromtimestamp(vuln.get('discovery_time')),
                    request_input=vuln.get('request', {}).get('input'),
                    response_status_code=vuln.get('response', {}).get('status_code')
                ))

        # 批量创建 ScanResults 实例
        ScanResults.objects.bulk_create(scan_result_instances)
        scan_task_instance.save()

        # 更新缓存
        cache_key = get_cache_key(scan_task.scan_id)
        cache_data = {
            'status': scan_task_instance.status,
            'scanned_pages': scan_task_instance.scanned_pages,
            'total_pages': scan_task_instance.total_pages,
        }
        set_cache_data(cache_key, cache_data)

    except Exception as e:
        logger.error(f"保存扫描结果时发生错误: {e}", exc_info=True)
        raise


def webscan_detail(request, scan_task_id):
    """进入每个扫描的详情页中，返回模板和相关数据，包括漏洞详情、扫描进度等信息"""
    scan_task = get_object_or_404(ScanTask, scan_id=scan_task_id)
    scan_results = ScanTask.objects.filter(scan_id=scan_task_id)
    vulnerability_details = extract_vulnerability_details(scan_results)

    return render(request, 'webscan/webscan-detail.html', {
        'scan_task': scan_task,
        'scan_results': scan_results,
        'vulnerability_details': vulnerability_details,
    })

def extract_vulnerability_details(scan_results):
    """提取漏洞详情"""
    vulnerability_details = []
    for result in scan_results:
        logger.info(f"处理扫描结果: {result}")
        if hasattr(result, 'details') and isinstance(result.details, dict) and 'description' in result.details:
            vulnerability_details.append({
                'description': result.details['description'],
                'severity': result.details.get('severity', 'Unknown'),
                'url': result.details.get('url', 'Unknown'),
            })
        else:
            vulnerability_details.append({
                'description': 'No details available',
                'severity': 'Unknown',
                'url': 'Unknown',
            })
    return vulnerability_details


def webscan_detail_info(request):
    """拿到每个漏洞的详细信息，作为ajax响应返回到前端模板中"""
    scan_task_id = request.GET.get('scan_task_id')
    if not scan_task_id:
        return JsonResponse({'error': '缺少必要的扫描任务ID'}, status=400)

    scan_task = get_object_or_404(ScanTask, scan_id=scan_task_id)
    scan_results = ScanTask.objects.filter(scan_task=scan_task)
    vulnerability_details = extract_vulnerability_details(scan_results)

    return JsonResponse(vulnerability_details, safe=False)

def webscan_progress(request):
    scan_task_id = request.GET.get('scan_task_id')
    if not scan_task_id:
        return JsonResponse({'error': 'Missing scan_task_id'}, status=400)

    scan_task = get_object_or_404(ScanTask, scan_id=scan_task_id)
    scan_results = ScanTask.objects.filter(scan_id=scan_task_id)
    results = []
    for result in scan_results:
        results.append({
            'target_url': result.target_url,
            'scan_type': result.scan_type,
            'created_at': result.created_at,
            'high_vulns': result.high_vulns,
            'medium_vulns': result.medium_vulns,
            'low_vulns': result.low_vulns,
            'status': result.status,
        })
    return JsonResponse(results, safe=False)

def generate_report(scan_task, scan_results):
    """生成扫描报告的辅助函数"""
    report = {
        'report_title': '漏洞扫描报告',
        'scan_task_id': scan_task.scan_id,
        'target_url': scan_task.target_url,
        'scan_type': scan_task.scan_type,
        'status': scan_task.status,
        'total_pages': scan_task.total_pages,
        'scanned_pages': scan_task.scanned_pages,
        'completed_at': scan_task.completed_at,
        'vulnerabilities': []
    }

    for result in scan_results:
        vulnerability = {
            'low_vulns': result.low_vuln,
            'info_vulns': result.info_vuln,
            'medium_vulns': result.medium_vuln,
            'high_vulns': result.high_vuln,
            'total_vulns': result.total_vuln,
            'details': result.details
        }
        report['vulnerabilities'].append(vulnerability)

    return report

def webscan_report(request):
    """生成漏洞扫描报告的接口视图"""
    scan_task_id = request.GET.get('scan_task_id')
    if not scan_task_id:
        return JsonResponse({'error': '缺少必要的扫描任务ID'}, status=400)

    scan_task = get_object_or_404(ScanTask, scan_id=scan_task_id)
    scan_results = ScanTask.objects.filter(scan_task=scan_task)
    report = generate_report(scan_task, scan_results)

    return JsonResponse(report)

def webscan_report_download(request):
    """生成漏洞扫描报告并提供下载的接口视图"""
    scan_task_id = request.GET.get('scan_task_id')
    if not scan_task_id:
        return JsonResponse({'error': '缺少必要的扫描任务ID'}, status=400)

    scan_task = get_object_or_404(ScanTask, scan_id=scan_task_id)
    scan_results = ScanTask.objects.filter(scan_task=scan_task)
    report = generate_report(scan_task, scan_results)

    try:
        # 将报告转换为PDF格式
        pdf_report = generate_pdf_report(report)

        # 提供PDF文件下载
        response = HttpResponse(pdf_report, content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="scan_report_{scan_task_id}.pdf"'
        return response
    except Exception as e:
        logger.error(f"生成PDF报告时发生错误 - scan_task_id: {scan_task_id}, 错误详情: {e}")
        return JsonResponse({'error': '生成PDF报告时发生错误，请稍后重试'}, status=500)

def create_general_table(data, styles, table_style=None):
    """创建通用表格并设置样式的辅助函数"""
    table = Table(data)
    if table_style:
        table.setStyle(table_style)
    else:
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, 1)
        ]))
    return table

def generate_pdf_report(report):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()

    elements = [Paragraph(report['report_title'], styles['Title']), Spacer(1, 12)]

    # 添加报告标题

    # 添加扫描任务信息
    task_info = [
        ['扫描任务ID', report['scan_task_id']],
        ['目标URL', report['target_url']],
        ['扫描类型', report['scan_type']],
        ['状态', report['status']],
        ['总页面数', report['total_pages']],
        ['已扫描页面数', report['scanned_pages']],
        ['完成时间', report['completed_at']]
    ]
    elements.append(create_general_table(task_info, styles))
    elements.append(Spacer(1, 12))

    # 添加漏洞信息
    vulnerabilities = report['vulnerabilities']
    for vulnerability in vulnerabilities:
        vuln_info = [
            ['低危漏洞', vulnerability['low_vulns']],
            ['信息漏洞', vulnerability['infovulns']],
            ['中危漏洞', vulnerability['medium_vulns']],
            ['高危漏洞', vulnerability['high_vulns']],
            ['总漏洞数', vulnerability['total_vulns']],
            ['详细信息', vulnerability['details']]
        ]
        elements.append(create_general_table(vuln_info, styles))
        elements.append(Spacer(1, 12))

    doc.build(elements)
    pdf = buffer.getvalue()
    buffer.close()
    return pdf
