from django.utils import timezone

from django.db import models
import logging
import uuid

# 设置日志记录
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ScanTaskStatus:
    PENDING = 'pending'
    RUNNING = 'running'
    COMPLETED = 'completed'
    FAILED = 'failed'

    choices = [
        (PENDING, 'Pending'),
        (RUNNING, 'Running'),
        (COMPLETED, 'Completed'),
        (FAILED, 'Failed'),
    ]


class ScanTask(models.Model):
    """
    ScanTask模型用于表示漏洞扫描任务相关信息，包含任务的基本属性、状态以及漏洞和页面扫描情况统计等内容。
    """
    scan_id = models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, help_text="扫描任务ID")
    target_url = models.URLField(max_length=255, help_text="扫描目标网址")
    scan_type = models.CharField(max_length=50, help_text="扫描类型，如快速、深度等")
    status = models.CharField(max_length=50, choices=ScanTaskStatus.choices, default=ScanTaskStatus.PENDING, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    low_vulns = models.PositiveIntegerField(default=0, help_text="低风险漏洞数")
    medium_vulns = models.PositiveIntegerField(default=0, help_text="中风险漏洞数")
    high_vulns = models.PositiveIntegerField(default=0, help_text="高风险漏洞数")
    total_vulns = models.PositiveIntegerField(default=0, help_text="总漏洞数")
    scanned_pages = models.PositiveIntegerField(default=0, help_text="已扫描页面数")
    total_pages = models.PositiveIntegerField(default=0, help_text="总页面数")

    def __str__(self):
        return f"ScanTask - {self.scan_id} - {self.target_url} (Type: {self.scan_type}, Status: {self.status}, Low Vulns: {self.low_vulns}, Medium Vulns: {self.medium_vulns}, High Vulns: {self.high_vulns})"


class ScanResults(models.Model):
    """
    ScanResults模型用于记录每个扫描任务具体的扫描结果信息，包含结果ID、关联的任务ID、扫描页面URL、漏洞相关详情等内容。
    """
    result_id = models.AutoField(primary_key=True, help_text="扫描结果ID")
    scan_id = models.ForeignKey(ScanTask, on_delete=models.CASCADE,help_text="扫描任务ID")
    url = models.URLField(max_length=255, help_text="扫描页面URL")
    vulnerability_name = models.CharField(max_length=255, help_text="漏洞名称")
    severity = models.CharField(max_length=50, help_text="漏洞等级")
    description = models.TextField(help_text="漏洞描述")
    discovery_time = models.DateTimeField(help_text="发现时间")
    request_input = models.CharField(max_length=100, default="", help_text="请求输入")
    response_status_code = models.IntegerField(default=0, help_text="响应状态码")

    def __str__(self):
        return f"ScanResults - {self.result_id} - {self.scan_id} - {self.url} - {self.vulnerability_name} - {self.severity} - {self.description} - {self.discovery_time}"

