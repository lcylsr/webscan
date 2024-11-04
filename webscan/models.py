from django.db import models
from django.core.exceptions import ValidationError
from urllib.parse import urlparse


class Scan(models.Model):
    """表示一次网站安全扫描的模型"""

    SCAN_TYPES = [
        ('quick', '快速扫描'),
        ('deep', '深度扫描'),
    ]

    url = models.URLField(max_length=200, unique=True, help_text="存储目标URL，确保唯一性")
    scan_type = models.CharField(
        max_length=50,
        choices=SCAN_TYPES,
        default='quick',
        verbose_name='扫描类型',
        help_text="选择扫描类型：快速扫描或深度扫描"
    )
    created_at = models.DateTimeField(auto_now_add=True, help_text="自动添加创建时间")
    results = models.JSONField(null=True, blank=True, default=dict, help_text="存储扫描结果（可选），默认为空字典")

    def __str__(self):
        return f"{self.url} - {self.scan_type}"

    class Meta:
        ordering = ['-created_at']  # 根据创建时间降序排列

    def clean(self):
        """自定义验证方法，确保URL格式正确"""
        if not (self.url.startswith(('http://', 'https://', 'ftp://'))):
            raise ValidationError("URL必须以 http://、https:// 或 ftp:// 开头")

        parsed_url = urlparse(self.url)
        if not (parsed_url.scheme and parsed_url.netloc):
            pdf="URL 格式不正确"
            raise ValidationError(pdf)

        # 检查扫描结果的格式
        if self.results and not isinstance(self.results, (list, dict)):
            raise ValidationError("扫描结果必须为列表或字典格式")

        # 可根据具体需求进一步验证 results 的内容结构
        # if isinstance(self.results, dict) and 'key' not in self.results:
        #     raise ValidationError("扫描结果字典缺少必要的键 'key'")


class ScanTaskStatus(models.Model):
    """存储扫描任务的状态和进度的模型"""

    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='task_statuses', help_text="关联的扫描任务")
    status = models.CharField(max_length=20, choices=[
        ('pending', '待处理'),
        ('running', '正在运行'),
        ('completed', '已完成'),
        ('failed', '失败')
    ], default='pending', help_text="扫描任务的状态")
    progress = models.IntegerField(default=0, help_text="扫描任务的进度，取值范围0 - 100")
    updated_at = models.DateTimeField(auto_now=True, help_text="自动更新状态和进度的时间")

    def __str__(self):
        return f"{self.scan.url} - {self.status} ({self.progress}%)"

    class Meta:
        ordering = ['-updated_at']  # 根据更新时间降序排列

    def clean(self):
        """自定义验证方法，确保进度值在有效范围内"""
        if not (0 <= self.progress <= 100):
            raise ValidationError("进度值必须在0到100之间")