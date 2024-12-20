from django import forms

class ScanForm(forms.Form):
    """表单用于收集扫描请求的信息"""

    target_url = forms.URLField(
        label='目标域名或IP地址',
        max_length=200,
        error_messages={
            'required': '请输入目标域名或IP地址。',
            'invalid': '请输入有效的域名或IP地址，例如: www.example.com 或 192.168.0.1。',
        },
    )

    scan_type = forms.ChoiceField(
        label='扫描类型',
        choices=[
            ('quick', '快速扫描'),
            ('deep', '深度扫描'),
        ],
        error_messages={
            'required': '请选择扫描类型。',
        },
    )

    def clean_target_url(self):
        """验证目标目标域名或IP地址"""
        target_url = self.cleaned_data.get('target_url')
        # 直接返回，不需要额外的验证
        return target_url

    def clean_scan_type(self):
        """验证扫描类型是否被选择"""
        scan_type = self.cleaned_data.get('scan_type')
        # 如果不在choices中，Django会自动处理这个错误，因此可以省略这部分验证
        return scan_type

