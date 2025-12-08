from bottle import route, run, template, post, request, static_file, error
import os
import zipfile
import hashlib
import time
import shutil


# hint: flag is in /flag

UPLOAD_DIR = 'uploads'
os.makedirs(UPLOAD_DIR, exist_ok=True)
MAX_FILE_SIZE = 1 * 1024 * 1024  # 1MB

BLACKLIST = ["b","c","d","e","h","i","j","k","m","n","o","p","q","r","s","t","u","v","w","x","y","z","%",";",",","<",">",":","?"]

def contains_blacklist(content):
    """检查内容是否包含黑名单中的关键词（不区分大小写）"""
    content = content.lower()
    return any(black_word in content for black_word in BLACKLIST)

def safe_extract_zip(zip_path, extract_dir):
    """安全解压ZIP文件（防止路径遍历攻击）"""
    with zipfile.ZipFile(zip_path, 'r') as zf:
        for member in zf.infolist():
            member_path = os.path.realpath(os.path.join(extract_dir, member.filename))
            if not member_path.startswith(os.path.realpath(extract_dir)):
                raise ValueError("非法文件路径: 路径遍历攻击检测")
            
            zf.extract(member, extract_dir)

@route('/')
def index():
    """首页"""
    return '''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZIP文件查看器</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="header text-center">
        <div class="container">
            <h1 class="display-4 fw-bold">📦 ZIP文件查看器</h1>
            <p class="lead">安全地上传和查看ZIP文件内容</p>
        </div>
    </div>
    <div class="container">
        <div class="row justify-content-center" id="index-page">
            <div class="col-md-8 text-center">
                <div class="card">
                    <div class="card-body p-5">
                        <div class="emoji-icon">📤</div>
                        <h2 class="card-title">轻松查看ZIP文件内容</h2>
                        <p class="card-text">上传ZIP文件并安全地查看其中的内容，无需解压到本地设备</p>
                        <div class="mt-4">
                            <a href="/upload" class="btn btn-primary btn-lg px-4 me-3">
                                📁 上传ZIP文件
                            </a>
                            <a href="#features" class="btn btn-outline-secondary btn-lg px-4">
                                ℹ️ 了解更多
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <div class="row mt-5" id="features">
            <div class="col-md-4 mb-4">
                <div class="card h-100">
                    <div class="card-body text-center p-4">
                        <div class="emoji-icon">🛡️</div>
                        <h4>安全检测</h4>
                        <p>系统会自动检测上传文件，防止路径遍历攻击和恶意内容</p>
                    </div>
                </div>
            </div>
            <div class="col-md-4 mb-4">
                <div class="card h-100">
                    <div class="card-body text-center p-4">
                        <div class="emoji-icon">📄</div>
                        <h4>内容预览</h4>
                        <p>直接在线查看ZIP文件中的文本内容，无需下载</p>
                    </div>
                </div>
            </div>
            <div class="col-md-4 mb-4">
                <div class="card h-100">
                    <div class="card-body text-center p-4">
                        <div class="emoji-icon">⚡</div>
                        <h4>快速处理</h4>
                        <p>高效处理小于1MB的ZIP文件，快速获取内容</p>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
    '''

@route('/upload')
def upload_page():
    """上传页面"""
    return '''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>上传ZIP文件</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="header text-center">
        <div class="container">
            <h1 class="display-4 fw-bold">📦 ZIP文件查看器</h1>
            <p class="lead">安全地上传和查看ZIP文件内容</p>
        </div>
    </div>
    <div class="container mt-4">
        <div class="row justify-content-center">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header bg-primary text-white">
                        <h4 class="mb-0">📤 上传ZIP文件</h4>
                    </div>
                    <div class="card-body">
                        <form action="/upload" method="post" enctype="multipart/form-data" class="upload-form">
                            <div class="mb-3">
                                <label for="fileInput" class="form-label">选择ZIP文件（最大1MB）</label>
                                <input class="form-control" type="file" name="file" id="fileInput" accept=".zip" required>
                                <div class="form-text">仅支持.zip格式的文件，且文件大小不超过1MB</div>
                            </div>
                            <button type="submit" class="btn btn-primary w-100">
                                📤 上传文件
                            </button>
                        </form>
                    </div>
                </div>
                <div class="text-center mt-4">
                    <a href="/" class="btn btn-outline-secondary">
                        ↩️ 返回首页
                    </a>
                </div>
            </div>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
    '''

@post('/upload')
def upload():
    """处理文件上传"""
    zip_file = request.files.get('file')
    if not zip_file or not zip_file.filename.endswith('.zip'):
        return '请上传有效的ZIP文件'
    
    zip_file.file.seek(0, 2)  
    file_size = zip_file.file.tell()
    zip_file.file.seek(0)  
    
    if file_size > MAX_FILE_SIZE:
        return f'文件大小超过限制({MAX_FILE_SIZE/1024/1024}MB)'
    
    timestamp = str(time.time())
    unique_str = zip_file.filename + timestamp
    dir_hash = hashlib.md5(unique_str.encode()).hexdigest()
    extract_dir = os.path.join(UPLOAD_DIR, dir_hash)
    os.makedirs(extract_dir, exist_ok=True)
    
    zip_path = os.path.join(extract_dir, 'uploaded.zip')
    zip_file.save(zip_path)
    
    try:
        safe_extract_zip(zip_path, extract_dir)
    except (zipfile.BadZipFile, ValueError) as e:
        shutil.rmtree(extract_dir) 
        return f'处理ZIP文件时出错: {str(e)}'
    
    files = [f for f in os.listdir(extract_dir) if f != 'uploaded.zip']
    
    return template('''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>上传成功</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="header text-center">
        <div class="container">
            <h1 class="display-4 fw-bold">📦 ZIP文件查看器</h1>
            <p class="lead">安全地上传和查看ZIP文件内容</p>
        </div>
    </div>

    <div class="container mt-4">
        <div class="row justify-content-center">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header bg-success text-white">
                        <h4 class="mb-0">✅ 上传成功!</h4>
                    </div>
                    <div class="card-body">
                        <div class="alert alert-success" role="alert">
                            ✅ 文件已成功上传并解压
                        </div>

                        <h5>文件列表:</h5>
                        <ul class="list-group mb-4">
                            % for file in files:
                            <li class="list-group-item d-flex justify-content-between align-items-center">
                                <span>📄 {{file}}</span>
                                <a href="/view/{{dir_hash}}/{{file}}" class="btn btn-sm btn-outline-primary">
                                    查看
                                </a>
                            </li>
                            % end
                        </ul>

                        % if files:
                        <div class="d-grid gap-2">
                            <a href="/view/{{dir_hash}}/{{files[0]}}" class="btn btn-primary">
                                👀 查看第一个文件
                            </a>
                        </div>
                        % end
                    </div>
                </div>

                <div class="text-center mt-4">
                    <a href="/upload" class="btn btn-outline-primary me-2">
                        ➕ 上传另一个文件
                    </a>
                    <a href="/" class="btn btn-outline-secondary">
                        🏠 返回首页
                    </a>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
    ''', dir_hash=dir_hash, files=files)

@route('/view/<dir_hash>/<filename:path>')
def view_file(dir_hash, filename):
    file_path = os.path.join(UPLOAD_DIR, dir_hash, filename)
    
    if not os.path.exists(file_path):
        return "文件不存在"
    
    if not os.path.isfile(file_path):
        return "请求的路径不是文件"
    
    real_path = os.path.realpath(file_path)
    if not real_path.startswith(os.path.realpath(UPLOAD_DIR)):
        return "非法访问尝试"
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except:
        try:
            with open(file_path, 'r', encoding='latin-1') as f:
                content = f.read()
        except:
            return "无法读取文件内容（可能是二进制文件）"
    
    if contains_blacklist(content):
        return "文件内容包含不允许的关键词"
    
    try:
        return template(content)
    except Exception as e:
        return f"渲染错误: {str(e)}"

@route('/static/<filename:path>')
def serve_static(filename):
    """静态文件服务"""
    return static_file(filename, root='static')

@error(404)
def error404(error):
    return "讨厌啦不是说好只看看不摸的吗"

@error(500)
def error500(error):
    return "不要透进来啊啊啊啊"

if __name__ == '__main__':
    os.makedirs('static', exist_ok=True)
    
    #原神，启动!
    run(host='0.0.0.0', port=5000, debug=False)