import io
import zipfile
from PIL import Image,ImageOps
import fitz # 用于处理PDF
import re
import os
import json
import redis

import shutil # 删除目录树
from flask import (
    Flask, render_template, request, jsonify, redirect, url_for,
    session, send_from_directory, flash, abort, send_file
)
# from flask_session import Session
import random
import datetime
from dateutil.relativedelta import relativedelta
from werkzeug.utils import secure_filename
import time
from functools import wraps
from config import HONOR_TYPE, LEVEL_TYPE, MAJOR_TYPE # 假设你的 config.py 有这两个列表
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

# --- 配置 ---
SECRET_KEY = 'e3ffd14577c6444fb5d7997c27b74ef0'
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
USER_DATA_FILE = 'data/user.json'
HONORS_DATA_FILE = 'data/honors.json'
README_FILE = 'README.md' # <<< 新增：定义 README 文件名

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=7)
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024 # 限制为 16 MB

# 配置 Redis
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = redis.Redis(
    host='localhost',  # Redis 服务器地址
    port=6379,
    db=0,
    # password='your_redis_password'  # 如果设置了密码
)
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_USE_SIGNER'] = True  # 对 Session ID 签名

# # 初始化 Session
# Session(app)

# 告知反向代理
app.wsgi_app = ProxyFix(
    app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
)

# --- 日志 ---
logger = app.logger

# --- 确保目录和文件存在 ---

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
    logger.info(f"创建上传文件夹: {UPLOAD_FOLDER}")

if not os.path.exists('data'):
    os.makedirs('data')
    logger.info("创建数据文件夹: data")

if not os.path.exists(HONORS_DATA_FILE):
    with open(HONORS_DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump({}, f)
    logger.info(f"创建荣誉数据文件: {HONORS_DATA_FILE}")

# --- 辅助函数 ---
def find_honor_and_owner(honor_id):
    """
    辅助函数：根据荣誉ID在所有用户中查找荣誉及其所有者。
    返回 (honor_dict, owner_username) 或 (None, None)。
    """
    honors_data = load_honors_data()
    for username, honors_list in honors_data.items():
        for honor in honors_list:
            if honor.get('id') == honor_id:
                return honor, username
    return None, None

def parse_date_safe(date_str):
    """Safely parses YYYY-MM-DD string to date object, returns None on failure."""
    if not date_str:
        return None
    try:
        return datetime.datetime.strptime(date_str, '%Y-%m-%d').date()
    except (ValueError, TypeError):
        logger.warning(f"无法解析日期字符串: '{date_str}'")
        return None

def allowed_file(filename):
    """检查文件扩展名是否允许"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def load_data(filepath):
    """通用加载 JSON 数据函数"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            if not content: return {}
            return json.loads(content)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.error(f"无法加载或解析数据文件 '{filepath}': {e}")
        return {}

def save_data(filepath, data):
    """通用保存 JSON 数据函数"""
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
    except IOError as e:
        logger.error(f"无法写入数据文件 '{filepath}': {e}")

def load_honors_data():
    return load_data(HONORS_DATA_FILE)

def save_honors_data(data):
    save_data(HONORS_DATA_FILE, data)

def load_user_data():
    return load_data(USER_DATA_FILE)


# --- 装饰器 ---
def login_required(f):
    """登录检查装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session['logged_in']:
            flash("您需要先登录才能访问此页面。", "warning")
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """管理员权限检查装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            logger.warning(f"用户 '{session.get('username')}' (角色: {session.get('role')}) 尝试访问管理员页面: {request.path}")
            flash("您没有权限访问此页面，需要管理员身份。", "error")
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# --- 路由 ---

@app.after_request
def add_header(response):
    """添加防缓存头"""
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.context_processor
def inject_now():
    """向模板注入当前时间，用于页脚"""
    return {'now': datetime.datetime.utcnow}

@app.route('/')
def index():
    """主页，现在包含登录和注册的入口"""
    # 如果用户已登录，直接跳转到 home
    if session.get('logged_in'):
        return redirect(url_for('home'))

    # 未登录用户看到的是带登录/注册按钮的欢迎页
    return render_template('index.html', majors = MAJOR_TYPE)

@app.route('/home')
@login_required
def home():
    # ... (home 路由保持不变) ...
    username = session.get('username')
    users = load_user_data()

    user_info = users.get(username, {})
    current_motto = user_info.get('motto', '')

    response_data = {
        'username': username,
        'role': session.get('role'),
        'class': session.get('class'),
        'truename': session.get('truename'),
        'major': session.get('major'),
        'employment_duration': session.get('employment_duration'),
        'motto': current_motto,
        'honor_types': HONOR_TYPE,
        'honor_levels': LEVEL_TYPE
    }

    honors_data = load_honors_data()
    user_honors_raw = honors_data.get(username, [])

    total_honor_count_unfiltered = len(user_honors_raw)
    response_data['total_honor_count'] = total_honor_count_unfiltered

    all_possible_types = HONOR_TYPE
    honor_type_counts_unfiltered = {honor_type: 0 for honor_type in all_possible_types}
    for honor in user_honors_raw:
        honor_type = honor.get('type')
        if honor_type in honor_type_counts_unfiltered:
            honor_type_counts_unfiltered[honor_type] += 1
    response_data['honor_type_counts'] = honor_type_counts_unfiltered

    all_possible_levels = LEVEL_TYPE
    honor_level_counts_unfiltered = {level_type: 0 for level_type in all_possible_levels}
    for honor in user_honors_raw:
        honor_level = honor.get('honor_level') or honor.get('level')
        if honor_level in honor_level_counts_unfiltered:
            honor_level_counts_unfiltered[honor_level] += 1
    response_data['honor_level_counts'] = honor_level_counts_unfiltered

    selected_date_filter = request.args.get('filter_date', 'all')
    response_data['selected_date_filter'] = selected_date_filter
    today = datetime.date.today()
    cutoff_date = None
    try:
        if selected_date_filter == 'last_year':
            cutoff_date = today - relativedelta(years=1)
        elif selected_date_filter == 'last_3_years':
            cutoff_date = today - relativedelta(years=3)
        elif selected_date_filter == 'last_5_years':
            cutoff_date = today - relativedelta(years=5)
    except Exception as e:
        logger.error(f"计算 cutoff_date 时出错: {e}")
        cutoff_date = None

    filtered_honors = []
    if cutoff_date:
        for honor in user_honors_raw:
            honor_date = parse_date_safe(honor.get('date'))
            if honor_date and honor_date >= cutoff_date:
                filtered_honors.append(honor)
    else:
        filtered_honors = user_honors_raw

    user_honors_sorted_filtered = sorted(
        filtered_honors,
        key=lambda x: parse_date_safe(x.get('date')) or datetime.date.min,
        reverse=True
    )
    response_data['honors'] = user_honors_sorted_filtered

    return render_template('home.html', **response_data)

@app.route('/uploads/<username>/<path:filename>')
@login_required
def uploaded_file_user(username, filename):
    # <<< 修改：允许用户访问自己的文件，或管理员访问任何用户的文件 >>>
    if session.get('role') != 'admin' and session.get('username') != username:
         logger.warning(f"用户 '{session.get('username')}' 尝试访问用户 '{username}' 的文件: {filename}")
         abort(403) # Forbidden


    user_upload_folder = os.path.abspath(os.path.join(UPLOAD_FOLDER, username))
    safe_path = os.path.abspath(os.path.join(user_upload_folder, filename))
    if not safe_path.startswith(user_upload_folder):
        logger.warning(f"检测到潜在的路径遍历尝试 (用户: {username}): {filename}")
        abort(404)

    if not os.path.isdir(user_upload_folder):
         logger.error(f"用户 '{username}' 的上传目录不存在: {user_upload_folder}")
         abort(404)

    try:
        return send_from_directory(user_upload_folder, filename, as_attachment=False)
    except FileNotFoundError:
        logger.warning(f"尝试访问用户 '{username}' 不存在的文件: {filename} in {user_upload_folder}")
        abort(404)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """个人资料页面，支持修改基本信息和密码"""
    username = session.get('username')
    users = load_user_data()

    # 如果找不到用户数据，则重定向到主页
    if not username or username not in users:
        flash("无法加载您的用户数据，请重新登录。", "error")
        return redirect(url_for('logout'))

    current_user = users[username]

    if request.method == 'POST':
        form_type = request.form.get('form_type')

        # --- 表单一：处理基本信息更新 ---
        if form_type == 'update_profile':
            new_truename = request.form.get('truename', '').strip()
            new_major = request.form.get('major', '').strip()
            new_motto = request.form.get('motto', '').strip()

            if not new_truename:
                flash("真实姓名不能为空。", "error")
                return redirect(url_for('profile'))

            # 更新用户信息字典
            users[username]['truename'] = new_truename
            users[username]['major'] = new_major
            users[username]['motto'] = new_motto

            # 保存回 JSON 文件
            save_data(USER_DATA_FILE, users)

            # 更新 session 中的信息以便立即生效
            session['truename'] = new_truename
            session['major'] = new_major

            logger.info(f"用户 '{username}' 更新了个人基本信息。")
            flash("您的基本信息已成功更新！", "success")
            return redirect(url_for('profile'))

        # --- 表单二：处理密码修改 ---
        elif form_type == 'change_password':
            old_password = request.form.get('old_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')

            # 验证旧密码
            # 关键：使用 check_password_hash 来验证哈希后的密码
            if not check_password_hash(current_user.get('password', ''), old_password):
                flash("当前密码不正确。", "error")
                return redirect(url_for('profile'))

            # 验证新密码
            if not new_password or len(new_password) < 6:
                flash("新密码不能为空且长度至少为6位。", "error")
                return redirect(url_for('profile'))

            if new_password != confirm_password:
                flash("两次输入的新密码不一致。", "error")
                return redirect(url_for('profile'))

            # 生成新密码的哈希值并更新
            users[username]['password'] = generate_password_hash(new_password)
            save_data(USER_DATA_FILE, users)

            logger.info(f"用户 '{username}' 成功修改了密码。")
            flash("密码已成功修改！", "success")
            return redirect(url_for('profile'))

        else:
            flash("无效的表单提交。", "warning")
            return redirect(url_for('profile'))

    # --- 处理 GET 请求 ---
    # 将当前用户信息传递给模板
    return render_template('profile.html', user=current_user)

@app.route('/update_motto', methods=['POST'])
@login_required
def update_motto():
    # ... (update_motto 路由保持不变) ...
    username = session.get('username')
    if not username:
        return jsonify(success=False, error="用户未登录"), 401

    data = request.get_json()
    if data is None:
        return jsonify(success=False, error="无效的请求数据格式，请发送 JSON"), 400

    new_motto = data.get('motto', '')
    max_motto_length = 100
    if len(new_motto) > max_motto_length:
         return jsonify(success=False, error=f"签名过长，最多 {max_motto_length} 个字符"), 400

    users = load_user_data()
    if username in users:
        try:
            users[username]['motto'] = new_motto
            save_data(USER_DATA_FILE, users)
            logger.info(f"用户 '{username}' 更新签名为: '{new_motto}'")
            return jsonify(success=True, message="签名更新成功！", new_motto=new_motto)
        except Exception as e:
            logger.error(f"保存用户 '{username}' 的新签名时出错: {e}", exc_info=True)
            return jsonify(success=False, error="保存签名时发生服务器内部错误"), 500
    else:
        logger.warning(f"尝试更新签名的用户 '{username}' 不存在于用户数据中")
        return jsonify(success=False, error="无法找到用户信息"), 404

@app.route('/logout')
@login_required
def logout():
    # ... (logout 路由保持不变) ...
    logger.info(f"用户 '{session.get('username')}' 退出登录")
    default_upload_folder = os.path.abspath('uploads')
    app.config['UPLOAD_FOLDER'] = default_upload_folder
    session.clear()
    flash("您已成功退出登录。", "success")
    return redirect(url_for('index'))


@app.route('/login', methods=['GET','POST'])
def login():
    # Handle GET requests: If accessed directly, redirect to index page
    if request.method == 'GET':
        if session.get('logged_in'):
            return redirect(url_for('home')) # Already logged in, go home
        return redirect(url_for('index')) # Not logged in, show index page (which has the form)

    # Handle POST requests (form submission)
    if request.method == 'POST':
        username = request.form['name']
        password = request.form['password']
        users = load_user_data()

        # --- User loading error ---
        if not users:
             flash('登录服务暂时不可用，请稍后再试。', 'error')
             # Render index page, passing back username if possible
             return redirect(url_for('index')) # 失败后重定向回主页

        # --- User found ---
        if username in users:

            if username in users and check_password_hash(users[username]['password'], password): # Replace with secure check

                def get_employment_duration(employment_day):
                    # 根据日期计算入职天数
                    start_date = datetime.datetime.strptime(employment_day, '%Y-%m-%d').date()
                    today = datetime.datetime.now().date()
                    total_days = (today - start_date).days
                    if total_days < 0:
                        employment_duration_str = "未来日期"
                    else:
                        employment_duration_str = f"{total_days}天"
                    return employment_duration_str

                # --- Login Success ---
                session['logged_in'] = True
                session['username'] = users[username]['username']
                # Store other user details in session
                session['role'] = users[username].get('role', '未知角色')
                session['class'] = users[username].get('class', '')
                session['truename'] = users[username].get('truename', username)
                session['major'] = users[username].get('major', '')
                session['employment_duration'] = get_employment_duration(users[username].get('employment_day'))
                session.permanent = True # Make session persistent if needed
                logger.info(f"用户 '{username}' 登录成功")

                flash(f"欢迎回来, {session.get('truename', username)}！", "success") # Use session value
                next_url = request.args.get('next')
                return redirect(next_url or url_for('home'))
            else:
                # --- Password Incorrect ---
                logger.warning(f"用户 '{username}' 密码错误")
                flash('用户名或密码错误。', 'error')
                # Re-render index page with error, pass back username
                return render_template('index.html', username=username)
        else:
            # --- Username Not Found ---
            logger.warning(f"尝试使用不存在的用户名登录: '{username}'")
            flash('用户名或密码错误。', 'error')
            # Re-render index page with error, pass back username
            return redirect(url_for('index')) # 失败后重定向回主页

    # Fallback (shouldn't normally be reached for POST)
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    """处理用户注册的页面显示和表单提交"""
    # 如果用户已登录，直接重定向到主页
    if session.get('logged_in'):
        return redirect(url_for('home'))

    if request.method == 'POST':
        # 1. 从表单获取所有数据
        username = request.form.get('username', '').strip()
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        truename = request.form.get('truename', '').strip()
        major = request.form.get('major', '').strip()
        employment_day = request.form.get('employment_day').strip()

        # 2. 进行严格的后端验证
        users = load_user_data()

        if not all([username, password, confirm_password, truename, employment_day]):
            flash("所有带 * 号的必填项都不能为空。", "error")
            return redirect(url_for('register'))

        if username in users:
            flash(f"登录账号 '{username}' 已被占用，请更换一个。", "error")
            return redirect(url_for('register'))

        if len(password) < 6:
            flash("密码长度不能少于6位。", "error")
            return redirect(url_for('register'))

        if password != confirm_password:
            flash("两次输入的密码不一致。", "error")
            return redirect(url_for('register'))

        # 3. 验证通过，创建新用户数据
        new_user_data = {
            "username": username,
            "password": generate_password_hash(password),  # 关键：存储哈希后的密码
            "truename": truename,
            "major": major,
            "employment_day": employment_day,
            "role": "user",  # 默认角色为普通用户
            "motto": ""  # 初始座右铭为空
        }

        # 4. 保存新用户
        users[username] = new_user_data
        save_data(USER_DATA_FILE, users)

        logger.info(f"新用户 '{username}' ({truename}) 注册成功。")
        flash("恭喜您，注册成功！现在可以使用新账户登录了。", "success")
        return redirect(url_for('index'))

    return redirect(url_for('index'))


# --- 路由 ---
# 请确保删除了文件顶部的 import fitz

@app.route('/add_honor', methods=['GET', 'POST'])
@login_required
def add_honor():
    username = session.get('username')
    honor_types = HONOR_TYPE
    honor_levels = LEVEL_TYPE
    current_upload_folder = os.path.join(UPLOAD_FOLDER, username)

    if not os.path.exists(current_upload_folder):
        os.makedirs(current_upload_folder)

    if request.method == 'POST':
        # 1. 获取表单数据
        honor_name = request.form.get('honor_name')
        honor_type = request.form.get('honor_type')
        honor_date = request.form.get('honor_date')
        honor_stamp = request.form.get('honor_stamp')
        honor_stamp_other = request.form.get('honor_stamp_other') or ""
        honor_image = request.files.get('honor_image')
        honor_level = request.form.get('honor_level')

        # 2. 校验
        if not all([honor_name, honor_type, honor_level, honor_date, honor_stamp]):
            flash("请填写所有必填项。", "error")
            return render_template('add_honor.html', honor_types=honor_types, honor_levels=honor_levels, form_data=request.form.to_dict())

        if not honor_image or honor_image.filename == '':
            flash("请上传荣誉证明文件。", "error")
            return render_template('add_honor.html', honor_types=honor_types, honor_levels=honor_levels, form_data=request.form.to_dict())

        if not allowed_file(honor_image.filename):
            flash("无效的文件格式，请上传图片文件（PNG, JPG, JPEG, GIF）或PDF文件。", "error")
            return render_template('add_honor.html', honor_types=honor_types, honor_levels=honor_levels, form_data=request.form.to_dict())

        # 3. 【核心修改】文件处理逻辑 (借鉴自 edit_honor)
        temp_path = None # 确保 temp_path 在 try 外定义
        try:
            # --- 步骤 3.1: 保存上传文件到临时位置 ---
            if honor_image.filename[-3:] != 'pdf':
                original_filename = secure_filename(honor_image.filename)
                _, ext = os.path.splitext(original_filename)
            else:
                original_filename = honor_image.filename
                ext = '.pdf'
            
            temp_basename = f"temp_{int(time.time())}_{random.randint(1000, 9999)}"
            temp_filename = temp_basename + ext
            temp_path = os.path.join(current_upload_folder, temp_filename)
            honor_image.save(temp_path)
            logger.info(f"上传的文件已临时保存到: {temp_path}")

            # --- 步骤 3.2: 根据文件类型，创建Pillow图像对象 ---
            pil_image = None
            if ext.lower() == '.pdf':
                logger.info("检测到PDF文件，开始使用fitz进行转换...")
                import fitz # 局部导入，仅在需要时使用
                doc = fitz.open(temp_path)
                if len(doc) == 0:
                    raise ValueError("PDF文件为空，没有页面可以转换。")
                page = doc.load_page(0)  # 获取第一页
                pix = page.get_pixmap(dpi=200) # 渲染为像素图，提高分辨率
                doc.close()
                mode = "RGBA" if pix.alpha else "RGB"
                pil_image = Image.frombytes(mode, (pix.width, pix.height), pix.samples)
                logger.info("PDF第一页成功转换为Pillow图像对象。")
            else:
                logger.info("检测到图片文件，使用Pillow直接打开...")
                pil_image = Image.open(temp_path)
                pil_image = ImageOps.exif_transpose(pil_image) # 修正图片方向
                logger.info("图片文件成功加载为Pillow图像对象。")

            if not pil_image:
                raise ValueError("无法从上传的文件生成图像对象。")

            # --- 步骤 3.3: 生成最终文件名并保存图像和缩略图 (后续逻辑与原先类似) ---
            timestamp = int(time.time())
            rand_int = random.randint(100, 999)
            
            # 统一将最终图片保存为 JPG 格式
            output_image_filename = f"{username}_{timestamp}_{rand_int}.jpg"
            output_image_path = os.path.join(current_upload_folder, output_image_filename)
            
            # 创建缩略图文件名
            thumb_base, _ = os.path.splitext(output_image_filename)
            thumb_filename = f"{thumb_base}_thumb.jpg"
            thumb_save_path = os.path.join(current_upload_folder, thumb_filename)

            # 保存主图片 (转换为RGB以存为JPG)
            if pil_image.mode in ('RGBA', 'P'):
                background = Image.new('RGB', pil_image.size, (255, 255, 255))
                mask = pil_image.convert('RGBA').split()[3]
                background.paste(pil_image, mask=mask)
                background.save(output_image_path, "JPEG", quality=85, optimize=True)
            else:
                pil_image.convert('RGB').save(output_image_path, "JPEG", quality=85, optimize=True)
            logger.info(f"已将上传文件内容保存为最终图片: '{output_image_filename}'")
            
            # 创建并保存缩略图
            pil_image.thumbnail((400, 400), Image.Resampling.LANCZOS)
            if pil_image.mode in ('RGBA', 'P'):
                thumb_background = Image.new('RGB', pil_image.size, (255, 255, 255))
                thumb_mask = pil_image.convert('RGBA').split()[3]
                thumb_background.paste(pil_image, mask=thumb_mask)
                thumb_background.save(thumb_save_path, "JPEG", quality=85, optimize=True)
            else:
                pil_image.convert('RGB').save(thumb_save_path, "JPEG", quality=85, optimize=True)
            logger.info(f"成功创建缩略图: '{thumb_filename}'")
            
            pil_image.close()

        except Exception as e:
            logger.error(f"处理上传的文件失败: {e}", exc_info=True)
            flash(f"文件处理失败，请确保文件未损坏且格式正确。错误: {e}", "error")
            return render_template('add_honor.html', honor_types=honor_types, honor_levels=honor_levels, form_data=request.form.to_dict())
        finally:
            # --- 步骤 3.4: 清理临时文件 ---
            if temp_path and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                    logger.info(f"已成功删除临时文件: {temp_path}")
                except OSError as e:
                    logger.error(f"删除临时文件 '{temp_path}' 失败: {e}")

        # 4. 保存荣誉数据 (这部分逻辑不变)
        new_honor = {
            "id": f"honor_{timestamp}_{rand_int}",
            "name": honor_name,
            "type": honor_type,
            "date": honor_date,
            "stamp": honor_stamp,
            "stamp_other": honor_stamp_other,
            "image_filename": output_image_filename,
            "honor_level": honor_level,
            "thumb_filename": thumb_filename # 建议也保存缩略图文件名，方便调用
        }
        honors_data = load_honors_data()
        if username not in honors_data: honors_data[username] = []
        honors_data[username].append(new_honor)
        save_honors_data(honors_data)

        logger.info(f"用户 '{username}' 添加新荣誉 '{honor_name}' 成功")
        flash(f"荣誉 '{honor_name}' 添加成功！", "success")
        return redirect(url_for('home'))

    return render_template('add_honor.html', honor_types=honor_types, honor_levels=honor_levels)

@app.route('/admin/all_honors')
@login_required
@admin_required
def admin_all_honors():
    """
    【新增】管理员页面：查看、筛选所有用户的全部荣誉。
    """
    logger.info(f"管理员 '{session.get('username')}' 正在访问所有荣誉管理页面")

    try:
        honors_data = load_honors_data()
        users_data = load_user_data()

        # 1. 压平所有荣誉到一个列表，并补充教师信息
        all_honors_raw = []
        all_majors = set()
        all_teachers = {}  # {username: truename}

        for username, user_honors in honors_data.items():
            user_info = users_data.get(username, {})
            truename = user_info.get('truename', username)
            major = user_info.get('major', '未指定专业')

            if user_honors:  # 仅将有荣誉记录的教师加入筛选列表
                all_teachers[username] = truename
                if major:
                    all_majors.add(major)

            for honor in user_honors:
                honor_copy = honor.copy()
                honor_copy['username'] = username
                honor_copy['truename'] = truename
                honor_copy['major'] = major
                all_honors_raw.append(honor_copy)

        # 2. 服务端筛选 (按时间)
        selected_date_filter = request.args.get('filter_date', 'all')
        today = datetime.date.today()
        cutoff_date = None
        if selected_date_filter == 'last_year':
            cutoff_date = today - relativedelta(years=1)
        elif selected_date_filter == 'last_3_years':
            cutoff_date = today - relativedelta(years=3)
        elif selected_date_filter == 'last_5_years':
            cutoff_date = today - relativedelta(years=5)

        filtered_by_date_honors = []
        if cutoff_date:
            for honor in all_honors_raw:
                honor_date = parse_date_safe(honor.get('date'))
                if honor_date and honor_date >= cutoff_date:
                    filtered_by_date_honors.append(honor)
        else:
            filtered_by_date_honors = all_honors_raw

        # 3. 按日期倒序排序
        all_honors_sorted = sorted(
            filtered_by_date_honors,
            key=lambda x: parse_date_safe(x.get('date')) or datetime.date.min,
            reverse=True
        )

        # 4. 准备数据传递给模板
        response_data = {
            'honors': all_honors_sorted,
            'honor_types': HONOR_TYPE,
            'honor_levels': LEVEL_TYPE,
            'all_majors': sorted(list(all_majors)),  # 用于专业筛选
            'all_teachers': all_teachers,  # 用于教师筛选 {username: truename}
            'selected_date_filter': selected_date_filter,
            'username': session.get('username') # 传递当前用户名以兼容layout
        }

        return render_template('admin/all_honors.html', **response_data)

    except Exception as e:
        logger.error(f"管理员 '{session.get('username')}' 访问所有荣誉页面时出错: {e}", exc_info=True)
        flash("加载所有荣誉列表时发生错误。", "error")
        return redirect(url_for('admin_dashboard'))


# --- 【重要】用下面的版本替换掉旧的 edit_honor 和 delete_honor 函数 ---
@app.route('/edit_honor/<string:honor_id>', methods=['POST'])
@login_required
def edit_honor(honor_id):
    # 1. 查找荣誉及其所有者
    honor_to_edit, owner_username = find_honor_and_owner(honor_id)
    if not honor_to_edit:
        return jsonify(success=False, error="无法找到要编辑的荣誉记录。"), 404

    # 2. 权限验证
    if session.get('role') != 'admin' and session.get('username') != owner_username:
        return jsonify(success=False, error="您沒有權限編輯此記錄。"), 403

    # 3. 获取表单文本数据
    new_name = request.form.get('honor_name')
    if not new_name: # 简单校验
        return jsonify(success=False, error="荣誉名称不能为空。"), 400

    honors_data = load_honors_data()
    honor_index = next((i for i, honor in enumerate(honors_data.get(owner_username, [])) if honor.get('id') == honor_id), -1)
    if honor_index == -1:
        return jsonify(success=False, error="服务器数据不一致，无法定位荣誉记录。"), 500

    # 4. 更新荣誉的文本信息
    honors_data[owner_username][honor_index].update({
        "name": new_name,
        "type": request.form.get('honor_type'),
        "honor_level": request.form.get('honor_level'),
        "date": request.form.get('honor_date'),
        "stamp": request.form.get('honor_stamp'),
        "stamp_other": request.form.get('honor_stamp_other', ""),
    })

    # 5. 【核心修复】如果上传了新文件，则处理它
    new_image_file = request.files.get('honor_image')
    
    if new_image_file and new_image_file.filename:
        if new_image_file.filename[-3:] != "pdf":
            original_filename = secure_filename(new_image_file.filename)
            _, ext = os.path.splitext(original_filename)
        else:
            original_filename = new_image_file.filename
            ext = '.pdf'
        
        if not allowed_file(new_image_file.filename):
            return jsonify(success=False, error="上传了无效的文件格式。"), 400

        temp_path = None # 确保 temp_path 在 try 外定义
        try:
            current_upload_folder = os.path.join(UPLOAD_FOLDER, owner_username)
            if not os.path.exists(current_upload_folder):
                os.makedirs(current_upload_folder)

            # --- 【关键修正】采用更稳健的临时文件命名方式 ---
            temp_basename = f"temp_{int(time.time())}_{random.randint(1000, 9999)}"
            temp_filename = temp_basename + ext # 正确地保留原始扩展名
            temp_path = os.path.join(current_upload_folder, temp_filename)
            new_image_file.save(temp_path)
            # --- 修正结束 ---

            pil_image = None
            if ext.lower() == '.pdf':
                import fitz
                doc = fitz.open(temp_path)
                if len(doc) == 0: raise ValueError("PDF文件为空。")
                page = doc.load_page(0)
                pix = page.get_pixmap(dpi=200)
                doc.close()
                mode = "RGBA" if pix.alpha else "RGB"
                pil_image = Image.frombytes(mode, (pix.width, pix.height), pix.samples)
            else:
                pil_image = Image.open(temp_path)
                pil_image = ImageOps.exif_transpose(pil_image)

            if not pil_image:
                raise ValueError("无法从上传的文件生成图像对象。")

            # 生成新的唯一文件名
            timestamp = int(time.time())
            rand_int = random.randint(100, 999)
            output_image_filename = f"{owner_username}_{timestamp}_{rand_int}.jpg"
            output_thumb_filename = f"{os.path.splitext(output_image_filename)[0]}_thumb.jpg"
            
            output_image_path = os.path.join(current_upload_folder, output_image_filename)
            output_thumb_path = os.path.join(current_upload_folder, output_thumb_filename)

            # 保存主图 (统一为JPG) 和缩略图
            # (此部分逻辑与 add_honor 相同，此处不再赘述，确保您的代码中是完整的)
            if pil_image.mode in ('RGBA', 'P'):
                background = Image.new('RGB', pil_image.size, (255, 255, 255))
                mask = pil_image.convert('RGBA').split()[3]
                background.paste(pil_image, mask=mask)
                background.save(output_image_path, "JPEG", quality=85, optimize=True)
            else:
                pil_image.convert('RGB').save(output_image_path, "JPEG", quality=85, optimize=True)

            thumb_image = pil_image.copy()
            thumb_image.thumbnail((400, 400), Image.Resampling.LANCZOS)
            if thumb_image.mode in ('RGBA', 'P'):
                thumb_bg = Image.new('RGB', thumb_image.size, (255, 255, 255))
                thumb_mask = thumb_image.convert('RGBA').split()[3]
                thumb_bg.paste(thumb_image, mask=thumb_mask)
                thumb_bg.save(output_thumb_path, "JPEG", quality=85, optimize=True)
            else:
                thumb_image.convert('RGB').save(output_thumb_path, "JPEG", quality=85, optimize=True)
            
            pil_image.close()
            thumb_image.close()
            
            # 删除旧文件
            if honor_to_edit.get('image_filename'):
                old_image_path = os.path.join(current_upload_folder, honor_to_edit['image_filename'])
                if os.path.exists(old_image_path): os.remove(old_image_path)
            if honor_to_edit.get('thumb_filename'):
                old_thumb_path = os.path.join(current_upload_folder, honor_to_edit['thumb_filename'])
                if os.path.exists(old_thumb_path): os.remove(old_thumb_path)
                
            # 更新JSON中的文件名
            honors_data[owner_username][honor_index]['image_filename'] = output_image_filename
            honors_data[owner_username][honor_index]['thumb_filename'] = output_thumb_filename

        except Exception as e:
            logger.error(f"编辑时处理新上传文件失败: {e}", exc_info=True)
            return jsonify(success=False, error=f"文件处理失败: {e}"), 500
        finally:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)

    # 6. 保存所有更改
    save_honors_data(honors_data)
    
    return jsonify(success=True, message=f"荣誉 '{new_name}' 更新成功！")


@app.route('/delete_honor/<string:honor_id>', methods=['POST'])
@login_required
def delete_honor(honor_id):
    """
    【修改】删除荣誉记录。
    增加了权限检查：必须是荣誉的所有者或管理员才能操作。
    """
    # 1. 查找荣誉及其所有者
    honor_to_delete, owner_username = find_honor_and_owner(honor_id)

    if not honor_to_delete:
        logger.warning(f"用户 '{session.get('username')}' 尝试删除不存在的荣誉 ID: {honor_id}")
        flash("无法找到要删除的荣誉记录。", "error")
        return redirect(request.referrer or url_for('home')) # 重定向上一个页面

    # 2. 权限验证：必须是所有者或管理员
    is_admin = session.get('role') == 'admin'
    is_owner = session.get('username') == owner_username
    if not is_owner and not is_admin:
        logger.warning(f"权限不足：用户 '{session.get('username')}' 尝试删除属于 '{owner_username}' 的荣誉 ID: {honor_id}")
        flash("您没有权限删除此条荣誉记录。", "error")
        return redirect(request.referrer or url_for('home'))

    # 3. 执行删除操作 (使用 owner_username 定位数据)
    honors_data = load_honors_data()
    current_upload_folder = os.path.join(UPLOAD_FOLDER, owner_username) # 关键：使用荣誉所有者的上传目录

    honor_index = next((i for i, honor in enumerate(honors_data.get(owner_username, [])) if honor.get('id') == honor_id), -1)

    if honor_index == -1:
        logger.error(f"数据不一致：在用户 '{owner_username}' 的列表中找不到荣誉 ID '{honor_id}'")
        flash("服务器数据不一致，无法删除。", "error")
        return redirect(request.referrer or url_for('home'))

    deleted_honor_name = honor_to_delete.get('name', '未知荣誉')
    image_filename = honor_to_delete.get('image_filename')

    # 从数据文件中移除记录
    honors_data[owner_username].pop(honor_index)
    if not honors_data[owner_username]: # 如果列表为空，可以移除该用户键
        del honors_data[owner_username]
    save_honors_data(honors_data)

    # 删除关联的图片文件 (逻辑保持不变)
    if image_filename:
        original_path = os.path.join(current_upload_folder, image_filename)
        base, ext = os.path.splitext(image_filename)
        thumb_path = os.path.join(current_upload_folder, f"{base}_thumb{ext}")
        for path_to_delete in [original_path, thumb_path]:
            if os.path.exists(path_to_delete):
                try:
                    os.remove(path_to_delete)
                    logger.info(f"成功删除文件: {path_to_delete}")
                except OSError as e:
                    logger.error(f"删除文件失败 '{path_to_delete}': {e}")

    logger.info(f"用户 '{session.get('username')}' 成功删除了属于 '{owner_username}' 的荣誉 ID: {honor_id} (名: {deleted_honor_name})")
    flash(f"已成功删除教师 '{owner_username}' 的荣誉: '{deleted_honor_name}'。", "success")
    return redirect(request.referrer or url_for('home'))

# --- 错误处理 ---
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error_code=404, error_message="页面未找到"), 404

@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"服务器内部错误: {e}", exc_info=True)
    return render_template('error.html', error_code=500, error_message="服务器内部错误"), 500

# --- 其他路由 (honor_table, download_honor_image_jpg, download_honors_zip) 保持不变 ---
@app.route('/honor_table')
@login_required
def honor_table():
    """【修改】显示当前登录用户荣誉的表格视图, 支持日期筛选和关键词搜索"""
    current_username = session.get('username')
    if not current_username:
        flash("用户未登录。", "error")
        return redirect(url_for('login'))

    logger.info(f"用户 '{current_username}' 正在访问自己的荣誉表格")
    try:
        honors_data = load_honors_data()
        user_data = load_user_data()
        user_honors_list_raw = honors_data.get(current_username, [])

        # --- 1. 获取筛选和搜索参数 ---
        selected_date_filter = request.args.get('filter_date', 'all')
        search_query = request.args.get('q', '').strip() # 【新增】获取搜索关键词
        logger.info(f"用户 '{current_username}' 使用日期筛选: {selected_date_filter}, 搜索词: '{search_query}'")

        # --- 2. 按日期筛选 ---
        today = datetime.date.today()
        cutoff_date = None
        if selected_date_filter == 'last_year': cutoff_date = today - relativedelta(years=1)
        elif selected_date_filter == 'last_3_years': cutoff_date = today - relativedelta(years=3)
        elif selected_date_filter == 'last_5_years': cutoff_date = today - relativedelta(years=5)

        filtered_by_date_honors = []
        if cutoff_date:
            for honor in user_honors_list_raw:
                honor_date = parse_date_safe(honor.get('date'))
                if honor_date and honor_date >= cutoff_date:
                    filtered_by_date_honors.append(honor)
        else:
            filtered_by_date_honors = user_honors_list_raw

        # --- 3. 【新增】按关键词搜索 ---
        if search_query:
            final_filtered_honors = [
                honor for honor in filtered_by_date_honors
                if search_query.lower() in honor.get('name', '').lower()
            ]
        else:
            final_filtered_honors = filtered_by_date_honors

        # --- 4. 数据处理和排序 ---
        processed_honors = []
        for honor in final_filtered_honors:
            honor_copy = honor.copy()
            honor_copy['display_level'] = honor.get('honor_level') or honor.get('level') or '未指定'
            processed_honors.append(honor_copy)

        processed_honors.sort(key=lambda x: parse_date_safe(x.get('date')) or datetime.date.min, reverse=True)
        logger.info(f"为用户 '{current_username}' 加载了 {len(processed_honors)} 条荣誉记录 (日期筛选: {selected_date_filter}, 搜索: '{search_query}')")

        current_user_info = user_data.get(current_username, {})
        current_truename = current_user_info.get('truename', current_username)

        # --- 5. 准备响应数据 ---
        response_data = {
            'honors': processed_honors,
            'user_truename': current_truename,
            'selected_date_filter': selected_date_filter,
            'search_query': search_query, # 【新增】将搜索词传回模板
            'honor_types': HONOR_TYPE,
            'honor_levels': LEVEL_TYPE
        }
        return render_template('honor_table.html', **response_data)

    except Exception as e:
        logger.error(f"为用户 '{current_username}' 生成荣誉表格时发生错误: {e}", exc_info=True)
        flash("加载您的荣誉列表时发生错误，请稍后再试。", "error")
        return redirect(url_for('home'))


def sanitize_filename(filename):
    """Removes or replaces characters invalid in filenames."""
    name = filename.strip('. ')
    name = re.sub(r'[\\/*?:"<>|]', '_', name)
    name = re.sub(r'_+', '_', name)
    return name[:200]


@app.route('/download_honor_image/<string:honor_id>/jpg')
@login_required
def download_honor_image_jpg(honor_id):
    """Downloads the image for a specific honor, converted to JPG."""
    current_username = session.get('username')
    logger.info(f"用户 '{current_username}' 请求下载荣誉 ID '{honor_id}' 的 JPG 图片")
    try:
        honors_data = load_honors_data()
        user_honors = honors_data.get(current_username, [])
        honor_to_download = next((h for h in user_honors if h.get('id') == honor_id), None)

        if not honor_to_download:
            logger.warning(f"用户 '{current_username}' 尝试下载无效或不属于自己的荣誉 ID: {honor_id}")
            abort(404, description="找不到指定的荣誉记录或无权访问。")

        image_filename = honor_to_download.get('image_filename')
        if not image_filename:
            logger.warning(f"荣誉 ID '{honor_id}' 没有关联的图片文件。")
            abort(404, description="该荣誉记录没有关联的证明文件。")

        user_upload_folder = os.path.abspath(os.path.join(UPLOAD_FOLDER, current_username))
        original_image_path = os.path.join(user_upload_folder, image_filename)

        if not os.path.exists(original_image_path):
            logger.error(f"用户 '{current_username}' 的图片文件不存在: {original_image_path}")
            abort(404, description="找不到对应的图片文件。")

        img = Image.open(original_image_path)
        output_buffer = io.BytesIO()
        original_mode = img.mode

        if img.mode in ('RGBA', 'P'):
            logger.debug(f"图片 '{image_filename}' (模式: {img.mode}) 正在转换为 RGB 用于 JPG 保存。")
            background = Image.new('RGB', img.size, (255, 255, 255))
            try: background.paste(img, mask=img.split()[3])
            except IndexError:
                 try: background.paste(img, mask=img.convert("RGBA").split()[3])
                 except Exception: background.paste(img)
            img.close()
            img = background
        elif img.mode != 'RGB':
             logger.debug(f"图片 '{image_filename}' (模式: {img.mode}) 正在尝试转换为 RGB。")
             try: img = img.convert('RGB')
             except Exception as conv_e:
                 logger.error(f"无法将图片 '{image_filename}' (模式: {original_mode}) 转换为 RGB: {conv_e}")
                 img.close()
                 abort(500, description="图片格式转换失败。")

        img.save(output_buffer, format='JPEG', quality=85, optimize=True)
        img.close()
        output_buffer.seek(0)

        honor_name = honor_to_download.get('name', 'honor')
        honor_date = honor_to_download.get('date', '')
        download_filename = sanitize_filename(f"{honor_name}_{honor_date}.jpg")
        logger.info(f"成功转换图片 '{image_filename}' 为 JPG，准备发送为 '{download_filename}'")

        return send_file(output_buffer, mimetype='image/jpeg', as_attachment=True, download_name=download_filename)

    except FileNotFoundError:
         logger.error(f"文件未找到错误处理荣誉ID '{honor_id}' 的下载请求。")
         abort(404, description="找不到图片文件。")
    except Exception as e:
        logger.error(f"下载并转换荣誉图片 ID '{honor_id}' 时发生错误: {e}", exc_info=True)
        abort(500, description="处理图片下载时发生服务器内部错误。")


@app.route('/download_honors_zip', methods=['POST'])
@login_required
def download_honors_zip():
    """Creates a ZIP file containing JPGs for the requested honor IDs."""
    current_username = session.get('username')
    logger.info(f"用户 '{current_username}' 请求批量下载荣誉图片为 ZIP")

    if not request.is_json:
        logger.warning(f"用户 '{current_username}' 的批量下载请求不是 JSON 格式。")
        return jsonify(error="请求必须是 JSON 格式"), 400

    data = request.get_json()
    honor_ids = data.get('honor_ids')

    if not isinstance(honor_ids, list) or not honor_ids:
        logger.warning(f"用户 '{current_username}' 的批量下载请求缺少或包含无效的 honor_ids 列表。")
        return jsonify(error="请求体必须包含一个非空的 'honor_ids' 列表"), 400

    logger.info(f"用户 '{current_username}' 请求下载的荣誉 IDs: {honor_ids}")

    try:
        honors_data = load_honors_data()
        user_honors_all = honors_data.get(current_username, [])
        user_upload_folder = os.path.abspath(os.path.join(UPLOAD_FOLDER, current_username))
        honors_to_zip_map = {h['id']: h for h in user_honors_all if h['id'] in honor_ids}

        if len(honors_to_zip_map) != len(honor_ids):
            missing_or_unowned = set(honor_ids) - set(honors_to_zip_map.keys())
            logger.warning(f"用户 '{current_username}' 请求的 IDs 包含无效或不属于自己的荣誉: {missing_or_unowned}")
            return jsonify(error=f"部分请求的荣誉 ID 无效或不属于您: {', '.join(missing_or_unowned)}"), 403

        zip_buffer = io.BytesIO()
        processed_count, skipped_count = 0, 0
        processed_filenames = set()

        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for honor_id, honor in honors_to_zip_map.items():
                image_filename = honor.get('image_filename')
                if not image_filename:
                    logger.warning(f"荣誉 ID '{honor_id}' (名称: {honor.get('name')}) 无图片文件，跳过。")
                    skipped_count += 1; continue

                original_image_path = os.path.join(user_upload_folder, image_filename)
                if not os.path.exists(original_image_path):
                    logger.warning(f"荣誉 ID '{honor_id}' 的图片文件 '{original_image_path}' 不存在，跳过。")
                    skipped_count += 1; continue

                img = None # Ensure img is defined for finally block
                try:
                    img = Image.open(original_image_path)
                    jpg_buffer = io.BytesIO()
                    original_mode = img.mode

                    if img.mode in ('RGBA', 'P'):
                         background = Image.new('RGB', img.size, (255, 255, 255))
                         try: background.paste(img, mask=img.split()[3])
                         except IndexError:
                             try: background.paste(img, mask=img.convert("RGBA").split()[3])
                             except Exception: background.paste(img)
                         img.close(); img = background
                    elif img.mode != 'RGB':
                         try: converted_img = img.convert('RGB'); img.close(); img = converted_img
                         except Exception as conv_e:
                            logger.error(f"ZIP: 无法将图片 '{image_filename}' (模式: {original_mode}) 转为 RGB: {conv_e}，跳过。")
                            skipped_count += 1; continue # Skip this image

                    img.save(jpg_buffer, format='JPEG', quality=85, optimize=True)
                    jpg_buffer.seek(0)

                    base_name = sanitize_filename(f"{honor.get('name', 'honor')}_{honor.get('date', '')}")
                    zip_entry_name = f"{base_name}.jpg"
                    counter = 1
                    while zip_entry_name in processed_filenames:
                        zip_entry_name = f"{base_name}_{counter}.jpg"; counter += 1
                    processed_filenames.add(zip_entry_name)

                    zipf.writestr(zip_entry_name, jpg_buffer.getvalue())
                    processed_count += 1
                    logger.debug(f"成功添加 '{zip_entry_name}' (来自 {image_filename}) 到 ZIP 文件。")

                except Exception as img_proc_e:
                    logger.error(f"处理荣誉 ID '{honor_id}' 的图片 '{image_filename}' 时出错: {img_proc_e}", exc_info=False)
                    skipped_count += 1
                finally:
                    if img and hasattr(img, 'close'): img.close() # Ensure image is closed


        zip_buffer.seek(0)
        zip_download_filename = f"{current_username}_honors_{datetime.date.today().strftime('%Y%m%d')}.zip"
        logger.info(f"为用户 '{current_username}' 创建 ZIP 文件完成。处理: {processed_count}, 跳过: {skipped_count}。发送为 '{zip_download_filename}'")

        if processed_count == 0:
             return jsonify(error="未能成功处理任何请求的图片文件。"), 400

        flash(message='已为你成功下载当前视图的所有荣誉', category='记得下次再来呀')
        return send_file(zip_buffer, mimetype='application/zip', as_attachment=True, download_name=zip_download_filename)

    except Exception as e:
        logger.error(f"创建荣誉 ZIP 文件时发生错误: {e}", exc_info=True)
        return jsonify(error="创建 ZIP 文件时发生服务器内部错误。"), 500

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    """管理员后台主页，重定向到用户管理页面"""
    return redirect(url_for('admin_user_management'))

@app.route('/admin/users')
@login_required
@admin_required
def admin_user_management():
    """显示所有用户的管理页面"""
    logger.info(f"管理员 '{session.get('username')}' 访问用户管理页面")
    users_data = load_user_data()
    # 传递给模板前，移除密码字段，增加安全性
    users_list_safe = []
    for username, data in users_data.items():
        safe_data = data.copy()
        safe_data.pop('password', None) # 从副本中移除密码
        users_list_safe.append(safe_data)

    # 按用户名排序
    users_list_sorted = sorted(users_list_safe, key=lambda x: x['username'])

    return render_template('admin/user_management.html', users=users_list_sorted)


@app.route('/admin/user/add', methods=['POST'])
@login_required
@admin_required
def admin_add_user():
    """管理员添加新用户"""
    username = request.form.get('username', '').strip()
    password = request.form.get('password')
    truename = request.form.get('truename', '').strip()
    major = request.form.get('major', '').strip()
    employment_day = request.form.get('employment_day', '').strip()
    role = request.form.get('role', 'user').strip()

    if not all([username, password, truename, employment_day, role]):
        flash("所有字段均为必填项。", "error")
        return redirect(url_for('admin_user_management'))

    if len(password) < 6:
        flash("密码长度不能少于6位。", "error")
        return redirect(url_for('admin_user_management'))

    users = load_user_data()
    if username in users:
        flash(f"用户名 '{username}' 已存在。", "error")
        return redirect(url_for('admin_user_management'))

    users[username] = {
        "username": username,
        "password": generate_password_hash(password),
        "truename": truename,
        "major": major,
        "employment_day": employment_day,
        "role": role,
        "motto": "" # 初始为空
    }
    save_data(USER_DATA_FILE, users)
    logger.info(f"管理员 '{session.get('username')}' 添加了新用户 '{username}' (角色: {role})")
    flash(f"用户 '{username}' 添加成功！", "success")
    return redirect(url_for('admin_user_management'))


@app.route('/admin/user/reset_password/<username>', methods=['POST'])
@login_required
@admin_required
def admin_reset_password(username):
    """管理员重置用户密码"""
    new_password = request.form.get('new_password')
    if not new_password or len(new_password) < 6:
        flash("新密码不能为空且长度至少为6位。", "error")
        return redirect(url_for('admin_user_management'))

    users = load_user_data()
    if username not in users:
        flash("用户不存在。", "error")
        return redirect(url_for('admin_user_management'))

    users[username]['password'] = generate_password_hash(new_password)
    save_data(USER_DATA_FILE, users)
    logger.info(f"管理员 '{session.get('username')}' 重置了用户 '{username}' 的密码。")
    flash(f"用户 '{username}' 的密码已成功重置！", "success")
    return redirect(url_for('admin_user_management'))


@app.route('/admin/user/change_role/<username>', methods=['POST'])
@login_required
@admin_required
def admin_change_role(username):
    """管理员修改用户角色"""
    if username == session.get('username'):
        flash("出于安全考虑，您不能在此处修改自己的角色。", "warning")
        return redirect(url_for('admin_user_management'))

    new_role = request.form.get('role')
    if new_role not in ['user', 'admin']:
        flash("无效的角色。", "error")
        return redirect(url_for('admin_user_management'))

    users = load_user_data()
    if username not in users:
        flash("用户不存在。", "error")
        return redirect(url_for('admin_user_management'))

    users[username]['role'] = new_role
    save_data(USER_DATA_FILE, users)
    logger.info(f"管理员 '{session.get('username')}' 将用户 '{username}' 的角色修改为 '{new_role}'")
    flash(f"用户 '{username}' 的角色已更新为 '{new_role}'。", "success")
    return redirect(url_for('admin_user_management'))


@app.route('/admin/user/delete/<username>', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(username):
    """管理员删除用户及其所有数据"""
    if username == session.get('username'):
        flash("出于安全考虑，您不能删除自己的账户。", "warning")
        return redirect(url_for('admin_user_management'))

    # 1. 从 user.json 删除用户
    users = load_user_data()
    if username not in users:
        flash("要删除的用户不存在。", "error")
        return redirect(url_for('admin_user_management'))
    deleted_user_truename = users.pop(username).get('truename', username)
    save_data(USER_DATA_FILE, users)
    logger.info(f"已从用户数据库中删除 '{username}'。")

    # 2. 从 honors.json 删除用户的荣誉
    honors = load_honors_data()
    if username in honors:
        honors.pop(username)
        save_honors_data(honors)
        logger.info(f"已删除用户 '{username}' 的所有荣誉记录。")

    # 3. 删除用户的上传文件夹
    user_upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], username)
    if os.path.exists(user_upload_dir):
        try:
            shutil.rmtree(user_upload_dir)
            logger.info(f"已成功删除用户 '{username}' 的上传目录: {user_upload_dir}")
        except Exception as e:
            logger.error(f"删除用户 '{username}' 的目录 '{user_upload_dir}' 时失败: {e}")
            flash(f"用户信息已删除，但删除文件目录时发生错误: {e}", "error")

    logger.warning(f"管理员 '{session.get('username')}' 删除了用户 '{username}' ({deleted_user_truename}) 及其所有数据。")
    flash(f"用户 '{deleted_user_truename}' ({username}) 及其所有数据已彻底删除。", "success")
    return redirect(url_for('admin_user_management'))


# --- 主程序入口 ---
if __name__ == '__main__':
    print(f"上传根目录: {os.path.abspath(UPLOAD_FOLDER)}")
    print(f"荣誉数据: {os.path.abspath(HONORS_DATA_FILE)}")
    print(f"用户数据: {os.path.abspath(USER_DATA_FILE)}")
    print(f"将尝试加载README文件: {os.path.abspath(README_FILE)}") # <<< 新增：提示README路径
    app.run(debug=True, host='0.0.0.0', port=8001)