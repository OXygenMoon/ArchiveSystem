import io
import zipfile
from PIL import Image,ImageOps
import re
import os
import json
import shutil # 删除目录树
from flask import (
    Flask, render_template, request, jsonify, redirect, url_for,
    session, send_from_directory, flash, abort, send_file
)
# from flask_session import Session # 如果需要 Redis Session，取消注释
import random
import datetime
from dateutil.relativedelta import relativedelta
from werkzeug.utils import secure_filename
import time
from functools import wraps
from config import HONOR_TYPE, LEVEL_TYPE, MAJOR_TYPE # 假设你的 config.py 有这两个列表
from werkzeug.security import generate_password_hash, check_password_hash

# --- 配置 ---
SECRET_KEY = os.urandom(24)
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
USER_DATA_FILE = 'data/user.json'
HONORS_DATA_FILE = 'data/honors.json'
README_FILE = 'README.md' # <<< 新增：定义 README 文件名

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_USE_SIGNER'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=7)
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024 # 限制为 16 MB

# --- 日志 ---
logger = app.logger

# --- 确保目录和文件存在 ---
# ... (保持不变) ...
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


@app.route('/login', methods=['POST'])
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


@app.route('/add_honor', methods=['GET', 'POST'])
@login_required
def add_honor():
    # ... (add_honor 路由保持不变) ...
    username = session.get('username')
    honor_types = HONOR_TYPE
    honor_levels = LEVEL_TYPE
    current_upload_folder = os.path.join(UPLOAD_FOLDER, username)
    if not os.path.exists(current_upload_folder):
         try: os.makedirs(current_upload_folder)
         except OSError as e:
             logger.error(f"添加荣誉前无法创建目录 '{current_upload_folder}': {e}")
             flash("无法访问存储空间，添加失败。", "error")
             return redirect(url_for('home'))

    if request.method == 'POST':
        honor_name = request.form.get('honor_name')
        honor_type = request.form.get('honor_type')
        honor_date = request.form.get('honor_date')
        honor_stamp = request.form.get('honor_stamp')
        honor_stamp_other = request.form.get('honor_stamp_other') or ""
        honor_image = request.files.get('honor_image')
        honor_level = request.form.get('honor_level')

        if not all([honor_name, honor_type, honor_level, honor_date, honor_stamp]):
            flash("请填写所有必填项（除图片外）。", "error")
            form_data = request.form.to_dict()
            return render_template('add_honor.html', honor_types=honor_types, honor_levels=honor_levels, form_data=form_data)

        if not honor_image or honor_image.filename == '':
            flash("请上传荣誉证明图片。", "error")
            form_data = request.form.to_dict()
            return render_template('add_honor.html', honor_types=honor_types, honor_levels=honor_levels, form_data=form_data)
        if not allowed_file(honor_image.filename):
            flash("无效的图片格式，请上传 png, jpg, jpeg, gif 文件。", "error")
            form_data = request.form.to_dict()
            return render_template('add_honor.html', honor_types=honor_types, honor_levels=honor_levels, form_data=form_data)

        try:
            # filename = secure_filename(honor_image.filename)
            # base, ext = os.path.splitext(filename)
            base, ext = os.path.splitext(honor_image.filename)
            ext = ext.lower()
            timestamp = int(time.time())
            rand_int = random.randint(100, 999)
            unique_filename = f"{username}_{timestamp}_{rand_int}{ext}"
            save_path = os.path.join(current_upload_folder, unique_filename)
            honor_image.save(save_path)
            logger.info(f"用户 '{username}' 上传原始文件 '{unique_filename}' 到 '{current_upload_folder}' 成功")

            thumb_filename = None
            try:
                img = Image.open(save_path)
                img = ImageOps.exif_transpose(img) # 防止图片自己旋转

                thumbnail_size = (400, 400)
                img.thumbnail(thumbnail_size, Image.Resampling.LANCZOS)

                # thumb_base, thumb_ext = os.path.splitext(unique_filename)
                thumb_base, thumb_ext = os.path.splitext(unique_filename)
                thumb_ext= thumb_ext.lower()
                thumb_filename = f"{thumb_base}_thumb{thumb_ext}"
                thumb_save_path = os.path.join(current_upload_folder, thumb_filename)
                img.save(thumb_save_path, quality=85, optimize=True)
                logger.info(f"为 '{unique_filename}' 生成缩略图 '{thumb_filename}' 成功")
                img.close()
            except Exception as thumb_e:
                logger.error(f"为 '{unique_filename}' 生成缩略图失败: {thumb_e}", exc_info=True)
                thumb_filename = None

        except Exception as e:
            logger.error(f"文件上传或处理失败: {e}", exc_info=True)
            flash(f"文件上传或处理失败: {e}", "error")
            form_data = request.form.to_dict()
            return render_template('add_honor.html', honor_types=honor_types, honor_levels=honor_levels, form_data=form_data)

        new_honor = {
            "id": f"honor_{timestamp}_{rand_int}",
            "name": honor_name,
            "type": honor_type,
            "date": honor_date,
            "stamp": honor_stamp,
            "stamp_other": honor_stamp_other,
            "image_filename": unique_filename,
            "honor_level": honor_level
            # "thumb_filename": thumb_filename # 如果需要记录缩略图名
        }

        honors_data = load_honors_data()
        if username not in honors_data:
            honors_data[username] = []
        honors_data[username].append(new_honor)
        save_honors_data(honors_data)

        logger.info(f"用户 '{username}' 添加新荣誉 '{honor_name}' (ID: {new_honor['id']}) 成功")
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
    """
    【修改】编辑荣誉记录。
    增加了权限检查：必须是荣誉的所有者或管理员才能操作。
    """
    # 1. 查找荣誉及其所有者
    honor_to_edit, owner_username = find_honor_and_owner(honor_id)

    if not honor_to_edit:
        logger.warning(f"用户 '{session.get('username')}' 尝试编辑不存在的荣誉 ID: {honor_id}")
        return jsonify(success=False, error="无法找到指定的荣誉记录。"), 404

    # 2. 权限验证：必须是所有者或管理员
    is_admin = session.get('role') == 'admin'
    is_owner = session.get('username') == owner_username
    if not is_owner and not is_admin:
        logger.warning(f"权限不足：用户 '{session.get('username')}' 尝试编辑属于 '{owner_username}' 的荣誉 ID: {honor_id}")
        return jsonify(success=False, error="您没有权限编辑此条荣誉记录。"), 403

    # 3. 执行编辑操作 (使用 owner_username 定位数据)
    honors_data = load_honors_data()
    current_upload_folder = os.path.join(UPLOAD_FOLDER, owner_username) # 关键：使用荣誉所有者的上传目录

    honor_index = next((i for i, honor in enumerate(honors_data.get(owner_username, [])) if honor.get('id') == honor_id), -1)

    if honor_index == -1:
        logger.error(f"数据不一致：在用户 '{owner_username}' 的列表中找不到荣誉 ID '{honor_id}'")
        return jsonify(success=False, error="服务器数据不一致，无法定位荣誉记录。"), 500

    try:
        # (此部分逻辑与原函数基本一致，但确保了操作对象是 owner_username)
        new_name = request.form.get('honor_name')
        new_type = request.form.get('honor_type')
        new_level = request.form.get('honor_level')
        new_date = request.form.get('honor_date')
        new_stamp = request.form.get('honor_stamp')
        new_stamp_other = request.form.get('honor_stamp_other', "")
        new_image_file = request.files.get('honor_image')

        if not all([new_name, new_type, new_level, new_date, new_stamp]):
             return jsonify(success=False, error="请填写所有必填项。"), 400

        old_filename = honor_to_edit.get('image_filename')
        updated_filename = old_filename

        if new_image_file and new_image_file.filename != '':
            if allowed_file(new_image_file.filename):
                try:
                    _, ext = os.path.splitext(new_image_file.filename)
                    ext = ext.lower()
                    timestamp = int(time.time())
                    rand_int = random.randint(100, 999)
                    # 文件名中包含所有者，避免冲突
                    updated_filename = f"{owner_username}_{timestamp}_{rand_int}{ext}"
                    save_path = os.path.join(current_upload_folder, updated_filename)
                    new_image_file.save(save_path)
                    logger.info(f"用户 '{session.get('username')}' 为荣誉 '{honor_id}' 上传了新图片 '{updated_filename}'")

                    # (缩略图生成和旧文件删除逻辑保持不变)
                    try:
                        img = Image.open(save_path)
                        img = ImageOps.exif_transpose(img)
                        thumbnail_size = (400, 400)
                        img.thumbnail(thumbnail_size, Image.Resampling.LANCZOS)
                        thumb_base, thumb_ext = os.path.splitext(updated_filename)
                        thumb_filename_to_save = f"{thumb_base}_thumb{thumb_ext}"
                        thumb_save_path = os.path.join(current_upload_folder, thumb_filename_to_save)
                        img.save(thumb_save_path, quality=85, optimize=True)
                        img.close()
                    except Exception as thumb_e:
                        logger.error(f"为新图片 '{updated_filename}' 生成缩略图失败: {thumb_e}")

                    if old_filename and old_filename != updated_filename:
                        old_path = os.path.join(current_upload_folder, old_filename)
                        if os.path.exists(old_path): os.remove(old_path)
                        old_base, old_ext = os.path.splitext(old_filename)
                        old_thumb_filename = f"{old_base}_thumb{old_ext}"
                        old_thumb_path = os.path.join(current_upload_folder, old_thumb_filename)
                        if os.path.exists(old_thumb_path): os.remove(old_thumb_path)
                except Exception as e:
                    logger.error(f"更新荣誉 '{honor_id}' 的图片时处理失败: {e}", exc_info=True)
                    return jsonify(success=False, error=f"图片处理失败: {e}"), 500
            else:
                return jsonify(success=False, error="上传了无效的图片格式。请使用 png, jpg, jpeg, gif。"), 400

        updated_honor_data = {
            "id": honor_id, "name": new_name, "type": new_type, "date": new_date,
            "stamp": new_stamp, "stamp_other": new_stamp_other,
            "image_filename": updated_filename, "honor_level": new_level
        }

        honors_data[owner_username][honor_index] = updated_honor_data
        save_honors_data(honors_data)

        logger.info(f"用户 '{session.get('username')}' 成功编辑了属于 '{owner_username}' 的荣誉 ID: {honor_id}")
        return jsonify(success=True, message=f"荣誉 '{new_name}' 更新成功！")

    except Exception as e:
        logger.error(f"编辑荣誉 {honor_id} 时发生未知错误: {e}", exc_info=True)
        return jsonify(success=False, error="更新荣誉时发生内部错误。"), 500


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
    # 确保安装了 Markdown 库: pip install Markdown
    app.run(debug=True, host='0.0.0.0', port=8888)