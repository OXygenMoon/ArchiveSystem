import io
import zipfile
from PIL import Image
import re
import os
import json
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
from config import HONOR_TYPE, LEVEL_TYPE # 假设你的 config.py 有这两个列表
import markdown # <<< 新增：导入 markdown 库

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
# ... (parse_date_safe, allowed_file, load_data, save_data, load_honors_data, save_honors_data, load_user_data - 保持不变) ...
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

# vvvvvvvvvv  修改部分开始 vvvvvvvvvv
@app.route('/')
def index():
    """主页或登录页"""
    if session.get('logged_in'):
        return redirect(url_for('home'))

    # --- Removed README loading and processing logic ---
    # No need to read README.md or use markdown library here anymore
    # readme_content_html = None # Removed
    # try: ... except: block removed

    welcome = '欢迎来到个人成就系统'
    # Render the template without the readme_html variable
    return render_template('index.html', msg=welcome)

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
        'department': session.get('department'),
        'class': session.get('class'),
        'truename': session.get('truename'),
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


@app.route('/login', methods=['POST', 'GET'])
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
             return render_template('index.html', username=username)

        # --- User found ---
        if username in users:
            # IMPORTANT: Use hashed password comparison in production!
            # Example: if check_password_hash(users[username]['password_hash'], password):
            if password == users[username]['password']: # Replace with secure check
                # --- Login Success ---
                session['logged_in'] = True
                session['username'] = users[username]['username']
                # Store other user details in session
                session['role'] = users[username].get('role', '未知角色')
                session['department'] = users[username].get('department', '')
                session['class'] = users[username].get('class', '')
                session['truename'] = users[username].get('truename', username)
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
            return render_template('index.html', username=username)

    # Fallback (shouldn't normally be reached for POST)
    return redirect(url_for('index'))


# ++++++++ 新增：注册路由占位符 ++++++++
@app.route('/register', methods=['GET'])
def register():
    """注册页面 (占位符)"""
    # 目前只是显示一个信息并重定向回主页
    # 未来可以在这里渲染注册表单模板
    flash("注册功能暂未开放，敬请期待！", "info")
    return redirect(url_for('index'))
# +++++++++++++++++++++++++++++++++++++++


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
            filename = secure_filename(honor_image.filename)
            base, ext = os.path.splitext(filename)
            timestamp = int(time.time())
            rand_int = random.randint(100, 999)
            unique_filename = f"{username}_{timestamp}_{rand_int}{ext}"
            save_path = os.path.join(current_upload_folder, unique_filename)
            honor_image.save(save_path)
            logger.info(f"用户 '{username}' 上传原始文件 '{unique_filename}' 到 '{current_upload_folder}' 成功")

            thumb_filename = None
            try:
                img = Image.open(save_path)
                if img.mode in ('RGBA', 'P') and unique_filename.lower().endswith(('.jpg', '.jpeg')):
                    img = img.convert('RGB')

                thumbnail_size = (400, 400)
                img.thumbnail(thumbnail_size, Image.Resampling.LANCZOS)

                thumb_base, thumb_ext = os.path.splitext(unique_filename)
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


@app.route('/edit_honor/<string:honor_id>', methods=['POST'])
@login_required
def edit_honor(honor_id):
    # ... (edit_honor 路由保持不变) ...
    username = session.get('username')
    honors_data = load_honors_data()
    current_upload_folder = os.path.join(UPLOAD_FOLDER, username)

    if username not in honors_data:
         return jsonify(success=False, error="无法找到用户数据"), 404

    user_honors = honors_data[username]
    honor_to_edit = None
    honor_index = -1
    for i, honor in enumerate(user_honors):
        if honor.get('id') == honor_id:
            honor_to_edit = honor
            honor_index = i
            break

    if honor_to_edit is None:
        logger.warning(f"用户 '{username}' 尝试编辑不存在或不属于自己的荣誉 ID: {honor_id}")
        return jsonify(success=False, error="无法找到指定的荣誉记录，或您无权编辑。"), 404

    try:
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
                    filename = secure_filename(new_image_file.filename)
                    base, ext = os.path.splitext(filename)
                    timestamp = int(time.time())
                    rand_int = random.randint(100, 999)
                    updated_filename = f"{username}_{timestamp}_{rand_int}{ext}"
                    save_path = os.path.join(current_upload_folder, updated_filename)
                    new_image_file.save(save_path)
                    logger.info(f"用户 '{username}' 更新荣誉 '{honor_id}' 的新原始图片为 '{updated_filename}'")

                    try:
                        img = Image.open(save_path)
                        if img.mode in ('RGBA', 'P') and updated_filename.lower().endswith(('.jpg', '.jpeg')):
                           img = img.convert('RGB')
                        thumbnail_size = (400, 400)
                        img.thumbnail(thumbnail_size, Image.Resampling.LANCZOS)
                        thumb_base, thumb_ext = os.path.splitext(updated_filename)
                        thumb_filename_to_save = f"{thumb_base}_thumb{thumb_ext}"
                        thumb_save_path = os.path.join(current_upload_folder, thumb_filename_to_save)
                        img.save(thumb_save_path, quality=85, optimize=True)
                        logger.info(f"为新图片 '{updated_filename}' 生成缩略图 '{thumb_filename_to_save}' 成功")
                        img.close()
                    except Exception as thumb_e:
                        logger.error(f"为新图片 '{updated_filename}' 生成缩略图失败: {thumb_e}", exc_info=True)

                    if old_filename and old_filename != updated_filename:
                        old_path = os.path.join(current_upload_folder, old_filename)
                        if os.path.exists(old_path):
                            try: os.remove(old_path); logger.info(f"成功删除旧原始图片: {old_filename}")
                            except OSError as e: logger.error(f"删除旧原始图片失败 '{old_filename}': {e}")
                        old_base, old_ext = os.path.splitext(old_filename)
                        old_thumb_filename = f"{old_base}_thumb{old_ext}"
                        old_thumb_path = os.path.join(current_upload_folder, old_thumb_filename)
                        if os.path.exists(old_thumb_path):
                            try: os.remove(old_thumb_path); logger.info(f"成功删除旧缩略图: {old_thumb_filename}")
                            except OSError as e: logger.error(f"删除旧缩略图失败 '{old_thumb_filename}': {e}")

                except Exception as e:
                    logger.error(f"更新荣誉 '{honor_id}' 的图片时处理失败: {e}", exc_info=True)
                    return jsonify(success=False, error=f"图片处理失败: {e}"), 500
            else:
                return jsonify(success=False, error="上传了无效的图片格式。请使用 png, jpg, jpeg, gif。"), 400

        updated_honor_data = {
            "id": honor_id,
            "name": new_name,
            "type": new_type,
            "date": new_date,
            "stamp": new_stamp,
            "stamp_other": new_stamp_other,
            "image_filename": updated_filename,
            "honor_level": new_level
        }

        honors_data[username][honor_index] = updated_honor_data
        save_honors_data(honors_data)

        logger.info(f"用户 '{username}' 成功通过 API 编辑荣誉 ID: {honor_id}")
        return jsonify(
            success=True,
            message=f"荣誉 '{new_name}' 更新成功！",
            updated_honor=updated_honor_data
        )

    except Exception as e:
        logger.error(f"编辑荣誉 {honor_id} 时发生未知错误: {e}", exc_info=True)
        return jsonify(success=False, error="更新荣誉时发生内部错误。"), 500


@app.route('/uploads/<username>/<path:filename>')
@login_required
def uploaded_file_user(username, filename):
    # ... (uploaded_file_user 路由保持不变) ...
    if 'username' not in session or session['username'] != username:
         # if session.get('role') != 'admin': # Optional: Allow admins
         logger.warning(f"用户 '{session.get('username')}' 尝试访问用户 '{username}' 的文件: {filename}")
         abort(403)

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

@app.route('/delete_honor/<string:honor_id>', methods=['POST'])
@login_required
def delete_honor(honor_id):
    # ... (delete_honor 路由保持不变) ...
    username = session.get('username')
    honors_data = load_honors_data()
    current_upload_folder = os.path.join(UPLOAD_FOLDER, username)

    if username not in honors_data:
        flash("无法找到您的荣誉数据。", "error")
        return redirect(url_for('home'))

    user_honors = honors_data[username]
    honor_to_delete = None
    honor_index = -1

    for i, honor in enumerate(user_honors):
        if honor.get('id') == honor_id:
            honor_to_delete = honor
            honor_index = i
            break

    if honor_to_delete is None:
        logger.warning(f"用户 '{username}' 尝试删除不存在或不属于自己的荣誉 ID: {honor_id}")
        flash("无法找到要删除的荣誉记录，或您无权删除。", "error")
        return redirect(url_for('home'))

    deleted_honor_name = honor_to_delete.get('name', '未知荣誉')
    image_filename = honor_to_delete.get('image_filename')

    honors_data[username].pop(honor_index)
    save_honors_data(honors_data)

    if image_filename:
        original_path = os.path.join(current_upload_folder, image_filename)
        if os.path.exists(original_path):
            try:
                os.remove(original_path)
                logger.info(f"成功删除原始图片: {image_filename} from {current_upload_folder}")
            except OSError as e:
                logger.error(f"删除原始图片失败 '{image_filename}': {e}")
                flash(f"记录已删除，但删除图片 '{image_filename}' 时遇到问题。", "warning")

        base, ext = os.path.splitext(image_filename)
        thumb_filename_to_delete = f"{base}_thumb{ext}"
        thumb_path = os.path.join(current_upload_folder, thumb_filename_to_delete)
        if os.path.exists(thumb_path):
            try:
                os.remove(thumb_path)
                logger.info(f"成功删除缩略图: {thumb_filename_to_delete} from {current_upload_folder}")
            except OSError as e:
                logger.error(f"删除缩略图失败 '{thumb_filename_to_delete}': {e}")
    else:
        logger.warning(f"荣誉记录 '{honor_id}' 没有关联的 image_filename 字段，无法删除文件。")

    logger.info(f"用户 '{username}' 成功删除荣誉 ID: {honor_id} (名称: {deleted_honor_name})")
    flash(f"荣誉 '{deleted_honor_name}' 已成功删除。", "success")
    return redirect(url_for('home'))

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
    """显示当前登录用户荣誉的表格视图, 支持日期筛选"""
    current_username = session.get('username')
    if not current_username:
        flash("用户未登录。", "error")
        return redirect(url_for('login'))

    logger.info(f"用户 '{current_username}' 正在访问自己的荣誉表格")
    try:
        honors_data = load_honors_data()
        user_data = load_user_data()
        user_honors_list_raw = honors_data.get(current_username, [])

        selected_date_filter = request.args.get('filter_date', 'all')
        logger.info(f"用户 '{current_username}' 使用日期筛选: {selected_date_filter}")
        today = datetime.date.today()
        cutoff_date = None
        try:
            if selected_date_filter == 'last_year': cutoff_date = today - relativedelta(years=1)
            elif selected_date_filter == 'last_3_years': cutoff_date = today - relativedelta(years=3)
            elif selected_date_filter == 'last_5_years': cutoff_date = today - relativedelta(years=5)
        except Exception as e:
            logger.error(f"计算 cutoff_date 时出错: {e}")
            cutoff_date = None

        filtered_by_date_honors = []
        if cutoff_date:
            for honor in user_honors_list_raw:
                honor_date = parse_date_safe(honor.get('date'))
                if honor_date and honor_date >= cutoff_date:
                    filtered_by_date_honors.append(honor)
        else:
            filtered_by_date_honors = user_honors_list_raw

        processed_honors = []
        for honor in filtered_by_date_honors:
            honor_copy = honor.copy()
            honor_copy['display_level'] = honor.get('honor_level') or honor.get('level') or '未指定'
            processed_honors.append(honor_copy)

        processed_honors.sort(key=lambda x: parse_date_safe(x.get('date')) or datetime.date.min, reverse=True)
        logger.info(f"为用户 '{current_username}' 加载了 {len(processed_honors)} 条荣誉记录 (日期筛选: {selected_date_filter})")

        current_user_info = user_data.get(current_username, {})
        current_truename = current_user_info.get('truename', current_username)

        try: from config import HONOR_TYPE, LEVEL_TYPE
        except ImportError:
            logger.warning("无法从 config.py 导入 HONOR_TYPE 或 LEVEL_TYPE。")
            HONOR_TYPE, LEVEL_TYPE = [], []

        response_data = {
            'honors': processed_honors, 'user_truename': current_truename,
            'selected_date_filter': selected_date_filter,
            'honor_types': HONOR_TYPE, 'honor_levels': LEVEL_TYPE
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

        return send_file(zip_buffer, mimetype='application/zip', as_attachment=True, download_name=zip_download_filename)

    except Exception as e:
        logger.error(f"创建荣誉 ZIP 文件时发生错误: {e}", exc_info=True)
        return jsonify(error="创建 ZIP 文件时发生服务器内部错误。"), 500


# --- 主程序入口 ---
if __name__ == '__main__':
    print(f"上传根目录: {os.path.abspath(UPLOAD_FOLDER)}")
    print(f"荣誉数据: {os.path.abspath(HONORS_DATA_FILE)}")
    print(f"用户数据: {os.path.abspath(USER_DATA_FILE)}")
    print(f"将尝试加载README文件: {os.path.abspath(README_FILE)}") # <<< 新增：提示README路径
    # 确保安装了 Markdown 库: pip install Markdown
    app.run(debug=True, host='0.0.0.0', port=8888)