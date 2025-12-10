import os
import io
import zipfile
from PIL import Image, ImageOps
import fitz  # 用于处理PDF
import re
import json
import redis  # (Session 依然使用 Redis)

import shutil  # 删除目录树
from flask import (
    Flask, render_template, request, jsonify, redirect, url_for,
    session, send_from_directory, flash, abort, send_file,
    render_template_string
)
import random
import datetime
from dateutil.relativedelta import relativedelta
from werkzeug.utils import secure_filename
import time
from functools import wraps
from config import HONOR_TYPE, LEVEL_TYPE, MAJOR_TYPE
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

# --- 数据库和命令行工具 ---
import click
from flask.cli import with_appcontext
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import String, Text, ForeignKey, Integer, DateTime, func, JSON
from sqlalchemy.orm import Mapped, mapped_column, DeclarativeBase, relationship
from typing import List

# --- 数据库和命令行工具 结束 ---

# --- 【修改】项目根目录 ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# --- 配置 ---
SECRET_KEY = 'e3ffd14577c6444fb5d7997c27b74ef0'
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}

# --- 【废弃】旧的 JSON 文件 (不再使用) ---
# USER_DATA_FILE = 'data/user.json'
# HONORS_DATA_FILE = 'data/honors.json'
# ACTIVITY_LOG_FILE = 'data/activity_log.json'
# README_FILE = 'README.md'

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=7)
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024  # 限制为 20 MB

# 配置 Redis (Session)
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = redis.Redis(host='localhost', port=6379, db=0)
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_USE_SIGNER'] = True


# --- 【修改】数据库配置 ---
class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'data', 'app.db')
db = SQLAlchemy(app, model_class=Base)
# --- 【修改结束】 ---

# 告知反向代理
app.wsgi_app = ProxyFix(
    app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
)

# --- 日志 ---
logger = app.logger

# --- 确保目录存在 ---
# (我们只保留 uploads 目录的检查)
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
    logger.info(f"创建上传文件夹: {UPLOAD_FOLDER}")
if not os.path.exists('data'):
    os.makedirs('data')
    logger.info("创建数据文件夹: data")


# --- 【修改】数据库模型 (Schema) 定义 ---
# (我们在上一步已添加，这里保持不变)

class User(db.Model):
    """用户模型"""
    __tablename__ = 'user'
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(256), nullable=False)
    truename: Mapped[str] = mapped_column(String(100), nullable=True)
    major: Mapped[str] = mapped_column(String(50), nullable=True)
    employment_day: Mapped[str] = mapped_column(String(20), nullable=True)
    role: Mapped[str] = mapped_column(String(20), nullable=False, default='user')
    motto: Mapped[str] = mapped_column(Text, nullable=True)
    honors: Mapped[List["Honor"]] = relationship(
        back_populates="owner", cascade="all, delete-orphan"
    )
    logs: Mapped[List["ActivityLog"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class Honor(db.Model):
    """荣誉模型"""
    __tablename__ = 'honor'
    id: Mapped[str] = mapped_column(String(50), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    type: Mapped[str] = mapped_column(String(50), index=True)
    date: Mapped[str] = mapped_column(String(20), index=True)
    stamp: Mapped[str] = mapped_column(String(200))
    stamp_other: Mapped[str] = mapped_column(String(200), nullable=True)
    image_filename: Mapped[str] = mapped_column(String(200))
    honor_level: Mapped[str] = mapped_column(String(50), index=True)
    thumb_filename: Mapped[str] = mapped_column(String(200), nullable=True)
    original_pdf_filename: Mapped[str] = mapped_column(String(200), nullable=True)
    page_images: Mapped[list] = mapped_column(JSON, nullable=True)  # 多页PDF
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"), index=True)
    owner: Mapped["User"] = relationship(back_populates="honors")


class ActivityLog(db.Model):
    """活动日志模型"""
    __tablename__ = 'activity_log'
    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime.datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.datetime.utcnow, index=True
    )
    action: Mapped[str] = mapped_column(String(50), index=True)
    details: Mapped[str] = mapped_column(Text, nullable=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"), index=True)
    user: Mapped["User"] = relationship(back_populates="logs")


# --- 辅助函数 ---

def parse_date_safe(date_str):
    """Safely parses YYYY-MM-DD string to date object, returns None on failure."""
    if not date_str:
        return None
    try:
        return datetime.datetime.strptime(date_str, '%Y-%m-%d').date()
    except (ValueError, TypeError):
        logger.warning(f"无法解析日期字符串: '{date_str}'")
        return None


def _get_employment_duration_str(employment_day_str):
    """【新增】辅助函数：根据日期字符串计算入职天数"""
    if not employment_day_str:
        return "N/A"
    try:
        start_date = datetime.datetime.strptime(employment_day_str, '%Y-%m-%d').date()
        today = datetime.datetime.now().date()
        total_days = (today - start_date).days
        if total_days < 0:
            return "未来日期"
        return f"{total_days}天"
    except Exception:
        return "N/A"


def allowed_file(filename):
    """检查文件扩展名是否允许"""
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# --- 【修改】日志函数，现在写入数据库 ---
def log_activity(username, action, details):
    """
    【重构】记录一项用户活动到数据库。
    """
    if not username:
        logger.warning("尝试记录活动，但用户名为空。")
        return

    try:
        # 1. 查找用户
        user = db.session.scalar(
            db.select(User).where(User.username == username)
        )
        if not user:
            logger.warning(f"尝试为不存在的用户 '{username}' 记录活动日志")
            return

        # 2. 创建新日志条目
        new_log_entry = ActivityLog(
            action=action,
            details=details,
            user=user  # 自动关联 user_id
        )
        db.session.add(new_log_entry)

        # 3. 【优化】只保留最新的 50 条
        # (这是一个高级查询，用于删除旧日志，确保性能)
        subq = db.select(ActivityLog.id).where(
            ActivityLog.user_id == user.id
        ).order_by(
            ActivityLog.timestamp.desc()
        ).offset(50).scalar_subquery()  # 找出该用户第50条之后的日志ID

        # 删除所有比第50条更早的日志
        db.session.execute(
            db.delete(ActivityLog).where(
                ActivityLog.user_id == user.id,
                ActivityLog.id.in_(subq)
            )
        )

        # 4. 提交
        db.session.commit()
        logger.info(f"[活动日志] 用户: {username}, 操作: {action}")
    except Exception as e:
        db.session.rollback()  # 出错时回滚
        logger.error(f"为用户 {username} 记录数据库活动日志失败: {e}", exc_info=True)


# --- 装饰器 (保持不变) ---
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
            logger.warning(
                f"用户 '{session.get('username')}' (角色: {session.get('role')}) 尝试访问管理员页面: {request.path}")
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
    return {'now': datetime.datetime.utcnow()}


@app.route('/')
def index():
    """主页，现在包含登录和注册的入口"""
    if session.get('logged_in'):
        return redirect(url_for('home'))

    today_str = datetime.date.today().strftime('%Y-%m-%d')
    return render_template('index.html', majors=MAJOR_TYPE, today=today_str)


# --- 【重构】_get_dashboard_data_for_user 辅助函数 ---
# (从 JSON 切换到 数据库 查询)
def _get_dashboard_data_for_user(target_username, request_args):
    """
    【重构】辅助函数：为特定用户获取看板所需的所有数据。
    """
    # 1. 获取目标用户
    user = db.session.scalar(
        db.select(User).where(User.username == target_username)
    )
    if not user:
        return None  # 用户未找到

    # 2. 获取筛选参数 (来自 request.args)
    selected_types_str = request_args.get('filter_type', '')
    selected_levels_str = request_args.get('filter_level', '')
    selected_types = [t.strip() for t in selected_types_str.split(',') if t.strip()]
    selected_levels = [l.strip() for l in selected_levels_str.split(',') if l.strip()]
    selected_date_filter = request_args.get('filter_date', 'all')

    # 3. 准备基础响应数据
    response_data = {
        'view_username': target_username,
        'view_truename': user.truename,
        'view_major': user.major,
        'view_employment_day': user.employment_day,
        'motto': user.motto,
        'honor_types': HONOR_TYPE,
        'honor_levels': LEVEL_TYPE,
        'selected_types': selected_types,
        'selected_levels': selected_levels,
        'selected_date_filter': selected_date_filter
    }

    # 4. 【重构】获取荣誉和统计数据
    # user.honors 是 SQLAlchemy 提供的关系列表
    user_honors_raw = user.honors
    response_data['total_honor_count'] = len(user_honors_raw)

    # (类型统计)
    honor_type_counts_unfiltered = {honor_type: 0 for honor_type in HONOR_TYPE}
    for honor in user_honors_raw:
        if honor.type in honor_type_counts_unfiltered:
            honor_type_counts_unfiltered[honor.type] += 1
    response_data['honor_type_counts'] = honor_type_counts_unfiltered

    # (等级统计)
    honor_level_counts_unfiltered = {level_type: 0 for level_type in LEVEL_TYPE}
    for honor in user_honors_raw:
        honor_level = honor.honor_level
        if honor_level in honor_level_counts_unfiltered:
            honor_level_counts_unfiltered[honor_level] += 1
    response_data['honor_level_counts'] = honor_level_counts_unfiltered

    # --- 【新增】荣誉时间线 (ECharts 按月统计) ---
    monthly_counts = {}

    # 1. 遍历所有荣誉, 按 'YYYY-MM' 格式聚合
    for honor in user_honors_raw:
        honor_date = parse_date_safe(honor.date)
        if honor_date:
            month_key = honor_date.strftime('%Y-%m')
            if month_key not in monthly_counts:
                monthly_counts[month_key] = 0
            monthly_counts[month_key] += 1

    # 2. 转换为 ECharts 需要的 [date_str, count] 格式
    #    我们使用每月1号作为 ECharts 的 X 轴坐标
    monthly_timeseries = []
    if monthly_counts:
        # 找出最早和最晚的月份
        start_date = datetime.datetime.strptime(min(monthly_counts.keys()), '%Y-%m').date()
        end_date = datetime.datetime.strptime(max(monthly_counts.keys()), '%Y-%m').date()

        # 补全中间所有缺失的月份 (确保图表是连续的)
        current_date = start_date
        while current_date <= end_date:
            month_key = current_date.strftime('%Y-%m')
            count = monthly_counts.get(month_key, 0)

            # ECharts 需要 [YYYY-MM-DD, count] 格式
            monthly_timeseries.append([current_date.strftime('%Y-%m-%d'), count])

            # 移动到下一个月
            current_date = (current_date.replace(day=1) + relativedelta(months=1))

    # 3. 添加到响应
    response_data['monthly_timeseries_data'] = monthly_timeseries

    # (我们需要一个按日期排序的 *未经过滤* 的列表)
    all_honors_sorted_for_axis = sorted(
        user_honors_raw,
        # 按日期正序 (从远到近), 这样时间轴才是从左到右
        key=lambda x: parse_date_safe(x.date) or datetime.date.min,
        reverse=False  # 【注意】这里是 False (正序)
    )
    response_data['all_honors_sorted_for_axis'] = all_honors_sorted_for_axis

    # 5. 【重构】应用日期筛选逻辑
    # (这部分逻辑几乎不变, 只是数据源是 user_honors_raw)
    today = datetime.date.today()
    filtered_honors = []
    if selected_date_filter == 'last_year':
        cutoff_date = today - relativedelta(years=1)
        for honor in user_honors_raw:
            honor_date = parse_date_safe(honor.date)
            if honor_date and honor_date >= cutoff_date:
                filtered_honors.append(honor)
    # ... (elif ... last_3_years, last_5_years - 逻辑不变) ...
    elif selected_date_filter == 'last_3_years':
        cutoff_date = today - relativedelta(years=3)
        for honor in user_honors_raw:
            honor_date = parse_date_safe(honor.date)
            if honor_date and honor_date >= cutoff_date:
                filtered_honors.append(honor)
    elif selected_date_filter == 'last_5_years':
        cutoff_date = today - relativedelta(years=5)
        for honor in user_honors_raw:
            honor_date = parse_date_safe(honor.date)
            if honor_date and honor_date >= cutoff_date:
                filtered_honors.append(honor)
    elif selected_date_filter == 'custom':
        start_date_str = request_args.get('start_date')
        end_date_str = request_args.get('end_date')
        start_date_limit = parse_date_safe(start_date_str)
        end_date_limit = parse_date_safe(end_date_str)

        if start_date_limit and end_date_limit:
            for honor in user_honors_raw:
                honor_date = parse_date_safe(honor.date)
                if honor_date and start_date_limit <= honor_date <= end_date_limit:
                    filtered_honors.append(honor)
        else:
            filtered_honors = user_honors_raw
    else:  # 对应 filter_date == 'all'
        filtered_honors = user_honors_raw

    # 6. 【重构】应用类型和等级筛选
    if selected_types:
        filtered_honors = [h for h in filtered_honors if h.type in selected_types]
    if selected_levels:
        filtered_honors = [h for h in filtered_honors if h.honor_level in selected_levels]

    # 7. 排序并返回
    user_honors_sorted_filtered = sorted(
        filtered_honors,
        key=lambda x: parse_date_safe(x.date) or datetime.date.min,
        reverse=True
    )
    response_data['honors'] = user_honors_sorted_filtered

    return response_data


# --- 【重构】home 和 view_user_dashboard ---
# (这两个函数在上一版已修改为调用辅助函数, 保持不变)
@app.route('/home')
@login_required
def home():
    username = session.get('username')
    response_data = _get_dashboard_data_for_user(username, request.args)
    if response_data is None:
        flash("无法加载您的用户数据。", "error")
        return redirect(url_for('logout'))
    response_data['is_self_view'] = True
    response_data['can_edit'] = True
    employment_day = response_data.get('view_employment_day')
    employment_duration_str = "N/A"
    if employment_day:
        employment_day = response_data.get('view_employment_day')
        response_data['employment_duration'] = _get_employment_duration_str(employment_day)
    response_data['employment_duration'] = employment_duration_str
    return render_template('home.html', **response_data)


@app.route('/view/<string:username_to_view>')
@login_required
def view_user_dashboard(username_to_view):
    response_data = _get_dashboard_data_for_user(username_to_view, request.args)
    if response_data is None:
        flash(f"未找到用户 '{username_to_view}'。", "error")
        return redirect(url_for('teachers_overview'))
    is_self = (session.get('username') == username_to_view)
    is_admin = (session.get('role') == 'admin')
    response_data['is_self_view'] = is_self
    response_data['can_edit'] = (is_self or is_admin)
    employment_day = response_data.get('view_employment_day')
    employment_duration_str = "N/A"
    if employment_day:
        employment_day = response_data.get('view_employment_day')
        response_data['employment_duration'] = _get_employment_duration_str(employment_day)
    response_data['employment_duration'] = employment_duration_str
    return render_template('home.html', **response_data)


@app.route('/uploads/<username>/<path:filename>')
@login_required
def uploaded_file_user(username, filename):
    # (此函数无需修改, 它只处理文件系统)
    if session.get('role') != 'admin' and session.get('username') != username:
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


# --- 【重构】teachers_overview ---
@app.route('/teachers')
@login_required
def teachers_overview():
    """
    【重构】教师总览页面，从数据库读取
    """
    try:
        # 1. 从数据库获取所有用户
        all_users = db.session.scalars(db.select(User).order_by(User.truename)).all()

        # 2. 按专业分组
        users_by_major = {}
        for user in all_users:
            if user.role == 'admin' and not user.major:
                continue
            major = user.major or '未指定专业'
            if major not in users_by_major:
                users_by_major[major] = []

            users_by_major[major].append({
                'username': user.username,
                'truename': user.truename,
                'motto': user.motto
            })

        # 3. 排序 (逻辑不变)
        sorted_majors = sorted(users_by_major.keys())
        if '未指定专业' in sorted_majors:
            sorted_majors.remove('未指定专业')
            sorted_majors.append('未指定专业')

        return render_template('teachers.html',
                               majors=MAJOR_TYPE,
                               sorted_major_keys=sorted_majors,
                               users_by_major=users_by_major)

    except Exception as e:
        logger.error(f"加载教师总览页面时出错: {e}", exc_info=True)
        flash("加载教师列表时出错。", "error")
        return redirect(url_for('home'))


# --- 【重构】profile ---
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """
    【重构】个人资料页面, 读写数据库
    """
    username = session.get('username')

    # 1. 【修改】从数据库获取当前用户
    user = db.session.scalar(db.select(User).where(User.username == username))
    if not user:
        flash("无法加载您的用户数据，请重新登录。", "error")
        return redirect(url_for('logout'))

    # --- 【修改】处理 POST 请求 ---
    if request.method == 'POST':
        form_type = request.form.get('form_type')

        # --- 表单一：处理基本信息更新 ---
        # --- 表单一：处理基本信息更新 ---
        if form_type == 'update_profile':
            new_truename = request.form.get('truename', '').strip()
            new_major = request.form.get('major', '').strip()
            new_motto = request.form.get('motto', '').strip()
            new_employment_day = request.form.get('employment_day', '').strip()  # <<< 【新增】

            # 验证...
            if not new_truename:
                flash("真实姓名不能为空。", "error")
                return redirect(url_for('profile'))
            if not new_major or new_major not in MAJOR_TYPE:
                flash("请选择一个有效的专业。", "error")
                return redirect(url_for('profile'))

            # --- 【新增】验证日期 ---
            if not new_employment_day:
                flash("入职日期不能为空。", "error")
                return redirect(url_for('profile'))
            try:
                day_obj = datetime.datetime.strptime(new_employment_day, '%Y-%m-%d').date()
                if day_obj > datetime.date.today():
                    flash("入职日期不能在未来。", "error")
                    return redirect(url_for('profile'))
            except ValueError:
                flash("入职日期格式不正确。", "error")
                return redirect(url_for('profile'))
            # --- 【新增结束】 ---

            # 【修改】更新数据库
            user.truename = new_truename
            user.major = new_major
            user.motto = new_motto
            user.employment_day = new_employment_day  # <<< 【新增】
            db.session.commit()  # 提交更改

            # 更新 session
            session['truename'] = new_truename
            session['major'] = new_major
            session['employment_duration'] = _get_employment_duration_str(new_employment_day)  # <<< 【新增】

            log_activity(username, "更新资料", "更新了个人基本信息")
            flash("您的基本信息已成功更新！", "success")
            return redirect(url_for('profile'))
        # --- 表单二：处理密码修改 ---
        elif form_type == 'change_password':
            old_password = request.form.get('old_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')

            if not check_password_hash(user.password, old_password):
                flash("当前密码不正确。", "error")
                return redirect(url_for('profile'))
            if not new_password or len(new_password) < 6:
                flash("新密码不能为空且长度至少为6位。", "error")
                return redirect(url_for('profile'))
            if new_password != confirm_password:
                flash("两次输入的新密码不一致。", "error")
                return redirect(url_for('profile'))

            # 【修改】更新数据库
            user.password = generate_password_hash(new_password)
            db.session.commit()

            log_activity(username, "修改密码", "成功修改了密码")
            flash("密码已成功修改！", "success")
            return redirect(url_for('profile'))
        else:
            flash("无效的表单提交。", "warning")
            return redirect(url_for('profile'))

    # --- 【修改】处理 GET 请求 ---

    # 1. 计算统计数据
    stats = {"days": 0, "years": "0.0", "total": 0, "last_year": 0}
    try:
        # 计算入职时长
        employment_day_str = user.employment_day
        if employment_day_str:
            start_date = datetime.datetime.strptime(employment_day_str, '%Y-%m-%d').date()
            today = datetime.date.today()
            days_joined = (today - start_date).days
            stats["days"] = days_joined
            stats["years"] = f"{days_joined / 365.25:.1f}"

        # 【修改】通过关系计算荣誉
        stats["total"] = len(user.honors)

        # 【修改】使用数据库查询计算近一年
        one_year_ago = datetime.date.today() - relativedelta(years=1)
        # SQLAlchemy 2.0 风格的 count 查询
        honors_last_year_count = db.session.scalar(
            db.select(func.count(Honor.id)).where(
                Honor.user_id == user.id,
                Honor.date >= one_year_ago.strftime('%Y-%m-%d')
            )
        )
        stats["last_year"] = honors_last_year_count
    except Exception as e:
        logger.error(f"为用户 {username} 计算统计数据时出错: {e}")
        flash("计算统计数据时出错。", "warning")

    # 2. 【修改】读取活动日志 (通过关系)
    recent_activities = db.session.scalars(
        db.select(ActivityLog).where(
            ActivityLog.user_id == user.id
        ).order_by(
            ActivityLog.timestamp.desc()
        ).limit(10)
    ).all()

    # (为模板准备 timestamp_obj, 因为现在 'timestamp' 就是
    #  一个 datetime 对象, 不再需要 'timestamp_obj' 了)
    for activity in recent_activities:
        activity.timestamp_obj = activity.timestamp

        # 3. 将所有数据传递给模板
    return render_template(
        'profile.html',
        user=user,  # 传递的是 User 对象
        stats=stats,
        activities=recent_activities,
        majors=MAJOR_TYPE
    )


# --- 【重构】update_motto ---
@app.route('/update_motto', methods=['POST'])
@login_required
def update_motto():
    username = session.get('username')
    if not username:
        return jsonify(success=False, error="用户未登录"), 401
    data = request.get_json()
    if data is None:
        return jsonify(success=False, error="无效的请求数据格式"), 400

    new_motto = data.get('motto', '')
    max_motto_length = 100
    if len(new_motto) > max_motto_length:
        return jsonify(success=False, error=f"最多 {max_motto_length} 个字符"), 400

    # 【修改】从数据库更新
    user = db.session.scalar(db.select(User).where(User.username == username))
    if user:
        try:
            user.motto = new_motto
            db.session.commit()
            logger.info(f"用户 '{username}' 更新签名为: '{new_motto}'")
            return jsonify(success=True, message="签名更新成功！", new_motto=new_motto)
        except Exception as e:
            db.session.rollback()
            logger.error(f"保存 '{username}' 的新签名时出错: {e}", exc_info=True)
            return jsonify(success=False, error="保存时发生服务器内部错误"), 500
    else:
        logger.warning(f"尝试更新签名的用户 '{username}' 不存在")
        return jsonify(success=False, error="无法找到用户信息"), 404


# --- 【重构】logout ---
@app.route('/logout')
@login_required
def logout():
    logger.info(f"用户 '{session.get('username')}' 退出登录")
    session.clear()
    flash("您已成功退出登录。", "success")
    return redirect(url_for('index'))


# --- 【重构】login ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        if session.get('logged_in'):
            return redirect(url_for('home'))
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['name']
        password = request.form['password']

        # 1. 【修改】从数据库查询用户
        user = db.session.scalar(
            db.select(User).where(User.username == username)
        )

        if user and check_password_hash(user.password, password):
            session['logged_in'] = True
            session['username'] = user.username
            session['role'] = user.role
            session['class'] = ""
            session['truename'] = user.truename
            session['major'] = user.major
            session['employment_duration'] = _get_employment_duration_str(user.employment_day)  # 【修改】
            session.permanent = True

            logger.info(f"用户 '{username}' 登录成功")
            log_activity(username, "用户登录", f"从 {request.remote_addr} 登录成功")

            flash(f"欢迎回来, {session.get('truename', username)}！", "success")
            next_url = request.args.get('next')
            return redirect(next_url or url_for('home'))
        else:
            logger.warning(f"用户 '{username}' 登录失败 (密码错误或用户不存在)")
            flash('用户名或密码错误。', 'error')
            return redirect(url_for('index'))


# --- 【重构】register ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if session.get('logged_in'):
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        truename = request.form.get('truename', '').strip()
        major = request.form.get('major', '').strip()
        employment_day = request.form.get('employment_day').strip()

        # 1. 【修改】验证
        if not all([username, password, confirm_password, truename, employment_day]):
            flash("所有带 * 号的必填项都不能为空。", "error")
            return redirect(url_for('register'))

        # 2. 【修改】检查用户是否存在
        existing_user = db.session.scalar(
            db.select(User).where(User.username == username)
        )
        if existing_user:
            flash(f"登录账号 '{username}' 已被占用，请更换一个。", "error")
            return redirect(url_for('register'))

        if len(password) < 6:
            flash("密码长度不能少于6位。", "error")
            return redirect(url_for('register'))
        if password != confirm_password:
            flash("两次输入的密码不一致。", "error")
            return redirect(url_for('register'))

        # 3. 【修改】创建 User 对象
        new_user = User(
            username=username,
            password=generate_password_hash(password),
            truename=truename,
            major=major,
            employment_day=employment_day,
            role="user",
            motto=""
        )

        # 4. 【修改】存入数据库
        try:
            db.session.add(new_user)
            db.session.commit()
            logger.info(f"新用户 '{username}' ({truename}) 注册成功。")
            flash("恭喜您，注册成功！现在可以使用新账户登录了。", "success")
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"注册用户 {username} 时出错: {e}", exc_info=True)
            flash("注册时发生数据库错误，请稍后再试。", "error")
            return redirect(url_for('register'))

    return redirect(url_for('index'))


# --- 【重构】get_users_by_major API ---
@app.route('/api/users_by_major')
@login_required
def get_users_by_major():
    major = request.args.get('major')
    if not major:
        return jsonify([])

    # 【修改】从数据库查询
    users_in_major = db.session.scalars(
        db.select(User).where(User.major == major).order_by(User.truename)
    ).all()

    # 转换为 JSON
    users_list = [
        {"username": user.username, "truename": user.truename}
        for user in users_in_major
    ]
    return jsonify(users_list)


@app.route('/add_honor', methods=['GET', 'POST'])
@login_required
def add_honor():
    current_username = session.get('username')
    current_user_role = session.get('role')

    # --- 【修改】处理 POST 请求 ---
    if request.method == 'POST':
        # ... (用户和权限检查 - 保持不变) ...
        owner_username = None
        if current_user_role == 'admin':
            owner_username = request.form.get('teacher_username')
        elif current_user_role == 'major_admin':
            owner_username = request.form.get('teacher_username')
        else:
            owner_username = current_username

        if not owner_username:
            flash("必须选择一个教师！", "error")
            return redirect(url_for('add_honor'))
        owner_user = db.session.scalar(
            db.select(User).where(User.username == owner_username)
        )
        if not owner_user:
            flash(f"选择的目标教师 '{owner_username}' 不存在。", "error")
            return redirect(url_for('add_honor'))
        if current_user_role == 'major_admin':
            current_user = db.session.scalar(db.select(User).where(User.username == current_username))
            if not current_user or current_user.major != owner_user.major:
                flash("您只能为您自己专业下的教师添加荣誉。", "error")
                return redirect(url_for('add_honor'))

        # ... (表单数据获取和校验 - 保持不变) ...
        honor_name = request.form.get('honor_name')
        honor_type = request.form.get('honor_type')
        honor_date = request.form.get('honor_date')
        honor_stamp = request.form.get('honor_stamp')
        honor_stamp_other = request.form.get('honor_stamp_other') or ""
        honor_image = request.files.get('honor_image')
        honor_level = request.form.get('honor_level')

        if not all([honor_name, honor_type, honor_level, honor_date, honor_stamp]):
            flash("请填写所有必填项。", "error")
            return redirect(url_for('add_honor'))
        if not honor_image or honor_image.filename == '':
            flash("请上传荣誉证明文件。", "error")
            return redirect(url_for('add_honor'))
        if not allowed_file(honor_image.filename):
            flash("无效的文件格式，请上传图片文件或PDF文件。", "error")
            return redirect(url_for('add_honor'))

        # --- 【重大修改】文件处理 (PDF 拆分) ---

        owner_upload_folder = os.path.join(UPLOAD_FOLDER, owner_username)
        if not os.path.exists(owner_upload_folder):
            os.makedirs(owner_upload_folder)

        temp_path = None
        output_image_filename = None  # 封面图 (PDF 第1页 / 或图片本身)
        thumb_filename = None
        original_pdf_filename = None
        page_images_list = []  # 【新增】用于存储所有页面
        pil_image_for_thumb = None  # 【新增】用于暂存封面图以便生成缩略图

        timestamp = int(time.time())
        rand_int = random.randint(100, 999)
        base_filename = f"{owner_username}_{timestamp}_{rand_int}"

        try:
            # 1. 保存临时文件
            original_filename = secure_filename(honor_image.filename)
            _, ext = os.path.splitext(original_filename)
            temp_filename = f"temp_{base_filename}{ext}"
            temp_path = os.path.join(owner_upload_folder, temp_filename)
            honor_image.save(temp_path)

            # 2. 根据类型处理
            if ext.lower() == '.pdf':
                # --- A. 处理 PDF (拆分所有页面) ---
                logger.info(f"开始处理 PDF: {temp_path}")

                # 2.1 保存原始 PDF
                original_pdf_filename = f"{base_filename}_original.pdf"
                permanent_pdf_path = os.path.join(owner_upload_folder, original_pdf_filename)
                shutil.copy2(temp_path, permanent_pdf_path)

                doc = fitz.open(temp_path)
                if len(doc) == 0: raise ValueError("PDF文件为空")

                # 2.2 遍历所有页面
                for page_num in range(len(doc)):
                    page = doc.load_page(page_num)
                    pix = page.get_pixmap(dpi=200)
                    mode = "RGBA" if pix.alpha else "RGB"
                    pil_image = Image.frombytes(mode, (pix.width, pix.height), pix.samples)

                    # 2.3 生成该页的文件名
                    page_filename = f"{base_filename}_p{page_num + 1}.jpg"
                    page_save_path = os.path.join(owner_upload_folder, page_filename)

                    # 2.4 保存页面为 JPG
                    if pil_image.mode in ('RGBA', 'P'):
                        background = Image.new('RGB', pil_image.size, (255, 255, 255))
                        try:
                            mask = pil_image.convert('RGBA').split()[3]
                        except IndexError:
                            mask = None
                        background.paste(pil_image, mask=mask)
                        background.save(page_save_path, "JPEG", quality=85, optimize=True)
                        background.close()
                    else:
                        pil_image.convert('RGB').save(page_save_path, "JPEG", quality=85, optimize=True)

                    # 2.5 如果是第一页, 设为封面图, 并暂存
                    if page_num == 0:
                        output_image_filename = page_filename
                        pil_image_for_thumb = pil_image.copy()  # 暂存

                    page_images_list.append(page_filename)
                    pil_image.close()

                doc.close()
                logger.info(f"PDF 处理完毕, 共 {len(page_images_list)} 页")

            else:
                # --- B. 处理普通图片 ---
                logger.info(f"开始处理图片: {temp_path}")
                pil_image = Image.open(temp_path)
                pil_image = ImageOps.exif_transpose(pil_image)

                output_image_filename = f"{base_filename}.jpg"
                output_image_path = os.path.join(owner_upload_folder, output_image_filename)

                # 2.1 保存主图
                main_image_to_save = pil_image.copy()
                if main_image_to_save.mode in ('RGBA', 'P'):
                    background = Image.new('RGB', main_image_to_save.size, (255, 255, 255))
                    try:
                        mask = main_image_to_save.convert('RGBA').split()[3]
                    except IndexError:
                        mask = None
                    background.paste(main_image_to_save, mask=mask)
                    background.save(output_image_path, "JPEG", quality=85, optimize=True)
                    background.close()
                else:
                    main_image_to_save.convert('RGB').save(output_image_path, "JPEG", quality=85, optimize=True)
                main_image_to_save.close()

                # 2.2 暂存用于生成缩略图
                pil_image_for_thumb = pil_image.copy()

                # 2.3 将自己添加到页面列表
                page_images_list.append(output_image_filename)
                pil_image.close()

            if not pil_image_for_thumb:
                raise ValueError("无法生成用于缩略图的图像对象")

            # 3. 【统一】生成缩略图 (基于 pil_image_for_thumb)
            thumb_filename = f"{base_filename}_thumb.jpg"
            thumb_save_path = os.path.join(owner_upload_folder, thumb_filename)

            pil_image_for_thumb.thumbnail((400, 400), Image.Resampling.LANCZOS)
            if pil_image_for_thumb.mode in ('RGBA', 'P'):
                thumb_background = Image.new('RGB', pil_image_for_thumb.size, (255, 255, 255))
                try:
                    thumb_mask = pil_image_for_thumb.convert('RGBA').split()[3]
                except IndexError:
                    thumb_mask = None
                thumb_background.paste(pil_image_for_thumb, mask=thumb_mask)
                thumb_background.save(thumb_save_path, "JPEG", quality=85, optimize=True)
                thumb_background.close()
            else:
                pil_image_for_thumb.convert('RGB').save(thumb_save_path, "JPEG", quality=85, optimize=True)

            pil_image_for_thumb.close()
            logger.info(f"成功创建缩略图: {thumb_filename}")

        except Exception as e:
            logger.error(f"处理上传的文件失败: {e}", exc_info=True)
            flash(f"文件处理失败: {e}", "error")
            # 清理可能已创建的
            if temp_path and os.path.exists(temp_path): os.remove(temp_path)
            # (也可以添加逻辑删除已保存的 page_images)
            return redirect(url_for('add_honor'))
        finally:
            # 4. 清理临时文件
            if temp_path and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError as e:
                    logger.error(f"删除临时文件 '{temp_path}' 失败: {e}")

        # 5. 【修改】保存荣誉数据到数据库
        new_honor = Honor(
            id=f"honor_{timestamp}_{rand_int}",
            name=honor_name,
            type=honor_type,
            date=honor_date,
            stamp=honor_stamp,
            stamp_other=honor_stamp_other,
            image_filename=output_image_filename,  # 封面图
            honor_level=honor_level,
            thumb_filename=thumb_filename,  # 封面图的缩略图
            original_pdf_filename=original_pdf_filename,  # 原始PDF (如果有)
            page_images=page_images_list,  # 【新增】所有页面的列表
            owner=owner_user
        )

        try:
            db.session.add(new_honor)
            db.session.commit()

            log_activity(current_username, "添加荣誉", f"为 '{owner_username}' 添加了荣誉: {honor_name}")
            logger.info(f"用户 '{current_username}' 为 '{owner_username}' 添加新荣誉 '{honor_name}' 成功")
            flash(f"荣誉 '{honor_name}' 添加成功！", "success")

        except Exception as e:
            db.session.rollback()
            logger.error(f"保存荣誉到数据库失败: {e}", exc_info=True)
            flash("保存荣誉时发生数据库错误。", "error")
            # (这里也应该删除已保存的文件)
            delete_honor_files(new_honor)

        return redirect(url_for('add_honor'))

    # --- 处理 GET 请求 (保持不变) ---
    recent_honors = db.session.scalars(
        db.select(Honor).where(
            Honor.owner.has(username=current_username)
        ).order_by(Honor.date.desc()).limit(3)
    ).all()

    template_data = {
        "honor_types": HONOR_TYPE,
        "honor_levels": LEVEL_TYPE,
        "form_data": {},
        "recent_honors": recent_honors
    }

    all_users = db.session.scalars(db.select(User).order_by(User.truename)).all()
    current_user_obj = None

    if current_user_role == 'admin':
        all_majors = sorted(list(set(u.major for u in all_users if u.major)))
        users_by_major = {}
        for major in all_majors:
            users_in_major = [
                {"username": u.username, "truename": u.truename}
                for u in all_users if u.major == major
            ]
            users_by_major[major] = users_in_major

        template_data['all_majors'] = all_majors
        template_data['users_by_major_json'] = users_by_major

    elif current_user_role == 'major_admin':
        for u in all_users:
            if u.username == current_username:
                current_user_obj = u
                break

        user_major = current_user_obj.major if current_user_obj else ""
        major_admin_users = []
        if user_major:
            major_admin_users = [
                {"username": u.username, "truename": u.truename}
                for u in all_users if u.major == user_major
            ]
        template_data['major_admin_users'] = major_admin_users
        template_data['user_major'] = user_major

    return render_template('add_honor.html', **template_data)

# --- 【重构】admin_all_honors ---
@app.route('/admin/all_honors')
@login_required
@admin_required
def admin_all_honors():
    logger.info(f"管理员 '{session.get('username')}' 访问所有荣誉管理页面")
    try:
        # 1. 【修改】构建查询
        query = db.select(Honor).order_by(Honor.date.desc())

        # 2. 按日期筛选 (数据库层面)
        selected_date_filter = request.args.get('filter_date', 'all')
        today = datetime.date.today()
        cutoff_date_str = None
        if selected_date_filter == 'last_year':
            cutoff_date_str = (today - relativedelta(years=1)).strftime('%Y-%m-%d')
        elif selected_date_filter == 'last_3_years':
            cutoff_date_str = (today - relativedelta(years=3)).strftime('%Y-%m-%d')
        elif selected_date_filter == 'last_5_years':
            cutoff_date_str = (today - relativedelta(years=5)).strftime('%Y-%m-%d')

        if cutoff_date_str:
            query = query.where(Honor.date >= cutoff_date_str)

        # 3. 执行查询
        all_honors_sorted = db.session.scalars(query).all()

        # 4. 【修改】准备筛选器数据
        all_users = db.session.scalars(db.select(User)).all()
        all_majors = sorted(list(set(u.major for u in all_users if u.major)))
        all_teachers = {u.username: u.truename for u in all_users}

        response_data = {
            'honors': all_honors_sorted,  # 传递 Honor 对象列表
            'honor_types': HONOR_TYPE,
            'honor_levels': LEVEL_TYPE,
            'all_majors': all_majors,
            'all_teachers': all_teachers,
            'selected_date_filter': selected_date_filter,
            'username': session.get('username')
        }
        # 注意: 模板 home.html 必须修改为能处理 Honor 对象
        # (例如: honor.owner.username, honor.owner.truename)
        return render_template('admin/all_honors.html', **response_data)

    except Exception as e:
        logger.error(f"管理员 '{session.get('username')}' 访问所有荣誉页面时出错: {e}", exc_info=True)
        flash("加载所有荣誉列表时发生错误。", "error")
        return redirect(url_for('admin_dashboard'))


# --- 【重构】admin_all_honors_table ---
@app.route('/admin/all_honors_table')
@login_required
@admin_required
def admin_all_honors_table():
    logger.info(f"管理员 '{session.get('username')}' 访问所有荣誉的表格视图")
    try:
        # 1. 【修改】构建基础查询 (已包含排序和 Join)
        query = db.select(Honor).join(Honor.owner).order_by(Honor.date.desc())

        # 2. 获取筛选参数
        selected_date_filter = request.args.get('filter_date', 'all')
        search_query = request.args.get('q', '').strip()

        # 3. 按日期筛选 (数据库层面)
        today = datetime.date.today()
        cutoff_date_str = None
        if selected_date_filter == 'last_year':
            cutoff_date_str = (today - relativedelta(years=1)).strftime('%Y-%m-%d')
        elif selected_date_filter == 'last_3_years':
            cutoff_date_str = (today - relativedelta(years=3)).strftime('%Y-%m-%d')
        elif selected_date_filter == 'last_5_years':
            cutoff_date_str = (today - relativedelta(years=5)).strftime('%Y-%m-%d')

        if cutoff_date_str:
            query = query.where(Honor.date >= cutoff_date_str)

        # 4. 按关键词搜索 (数据库层面)
        if search_query:
            query = query.where(Honor.name.icontains(search_query))

        # 5. 执行查询
        final_filtered_honors = db.session.scalars(query).all()
        logger.info(f"为管理员加载了 {len(final_filtered_honors)} 条荣誉记录")

        # 6. 【修改】准备筛选器数据
        all_users = db.session.scalars(db.select(User)).all()
        all_majors = sorted(list(set(u.major for u in all_users if u.major)))
        all_teachers = {u.username: u.truename for u in all_users}

        # 7. 准备模板数据
        response_data = {
            'honors': final_filtered_honors,  # 传递 Honor 对象列表
            'honor_types': HONOR_TYPE,
            'honor_levels': LEVEL_TYPE,
            'all_majors': all_majors,
            'all_teachers': all_teachers,
            'selected_date_filter': selected_date_filter,
            'search_query': search_query,
            'username': session.get('username')
        }
        return render_template('admin/all_honors_table.html', **response_data)

    except Exception as e:
        logger.error(f"管理员 '{session.get('username')}' 访问所有荣誉表格时出错: {e}", exc_info=True)
        flash("加载所有荣誉表格时发生错误。", "error")
        return redirect(url_for('admin_dashboard'))


def delete_honor_files(honor: Honor):
    """
    【新增】辅助函数：安全地删除一个 Honor
    对象关联的所有物理文件。
    """
    if not honor:
        return

    owner_username = honor.owner.username
    current_upload_folder = os.path.join(UPLOAD_FOLDER, owner_username)
    if not os.path.isdir(current_upload_folder):
        return

    files_to_delete = []

    # 1. 添加封面图和缩略图
    if honor.image_filename:
        files_to_delete.append(honor.image_filename)
    if honor.thumb_filename:
        files_to_delete.append(honor.thumb_filename)

    # 2. 添加原始PDF (如果存在)
    if honor.original_pdf_filename:
        files_to_delete.append(honor.original_pdf_filename)

    # 3. 【关键】添加 page_images 列表中的所有图片
    if honor.page_images and isinstance(honor.page_images, list):
        for page_img in honor.page_images:
            if page_img:
                files_to_delete.append(page_img)

    # 4. 执行删除
    for f_name in set(files_to_delete):  # 使用 set() 避免重复删除
        path_to_delete = os.path.join(current_upload_folder, f_name)
        if os.path.exists(path_to_delete):
            try:
                os.remove(path_to_delete)
                logger.info(f"成功删除文件: {path_to_delete}")
            except OSError as e:
                logger.error(f"删除文件失败 '{path_to_delete}': {e}")


# --- 【重构】edit_honor ---
@app.route('/edit_honor/<string:honor_id>', methods=['POST'])
@login_required
def edit_honor(honor_id):
    honor_to_edit = db.session.get(Honor, honor_id)
    if not honor_to_edit:
        return jsonify(success=False, error="无法找到要编辑的荣誉记录。"), 404

    owner_username = honor_to_edit.owner.username

    if session.get('role') != 'admin' and session.get('username') != owner_username:
        return jsonify(success=False, error="您沒有權限編輯此記錄。"), 403

    new_name = request.form.get('honor_name')
    if not new_name:
        return jsonify(success=False, error="荣誉名称不能为空。"), 400

    try:
        # 1. 更新文本信息
        honor_to_edit.name = new_name
        honor_to_edit.type = request.form.get('honor_type')
        honor_to_edit.honor_level = request.form.get('honor_level')
        honor_to_edit.date = request.form.get('honor_date')
        honor_to_edit.stamp = request.form.get('honor_stamp')
        honor_to_edit.stamp_other = request.form.get('honor_stamp_other', "")

        # 2. 【修改】处理新文件 (如果上传了)
        new_image_file = request.files.get('honor_image')
        if new_image_file and new_image_file.filename:

            # 2.1 【重要】删除所有旧文件
            delete_honor_files(honor_to_edit)

            # 2.2 【复用】使用与 add_honor 相同的逻辑处理新文件
            current_upload_folder = os.path.join(UPLOAD_FOLDER, owner_username)
            temp_path = None
            pil_image_for_thumb = None

            timestamp = int(time.time())
            rand_int = random.randint(100, 999)
            base_filename = f"{owner_username}_{timestamp}_{rand_int}"

            try:
                original_filename = secure_filename(new_image_file.filename)
                _, ext = os.path.splitext(original_filename)
                temp_filename = f"temp_{base_filename}{ext}"
                temp_path = os.path.join(current_upload_folder, temp_filename)
                new_image_file.save(temp_path)

                new_page_images_list = []
                new_original_pdf_filename = None
                new_output_image_filename = None
                new_thumb_filename = f"{base_filename}_thumb.jpg"

                if ext.lower() == '.pdf':
                    new_original_pdf_filename = f"{base_filename}_original.pdf"
                    permanent_pdf_path = os.path.join(current_upload_folder, new_original_pdf_filename)
                    shutil.copy2(temp_path, permanent_pdf_path)

                    doc = fitz.open(temp_path)
                    if len(doc) == 0: raise ValueError("PDF文件为空")

                    for page_num in range(len(doc)):
                        page = doc.load_page(page_num)
                        pix = page.get_pixmap(dpi=200)
                        mode = "RGBA" if pix.alpha else "RGB"
                        pil_image = Image.frombytes(mode, (pix.width, pix.height), pix.samples)

                        page_filename = f"{base_filename}_p{page_num + 1}.jpg"
                        page_save_path = os.path.join(current_upload_folder, page_filename)

                        # (保存页面)
                        if pil_image.mode in ('RGBA', 'P'):
                            background = Image.new('RGB', pil_image.size, (255, 255, 255))
                            try:
                                mask = pil_image.convert('RGBA').split()[3]
                            except IndexError:
                                mask = None
                            background.paste(pil_image, mask=mask)
                            background.save(page_save_path, "JPEG", quality=85, optimize=True)
                            background.close()
                        else:
                            pil_image.convert('RGB').save(page_save_path, "JPEG", quality=85, optimize=True)

                        if page_num == 0:
                            new_output_image_filename = page_filename
                            pil_image_for_thumb = pil_image.copy()

                        new_page_images_list.append(page_filename)
                        pil_image.close()
                    doc.close()

                else:
                    pil_image = Image.open(temp_path)
                    pil_image = ImageOps.exif_transpose(pil_image)
                    new_output_image_filename = f"{base_filename}.jpg"
                    output_image_path = os.path.join(current_upload_folder, new_output_image_filename)

                    # (保存主图)
                    main_image_to_save = pil_image.copy()
                    if main_image_to_save.mode in ('RGBA', 'P'):
                        background = Image.new('RGB', main_image_to_save.size, (255, 255, 255))
                        try:
                            mask = main_image_to_save.convert('RGBA').split()[3]
                        except IndexError:
                            mask = None
                        background.paste(main_image_to_save, mask=mask)
                        background.save(output_image_path, "JPEG", quality=85, optimize=True)
                        background.close()
                    else:
                        main_image_to_save.convert('RGB').save(output_image_path, "JPEG", quality=85, optimize=True)
                    main_image_to_save.close()

                    pil_image_for_thumb = pil_image.copy()
                    new_page_images_list.append(new_output_image_filename)
                    pil_image.close()

                if not pil_image_for_thumb:
                    raise ValueError("无法生成用于缩略图的图像对象")

                # (生成缩略图)
                thumb_save_path = os.path.join(current_upload_folder, new_thumb_filename)
                pil_image_for_thumb.thumbnail((400, 400), Image.Resampling.LANCZOS)
                if pil_image_for_thumb.mode in ('RGBA', 'P'):
                    thumb_background = Image.new('RGB', pil_image_for_thumb.size, (255, 255, 255))
                    try:
                        thumb_mask = pil_image_for_thumb.convert('RGBA').split()[3]
                    except IndexError:
                        thumb_mask = None
                    thumb_background.paste(pil_image_for_thumb, mask=thumb_mask)
                    thumb_background.save(thumb_save_path, "JPEG", quality=85, optimize=True)
                    thumb_background.close()
                else:
                    pil_image_for_thumb.convert('RGB').save(thumb_save_path, "JPEG", quality=85, optimize=True)
                pil_image_for_thumb.close()

                # 2.3 【修改】更新数据库对象
                honor_to_edit.image_filename = new_output_image_filename
                honor_to_edit.thumb_filename = new_thumb_filename
                honor_to_edit.original_pdf_filename = new_original_pdf_filename
                honor_to_edit.page_images = new_page_images_list

            except Exception as e:
                logger.error(f"编辑时处理新上传文件失败: {e}", exc_info=True)
                return jsonify(success=False, error=f"文件处理失败: {e}"), 500
            finally:
                if temp_path and os.path.exists(temp_path):
                    os.remove(temp_path)

        # 3. 提交所有更改
        db.session.commit()
        log_activity(session.get('username'), "编辑荣誉", f"更新了荣誉: {new_name} (ID: {honor_id})")
        return jsonify(success=True, message=f"荣誉 '{new_name}' 更新成功！")

    except Exception as e:
        db.session.rollback()
        logger.error(f"编辑荣誉 {honor_id} 时出错: {e}", exc_info=True)
        return jsonify(success=False, error="保存到数据库时出错"), 500


# --- 【重构】delete_honor ---
@app.route('/delete_honor/<string:honor_id>', methods=['POST'])
@login_required
def delete_honor(honor_id):
    honor_to_delete = db.session.get(Honor, honor_id)

    if not honor_to_delete:
        flash("无法找到要删除的荣誉记录。", "error")
        return redirect(request.referrer or url_for('home'))

    owner_username = honor_to_delete.owner.username

    is_admin = session.get('role') == 'admin'
    is_owner = session.get('username') == owner_username
    if not is_owner and not is_admin:
        flash("您没有权限删除此条荣誉记录。", "error")
        return redirect(request.referrer or url_for('home'))

    try:
        deleted_honor_name = honor_to_delete.name

        # 1. 【修改】删除所有物理文件
        delete_honor_files(honor_to_delete)

        # 2. 从数据库移除记录
        db.session.delete(honor_to_delete)
        db.session.commit()

        log_activity(session.get('username'), "删除荣誉", f"删除了 '{owner_username}' 的荣誉: {deleted_honor_name}")
        flash(f"已成功删除教师 '{owner_username}' 的荣誉: '{deleted_honor_name}'。", "success")

    except Exception as e:
        db.session.rollback()
        logger.error(f"删除荣誉 {honor_id} 时出错: {e}", exc_info=True)
        flash("删除荣誉时发生数据库错误。", "error")

    return redirect(request.referrer or url_for('home'))
# --- 错误处理 (不变) ---
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error_code=404, error_message="页面未找到"), 404


@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"服务器内部错误: {e}", exc_info=True)
    return render_template('error.html', error_code=500, error_message="服务器内部错误"), 500


# --- 【重构】honor_table ---
@app.route('/honor_table')
@login_required
def honor_table():
    current_username = session.get('username')
    logger.info(f"用户 '{current_username}' 正在访问自己的荣誉表格")

    try:
        # 1. 【修改】获取用户和查询
        user = db.session.scalar(db.select(User).where(User.username == current_username))
        if not user:
            flash("用户未找到。", "error")
            return redirect(url_for('login'))

        query = db.select(Honor).where(Honor.user_id == user.id).order_by(Honor.date.desc())

        # 2. 获取筛选参数
        selected_date_filter = request.args.get('filter_date', 'all')
        search_query = request.args.get('q', '').strip()

        # 3. 按日期筛选 (数据库层面)
        today = datetime.date.today()
        cutoff_date_str = None
        if selected_date_filter == 'last_year':
            cutoff_date_str = (today - relativedelta(years=1)).strftime('%Y-%m-%d')
        elif selected_date_filter == 'last_3_years':
            cutoff_date_str = (today - relativedelta(years=3)).strftime('%Y-%m-%d')
        elif selected_date_filter == 'last_5_years':
            cutoff_date_str = (today - relativedelta(years=5)).strftime('%Y-%m-%d')

        if cutoff_date_str:
            query = query.where(Honor.date >= cutoff_date_str)

        # 4. 按关键词搜索 (数据库层面)
        if search_query:
            query = query.where(Honor.name.icontains(search_query))

        # 5. 执行查询
        final_filtered_honors = db.session.scalars(query).all()

        # 6. 准备响应数据
        response_data = {
            'honors': final_filtered_honors,
            'user_truename': user.truename,
            'selected_date_filter': selected_date_filter,
            'search_query': search_query,
            'honor_types': HONOR_TYPE,
            'honor_levels': LEVEL_TYPE
        }
        return render_template('honor_table.html', **response_data)

    except Exception as e:
        logger.error(f"为用户 '{current_username}' 生成荣誉表格时发生错误: {e}", exc_info=True)
        flash("加载您的荣誉列表时发生错误。", "error")
        return redirect(url_for('home'))


# --- (sanitize_filename - 不变) ---
def sanitize_filename(filename):
    name = filename.strip('. ')
    name = re.sub(r'[\\/*?:"<>|]', '_', name)
    name = re.sub(r'_+', '_', name)
    return name[:200]


# --- 【重构】download_honor_pdf ---
@app.route('/download_honor_pdf/<string:honor_id>')
@login_required
def download_honor_pdf(honor_id):
    current_username = session.get('username')
    logger.info(f"用户 '{current_username}' 请求下载荣誉 ID '{honor_id}' 的 PDF 文件")

    try:
        # 1. 【修改】从数据库查找
        honor_to_download = db.session.get(Honor, honor_id)
        if not honor_to_download:
            abort(404, description="找不到指定的荣誉记录。")

        owner_username = honor_to_download.owner.username

        # 2. 权限检查 (不变)
        if session.get('role') != 'admin' and current_username != owner_username:
            abort(403, description="您无权访问此荣誉的证明文件。")

        # 3. 检查并发送原始PDF文件 (逻辑不变)
        user_upload_folder = os.path.abspath(os.path.join(UPLOAD_FOLDER, owner_username))
        original_pdf_filename = honor_to_download.original_pdf_filename
        if original_pdf_filename:
            original_pdf_path = os.path.join(user_upload_folder, original_pdf_filename)
            if os.path.exists(original_pdf_path):
                # ... (send_from_directory 逻辑不变) ...
                honor_name = honor_to_download.name
                honor_date = honor_to_download.date
                download_filename = sanitize_filename(f"{honor_name}_{honor_date}.pdf")
                return send_from_directory(
                    directory=user_upload_folder,
                    path=original_pdf_filename,
                    as_attachment=True,
                    download_name=download_filename
                )

        # 4. 【修改】回退路径 (从 honor 对象获取信息)
        image_filename = honor_to_download.image_filename
        if not image_filename:
            abort(404, description="该荣誉记录没有关联的证明文件。")

        # ... (后续的 PDF 转换逻辑保持不变) ...
        original_image_path = os.path.join(user_upload_folder, image_filename)
        if not os.path.exists(original_image_path):
            abort(404, description="找不到对应的图片文件。")

        img = None
        try:
            img = Image.open(original_image_path)
            if img.mode in ('RGBA', 'P'):
                background = Image.new('RGB', img.size, (255, 255, 255))
                try:
                    mask = img.convert('RGBA').split()[3]
                except IndexError:
                    mask = None
                background.paste(img, mask=mask)
                img_rgb = background
            elif img.mode != 'RGB':
                img_rgb = img.convert('RGB')
            else:
                img_rgb = img

            pdf_buffer = io.BytesIO()
            img_rgb.save(pdf_buffer, format='PDF', resolution=100.0)
            pdf_buffer.seek(0)
        except Exception as conv_e:
            logger.error(f"将图片 '{image_filename}' 转换为 PDF 时出错: {conv_e}", exc_info=True)
            abort(500, description="图片格式转换失败。")
        finally:
            if 'img_rgb' in locals() and img_rgb is not img:
                img_rgb.close()
            if img:
                img.close()

        honor_name = honor_to_download.name
        honor_date = honor_to_download.date
        download_filename = sanitize_filename(f"{honor_name}_{honor_date}.pdf")

        return send_file(
            pdf_buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=download_filename
        )
    except Exception as e:
        logger.error(f"下载 PDF (ID '{honor_id}') 时发生错误: {e}", exc_info=True)
        abort(500, description="处理PDF下载时发生服务器内部错误。")


# --- 【重构】download_honor_image_jpg ---
@app.route('/download_honor_image/<string:honor_id>/jpg')
@login_required
def download_honor_image_jpg(honor_id):
    current_username = session.get('username')
    try:
        # 1. 【修改】从数据库查找
        honor_to_download = db.session.get(Honor, honor_id)
        if not honor_to_download:
            abort(404, description="找不到指定的荣誉记录。")

        owner_username = honor_to_download.owner.username

        # 2. 权限检查 (不变)
        if session.get('role') != 'admin' and current_username != owner_username:
            abort(403, description="您无权访问此荣誉的证明文件。")

        # 3. 【修改】从 honor 对象获取信息
        image_filename = honor_to_download.image_filename
        if not image_filename:
            abort(404, description="该荣誉记录没有关联的证明文件。")

        # ... (后续的 JPG 转换逻辑保持不变) ...
        user_upload_folder = os.path.abspath(os.path.join(UPLOAD_FOLDER, owner_username))
        original_image_path = os.path.join(user_upload_folder, image_filename)
        if not os.path.exists(original_image_path):
            abort(404, description="找不到对应的图片文件。")

        img = Image.open(original_image_path)
        output_buffer = io.BytesIO()
        if img.mode in ('RGBA', 'P'):
            background = Image.new('RGB', img.size, (255, 255, 255))
            try:
                mask = img.convert('RGBA').split()[3]
            except IndexError:
                mask = None
            background.paste(img, mask=mask)
            img.close()
            img = background
        elif img.mode != 'RGB':
            img = img.convert('RGB')

        img.save(output_buffer, format='JPEG', quality=85, optimize=True)
        img.close()
        output_buffer.seek(0)

        honor_name = honor_to_download.name
        honor_date = honor_to_download.date
        download_filename = sanitize_filename(f"{honor_name}_{honor_date}.jpg")

        return send_file(output_buffer, mimetype='image/jpeg', as_attachment=True, download_name=download_filename)

    except Exception as e:
        logger.error(f"下载 JPG (ID '{honor_id}') 时发生错误: {e}", exc_info=True)
        abort(500, description="处理图片下载时发生服务器内部错误。")


# --- 【重构】download_individual_pdfs_zip ---
@app.route('/download_individual_pdfs_zip', methods=['POST'])
@login_required
def download_individual_pdfs_zip():
    current_username = session.get('username')
    data = request.get_json()
    if not data or not isinstance(data.get('honor_ids'), list):
        return jsonify(error="请求体必须包含 'honor_ids' 列表"), 400

    honor_ids = data['honor_ids']
    if not honor_ids:
        return jsonify(error="honor_ids 列表不能为空"), 400

    try:
        # 1. 【修改】从数据库查询请求的荣誉
        honors_to_zip = db.session.scalars(
            db.select(Honor).where(
                Honor.id.in_(honor_ids),
                Honor.owner.has(username=current_username)  # 确保只拿自己的
            )
        ).all()

        if len(honors_to_zip) != len(honor_ids):
            logger.warning(f"用户 {current_username} 请求的 PDF ZIP 包含无效或不属于自己的荣誉")
            # (我们只打包合法的，不报错)

        user_upload_folder = os.path.abspath(os.path.join(UPLOAD_FOLDER, current_username))
        zip_buffer = io.BytesIO()
        processed_count, skipped_count = 0, 0
        processed_filenames = set()

        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
            sorted_honors = sorted(
                honors_to_zip,
                key=lambda x: parse_date_safe(x.date) or datetime.date.min,
                reverse=True
            )

            # (后续的文件处理逻辑保持不变)
            for honor in sorted_honors:
                # ... (您的 ZIP 打包、PDF 转换逻辑) ...
                image_filename = honor.image_filename
                if not image_filename:
                    skipped_count += 1
                    continue
                original_image_path = os.path.join(user_upload_folder, image_filename)
                if not os.path.exists(original_image_path):
                    skipped_count += 1
                    continue

                img = None
                try:
                    img = Image.open(original_image_path)
                    if img.mode != 'RGB':
                        img_rgb = img.convert('RGB')
                        img.close()
                    else:
                        img_rgb = img

                    pdf_single_buffer = io.BytesIO()
                    img_rgb.save(pdf_single_buffer, format='PDF', resolution=100.0)
                    img_rgb.close()

                    base_name = sanitize_filename(f"{honor.name}_{honor.date}")
                    zip_entry_name = f"{base_name}.pdf"
                    counter = 1
                    while zip_entry_name in processed_filenames:
                        zip_entry_name = f"{base_name}_{counter}.pdf"
                        counter += 1
                    processed_filenames.add(zip_entry_name)

                    zipf.writestr(zip_entry_name, pdf_single_buffer.getvalue())
                    pdf_single_buffer.close()
                    processed_count += 1
                except Exception as img_proc_e:
                    logger.error(f"处理荣誉 ID '{honor.id}' 为独立PDF时出错: {img_proc_e}", exc_info=False)
                    if img: img.close()
                    skipped_count += 1

        if processed_count == 0:
            return jsonify(error="未能成功处理任何请求的图片文件。"), 400

        zip_buffer.seek(0)
        zip_download_filename = f"{current_username}_honors_pdf_{datetime.date.today().strftime('%Y%m%d')}.zip"
        return send_file(zip_buffer, mimetype='application/zip', as_attachment=True,
                         download_name=zip_download_filename)

    except Exception as e:
        logger.error(f"创建荣誉的PDF-ZIP文件时发生错误: {e}", exc_info=True)
        return jsonify(error="创建 ZIP 文件时发生服务器内部错误。"), 500


# --- 【重构】download_honors_zip ---
@app.route('/download_honors_zip', methods=['POST'])
@login_required
def download_honors_zip():
    current_username = session.get('username')
    data = request.get_json()
    if not data or not isinstance(data.get('honor_ids'), list):
        return jsonify(error="请求体必须包含 'honor_ids' 列表"), 400

    honor_ids = data['honor_ids']
    if not honor_ids:
        return jsonify(error="honor_ids 列表不能为空"), 400

    try:
        # 1. 【修改】从数据库查询
        honors_to_zip = db.session.scalars(
            db.select(Honor).where(
                Honor.id.in_(honor_ids),
                Honor.owner.has(username=current_username)
            )
        ).all()

        user_upload_folder = os.path.abspath(os.path.join(UPLOAD_FOLDER, current_username))
        zip_buffer = io.BytesIO()
        processed_count, skipped_count = 0, 0
        processed_filenames = set()

        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # (后续的文件处理逻辑保持不变)
            for honor in honors_to_zip:
                # ... (您的 ZIP 打包、JPG 转换逻辑) ...
                image_filename = honor.image_filename
                if not image_filename:
                    skipped_count += 1;
                    continue
                original_image_path = os.path.join(user_upload_folder, image_filename)
                if not os.path.exists(original_image_path):
                    skipped_count += 1;
                    continue

                img = None
                try:
                    img = Image.open(original_image_path)
                    jpg_buffer = io.BytesIO()
                    if img.mode in ('RGBA', 'P'):
                        background = Image.new('RGB', img.size, (255, 255, 255))
                        try:
                            mask = img.convert('RGBA').split()[3]
                        except IndexError:
                            mask = None
                        background.paste(img, mask=mask)
                        img.close();
                        img = background
                    elif img.mode != 'RGB':
                        converted_img = img.convert('RGB');
                        img.close();
                        img = converted_img

                    img.save(jpg_buffer, format='JPEG', quality=85, optimize=True)
                    jpg_buffer.seek(0)

                    base_name = sanitize_filename(f"{honor.name}_{honor.date}")
                    zip_entry_name = f"{base_name}.jpg"
                    counter = 1
                    while zip_entry_name in processed_filenames:
                        zip_entry_name = f"{base_name}_{counter}.jpg";
                        counter += 1
                    processed_filenames.add(zip_entry_name)

                    zipf.writestr(zip_entry_name, jpg_buffer.getvalue())
                    processed_count += 1
                except Exception as img_proc_e:
                    logger.error(f"处理荣誉 ID '{honor.id}' 的图片时出错: {img_proc_e}", exc_info=False)
                    skipped_count += 1
                finally:
                    if img: img.close()

        zip_buffer.seek(0)
        zip_download_filename = f"{current_username}_honors_{datetime.date.today().strftime('%Y%m%d')}.zip"

        if processed_count == 0:
            return jsonify(error="未能成功处理任何请求的图片文件。"), 400

        return send_file(zip_buffer, mimetype='application/zip', as_attachment=True,
                         download_name=zip_download_filename)

    except Exception as e:
        logger.error(f"创建荣誉 ZIP 文件时发生错误: {e}", exc_info=True)
        return jsonify(error="创建 ZIP 文件时发生服务器内部错误。"), 500


# --- 管理员路由 ---

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    return redirect(url_for('admin_user_management'))


# --- 【重构】admin_user_management ---
@app.route('/admin/users')
@login_required
@admin_required
def admin_user_management():
    logger.info(f"管理员 '{session.get('username')}' 访问用户管理页面")

    # 【修改】从数据库查询
    users_list_sorted = db.session.scalars(
        db.select(User).order_by(User.username)
    ).all()

    return render_template('admin/user_management.html', users=users_list_sorted)


# --- 【重构】admin_add_user ---
@app.route('/admin/user/add', methods=['POST'])
@login_required
@admin_required
def admin_add_user():
    username = request.form.get('username', '').strip()
    password = request.form.get('password')
    # ... (获取其他表单字段) ...
    truename = request.form.get('truename', '').strip()
    major = request.form.get('major', '').strip()
    employment_day = request.form.get('employment_day', '').strip()
    role = request.form.get('role', 'user').strip()

    if not all([username, password, truename, employment_day, role]):
        flash("所有字段均为必填项。", "error")
        return redirect(url_for('admin_user_management'))
    # ... (其他验证) ...

    # 【修改】检查用户是否存在
    existing_user = db.session.scalar(db.select(User).where(User.username == username))
    if existing_user:
        flash(f"用户名 '{username}' 已存在。", "error")
        return redirect(url_for('admin_user_management'))

    # 【修改】创建 User 对象并保存
    try:
        new_user = User(
            username=username,
            password=generate_password_hash(password),
            truename=truename,
            major=major,
            employment_day=employment_day,
            role=role,
            motto=""
        )
        db.session.add(new_user)
        db.session.commit()
        logger.info(f"管理员 '{session.get('username')}' 添加了新用户 '{username}' (角色: {role})")
        flash(f"用户 '{username}' 添加成功！", "success")
    except Exception as e:
        db.session.rollback()
        logger.error(f"管理员添加用户 {username} 时出错: {e}", exc_info=True)
        flash("添加用户时发生数据库错误。", "error")

    return redirect(url_for('admin_user_management'))


# --- 【重构】admin_reset_password ---
@app.route('/admin/user/reset_password/<username>', methods=['POST'])
@login_required
@admin_required
def admin_reset_password(username):
    new_password = request.form.get('new_password')
    if not new_password or len(new_password) < 6:
        flash("新密码不能为空且长度至少为6位。", "error")
        return redirect(url_for('admin_user_management'))

    # 【修改】查找并更新用户
    user = db.session.scalar(db.select(User).where(User.username == username))
    if not user:
        flash("用户不存在。", "error")
        return redirect(url_for('admin_user_management'))

    try:
        user.password = generate_password_hash(new_password)
        db.session.commit()
        logger.info(f"管理员 '{session.get('username')}' 重置了用户 '{username}' 的密码。")
        flash(f"用户 '{username}' 的密码已成功重置！", "success")
    except Exception as e:
        db.session.rollback()
        flash("重置密码时发生数据库错误。", "error")

    return redirect(url_for('admin_user_management'))


# --- 【重构】admin_change_role ---
@app.route('/admin/user/change_role/<username>', methods=['POST'])
@login_required
@admin_required
def admin_change_role(username):
    if username == session.get('username'):
        flash("您不能在此处修改自己的角色。", "warning")
        return redirect(url_for('admin_user_management'))

    new_role = request.form.get('role')
    if new_role not in ['user', 'admin', 'major_admin']:  # 【修改】允许 'major_admin'
        flash("无效的角色。", "error")
        return redirect(url_for('admin_user_management'))

    # 【修改】查找并更新用户
    user = db.session.scalar(db.select(User).where(User.username == username))
    if not user:
        flash("用户不存在。", "error")
        return redirect(url_for('admin_user_management'))

    try:
        user.role = new_role
        db.session.commit()
        logger.info(f"管理员 '{session.get('username')}' 将用户 '{username}' 角色修改为 '{new_role}'")
        flash(f"用户 '{username}' 的角色已更新为 '{new_role}'。", "success")
    except Exception as e:
        db.session.rollback()
        flash("修改角色时发生数据库错误。", "error")

    return redirect(url_for('admin_user_management'))


# --- 【重构】admin_delete_user ---
@app.route('/admin/user/delete/<username>', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(username):
    if username == session.get('username'):
        flash("您不能删除自己的账户。", "warning")
        return redirect(url_for('admin_user_management'))

    # 1. 【修改】从数据库删除用户
    user_to_delete = db.session.scalar(db.select(User).where(User.username == username))
    if not user_to_delete:
        flash("要删除的用户不存在。", "error")
        return redirect(url_for('admin_user_management'))

    deleted_user_truename = user_to_delete.truename

    try:
        # 2. 删除用户的上传文件夹 (逻辑不变)
        user_upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], username)
        if os.path.exists(user_upload_dir):
            shutil.rmtree(user_upload_dir)
            logger.info(f"已成功删除用户 '{username}' 的上传目录: {user_upload_dir}")

        # 3. 【修改】从数据库删除
        # (由于设置了 cascade, 该用户的所有 honors 和 logs 会自动被删除)
        db.session.delete(user_to_delete)
        db.session.commit()

        logger.warning(
            f"管理员 '{session.get('username')}' 删除了用户 '{username}' ({deleted_user_truename}) 及其所有数据。")
        flash(f"用户 '{deleted_user_truename}' ({username}) 及其所有数据已彻底删除。", "success")

    except Exception as e:
        db.session.rollback()
        logger.error(f"删除用户 {username} 时出错: {e}", exc_info=True)
        flash(f"删除用户时发生错误: {e}", "error")

    return redirect(url_for('admin_user_management'))


# --- 【重构】admin_reset_password_default ---
@app.route('/admin/user/reset_password_default/<username>', methods=['POST'])
@login_required
@admin_required
def admin_reset_password_default(username):
    if username == session.get('username'):
        flash("您不能将自己的密码重置为默认值。", "warning")
        return redirect(url_for('admin_user_management'))

    # 【修改】查找并更新用户
    user = db.session.scalar(db.select(User).where(User.username == username))
    if not user:
        flash("用户不存在。", "error")
        return redirect(url_for('admin_user_management'))

    try:
        default_password = '123456'
        user.password = generate_password_hash(default_password)
        db.session.commit()

        truename = user.truename
        logger.info(f"管理员 '{session.get('username')}' 将用户 '{truename}' ({username}) 密码重置为默认。")
        flash(f"用户 '{truename}' ({username}) 的密码已成功重置为 '123456'！", "success")
    except Exception as e:
        db.session.rollback()
        flash("重置密码时发生数据库错误。", "error")

    return redirect(url_for('admin_user_management'))


# --- 【重构】admin_download_honors_zip ---
@app.route('/admin/download_honors_zip', methods=['POST'])
@login_required
@admin_required
def admin_download_honors_zip():
    data = request.get_json()
    if not data or not isinstance(data.get('honor_ids'), list):
        return jsonify(error="请求体必须包含 'honor_ids' 列表"), 400

    honor_ids = data['honor_ids']
    if not honor_ids: return jsonify(error="honor_ids 列表不能为空"), 400

    # 【修改】从数据库查询
    honors_to_zip = db.session.scalars(
        db.select(Honor).where(Honor.id.in_(honor_ids))
    ).all()

    zip_buffer = io.BytesIO()
    processed_filenames = set()

    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for honor in honors_to_zip:
            owner_username = honor.owner.username  # 获取所有者
            truename = honor.owner.truename
            image_filename = honor.image_filename
            if not image_filename: continue

            original_image_path = os.path.join(UPLOAD_FOLDER, owner_username, image_filename)
            if not os.path.exists(original_image_path): continue

            # (打包逻辑不变)
            base_name = sanitize_filename(f"{truename}_{honor.name}_{honor.date}")
            zip_entry_name = f"{base_name}.jpg"
            counter = 1
            while zip_entry_name in processed_filenames:
                zip_entry_name = f"{base_name}_{counter}.jpg";
                counter += 1
            processed_filenames.add(zip_entry_name)

            zipf.write(original_image_path, arcname=zip_entry_name)

    zip_buffer.seek(0)
    zip_download_filename = f"admin_honors_export_{datetime.date.today().strftime('%Y%m%d')}.zip"
    return send_file(zip_buffer, mimetype='application/zip', as_attachment=True, download_name=zip_download_filename)


# --- 【重构】admin_download_individual_pdfs_zip ---
@app.route('/admin/download_individual_pdfs_zip', methods=['POST'])
@login_required
@admin_required
def admin_download_individual_pdfs_zip():
    data = request.get_json()
    if not data or not isinstance(data.get('honor_ids'), list):
        return jsonify(error="请求体必须包含 'honor_ids' 列表"), 400

    honor_ids = data['honor_ids']
    if not honor_ids: return jsonify(error="honor_ids 列表不能为空"), 400

    # 【修改】从数据库查询
    honors_to_zip = db.session.scalars(
        db.select(Honor).where(Honor.id.in_(honor_ids))
    ).all()

    zip_buffer = io.BytesIO()
    processed_filenames = set()

    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for honor in honors_to_zip:
            owner_username = honor.owner.username
            truename = honor.owner.truename
            image_filename = honor.image_filename
            if not image_filename: continue

            original_image_path = os.path.join(UPLOAD_FOLDER, owner_username, image_filename)
            if not os.path.exists(original_image_path): continue

            # (PDF 转换和打包逻辑不变)
            img = None
            try:
                img = Image.open(original_image_path)
                if img.mode != 'RGB':
                    img_rgb = img.convert('RGB')
                else:
                    img_rgb = img.copy()
                img.close()

                pdf_single_buffer = io.BytesIO()
                img_rgb.save(pdf_single_buffer, format='PDF', resolution=100.0)
                img_rgb.close()

                base_name = sanitize_filename(f"{truename}_{honor.name}_{honor.date}")
                zip_entry_name = f"{base_name}.pdf"
                counter = 1
                while zip_entry_name in processed_filenames:
                    zip_entry_name = f"{base_name}_{counter}.pdf";
                    counter += 1
                processed_filenames.add(zip_entry_name)

                zipf.writestr(zip_entry_name, pdf_single_buffer.getvalue())
                pdf_single_buffer.close()
            except Exception as e:
                logger.error(f"处理荣誉ID '{honor.id}' 的图片为PDF时出错: {e}")
                if img: img.close()

    zip_buffer.seek(0)
    zip_download_filename = f"admin_honors_pdf_export_{datetime.date.today().strftime('%Y%m%d')}.zip"
    return send_file(zip_buffer, mimetype='application/zip', as_attachment=True, download_name=zip_download_filename)


# --- 【重构】API: check_honor_exists ---
@app.route('/api/check_honor_exists')
@login_required
def check_honor_exists():
    query_name = request.args.get('name', '').strip().lower()
    owner_username = request.args.get('username', '').strip()

    if not query_name or not owner_username or len(query_name) < 3:
        return jsonify(found=False, matches=[])

    try:
        # 【修改】在数据库中查询
        matches = db.session.scalars(
            db.select(Honor).where(
                Honor.owner.has(username=owner_username),
                Honor.name.icontains(query_name)  # icontains = 不区分大小写的 "like %query_name%"
            )
        ).all()

        if matches:
            return jsonify(found=True, matches=[
                {"name": honor.name, "date": honor.date}
                for honor in matches
            ])
        else:
            return jsonify(found=False, matches=[])
    except Exception as e:
        logger.error(f"检查荣誉是否存在时出错 (用户: {owner_username}, 名称: {query_name}): {e}")
        return jsonify(found=False, matches=[])


# --- 【重构】API: get_user_recent_honors ---
# (这个函数在上一版已修改为查询数据库, 保持不变)
RECENT_HONORS_PARTIAL_TEMPLATE = """
{% if honors %}
    {% for honor in honors %}
    <div class="flex items-center gap-3">
        <div class="avatar">
            <div class="w-12 h-12 rounded bg-base-200">
                <img src="{{ url_for('uploaded_file_user', username=target_username, filename=honor.thumb_filename) }}"
                     alt="{{ honor.name }} 缩略图"
                     class="object-cover"
                     onerror="this.style.display='none'; this.parentElement.innerHTML='<span class=\"text-xs text-base-content/50 p-1\">无图</span>';" />
            </div>
        </div>
        <div class="flex-1 min-w-0">
            <p class="text-sm font-medium truncate" title="{{ honor.name }}">{{ honor.name }}</p>
            <p class="text-xs text-base-content/60">{{ honor.date }}</p>
        </div>
    </div>
    {% endfor %}
{% else %}
    <p class="text-sm text-base-content/60 italic">
        {{ target_truename }} 还没有添加过任何荣誉。
    </p>
{% endif %}
"""


@app.route('/api/user/<string:target_username>/recent_honors')
@login_required
def get_user_recent_honors(target_username):
    if session.get('role') != 'admin' and session.get('username') != target_username:
        return jsonify(error="Permission denied"), 403

    try:
        # 1. 获取目标用户
        user = db.session.scalar(db.select(User).where(User.username == target_username))
        if not user:
            return jsonify(success=False, error="User not found")

        # 2. 【修改】通过关系查询
        recent_honors = db.session.scalars(
            db.select(Honor).where(
                Honor.user_id == user.id
            ).order_by(Honor.date.desc()).limit(3)
        ).all()

        # 3. 渲染
        html_content = render_template_string(
            RECENT_HONORS_PARTIAL_TEMPLATE,
            honors=recent_honors,
            target_username=user.username,
            target_truename=user.truename
        )
        return jsonify(success=True, html=html_content)

    except Exception as e:
        logger.error(f"为 {target_username} 获取最近荣誉时失败: {e}")
        return jsonify(success=False, error="服务器内部错误"), 500


# --- 数据库初始化和迁移命令 (保持不变) ---
@app.cli.command("init-db")
@with_appcontext
def init_db_command():
    """清除现有数据并创建新表。"""
    try:
        # db.drop_all() # 取消注释以清空
        db.create_all()
        click.echo("数据库表已成功初始化。")
    except Exception as e:
        click.echo(f"数据库初始化失败: {e}")


@app.cli.command("migrate-data")
@with_appcontext
def migrate_data_command():
    """【新增】将旧的 .json 数据迁移到新的 SQLite 数据库。"""
    click.echo("开始数据迁移...")

    try:
        # --- 步骤 1: 迁移用户 (user.json) ---
        click.echo("正在迁移 user.json...")
        users_json = json.load(open(os.path.join(BASE_DIR, 'data', 'user.json'), 'r', encoding='utf-8'))

        all_users_from_db = db.session.scalars(db.select(User)).all()
        user_map_from_db = {user.username: user for user in all_users_from_db}

        migrated_users_count = 0
        for username, data in users_json.items():
            if username in user_map_from_db:
                continue

            new_user = User(
                username=username,
                password=data.get('password'),
                truename=data.get('truename'),
                major=data.get('major'),
                employment_day=data.get('employment_day'),
                role=data.get('role', 'user'),
                motto=data.get('motto', '')
            )
            db.session.add(new_user)
            user_map_from_db[username] = new_user
            migrated_users_count += 1

        db.session.flush()
        click.echo(f"成功迁移 {migrated_users_count} 个新用户。")

        # --- 步骤 2: 迁移荣誉 (honors.json) ---
        click.echo("正在迁移 honors.json...")
        honors_json = json.load(open(os.path.join(BASE_DIR, 'data', 'honors.json'), 'r', encoding='utf-8'))

        migrated_honors_count = 0
        for owner_username, honors_list in honors_json.items():
            owner_user = user_map_from_db.get(owner_username)
            if not owner_user:
                click.echo(f"警告：honors.json 用户 '{owner_username}' 在 user.json 中不存在，跳过。")
                continue

            for honor_data in honors_list:
                honor_id = honor_data.get('id')
                if not honor_id: continue

                existing_honor = db.session.get(Honor, honor_id)
                if existing_honor: continue

                new_honor = Honor(
                    id=honor_id,
                    name=honor_data.get('name'),
                    type=honor_data.get('type'),
                    date=honor_data.get('date'),
                    stamp=honor_data.get('stamp'),
                    stamp_other=honor_data.get('stamp_other'),
                    image_filename=honor_data.get('image_filename'),
                    honor_level=honor_data.get('honor_level') or honor_data.get('level'),
                    thumb_filename=honor_data.get('thumb_filename'),
                    original_pdf_filename=honor_data.get('original_pdf_filename'),
                    owner=owner_user
                )
                db.session.add(new_honor)
                migrated_honors_count += 1

        click.echo(f"成功迁移 {migrated_honors_count} 条新荣誉记录。")

        # --- 步骤 3: 迁移活动日志 (activity_log.json) ---
        click.echo("正在迁移 activity_log.json...")
        logs_json = json.load(open(os.path.join(BASE_DIR, 'data', 'activity_log.json'), 'r', encoding='utf-8'))

        migrated_logs_count = 0
        for username, logs_list in logs_json.items():
            logger_user = user_map_from_db.get(username)
            if not logger_user:
                click.echo(f"警告：activity_log.json 用户 '{username}' 在 user.json 中不存在，跳过。")
                continue

            for log_data in logs_list:
                try:
                    timestamp_obj = datetime.datetime.strptime(
                        log_data.get('timestamp'), '%Y-%m-%d %H:%M:%S'
                    )
                except (ValueError, TypeError):
                    timestamp_obj = datetime.datetime.utcnow()

                new_log = ActivityLog(
                    timestamp=timestamp_obj,
                    action=log_data.get('action'),
                    details=log_data.get('details'),
                    user=logger_user
                )
                db.session.add(new_log)
                migrated_logs_count += 1

        click.echo(f"成功迁移 {migrated_logs_count} 条新日志记录。")

        # --- 步骤 4: 提交所有更改 ---
        db.session.commit()
        click.echo("数据迁移成功！所有数据已提交到 app.db。")

    except Exception as e:
        db.session.rollback()
        click.echo(f"数据迁移失败: {e}")
        import traceback
        traceback.print_exc()


# --- 主程序入口 ---
if __name__ == '__main__':
    # print(f"上传根目录: {os.path.abspath(UPLOAD_FOLDER)}")
    # print(f"荣誉数据: {os.path.abspath(HONORS_DATA_FILE)}")
    # print(f"用户数据: {os.path.abspath(USER_DATA_FILE)}")
    # print(f"将尝试加载README文件: {os.path.abspath(README_FILE)}")
    print(f"数据库文件: {os.path.abspath(os.path.join(BASE_DIR, 'data', 'app.db'))}")
    app.run(debug=True, host='0.0.0.0', port=8001)