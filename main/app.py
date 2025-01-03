# app.py
import os
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify, send_file
)
from functools import wraps

# 从 config 中导入配置
from config import (
    SECRET_KEY, USER_ROLES, DEPARTMENTS,
    DELETE_FILE, CHUFEN_FILE, ARCHIVE_DIR, BASE_DIR
)

# 从 models 中导入业务逻辑函数
from models.user_management import load_users, save_users, create_user, verify_user
from models.data_management import load_data, add_data_entry, revoke_data_entry, delete_data_entry
from models.document_generator import create_document

# 如果需要确保 ARCHIVE_DIR 存在，可以这里保证
os.makedirs(ARCHIVE_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = SECRET_KEY  # 使用 config.py 中的 SECRET_KEY


# ------------------------- 认证装饰器 -------------------------
def login_required(roles=None):
    """
    要求用户必须登录的装饰器，可选地指定角色来限制访问权限。
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not session.get('logged_in'):
                return redirect(url_for('home'))
            if roles and session.get('user_role') not in roles:
                return "您没有权限访问该页面", 403
            return func(*args, **kwargs)
        return wrapper
    return decorator


# ------------------------- 路由部分 -------------------------

@app.route('/')
def home():
    """
    主页路由，若已登录则跳转到 index，否则渲染 home.html。
    """
    if session.get('logged_in'):
        return redirect(url_for('index'))
    return render_template('home.html')


@app.route('/index', methods=['GET', 'POST'])
@login_required()
def index():
    """
    数据管理主页：
    - GET: 加载并显示违纪处分数据
    - POST: 仅当角色为 department_admin 或 super_admin 时才可新增记录并生成文档
    """
    user_role = session.get('user_role')
    user_department = session.get('department')
    user_class = session.get('class')
    username = session.get('username', '')

    # 仅管理员级别才可提交数据
    if request.method == 'POST' and user_role in ['department_admin', 'super_admin']:
        student_name = request.form['student_name']
        sex = request.form['student_sex']
        student_class = request.form['student_class']
        reason = request.form['reason']
        level = request.form['level']
        department = request.form.get('department', session.get('department', ''))


        # 判断必填项
        if not all([student_name, student_class, reason, level]):
            error_message = "请完整填写所有信息"
            data, columns = load_data(CHUFEN_FILE, user_role, user_class)
            return render_template(
                'index.html',
                error_message=error_message,
                data=data,
                columns=columns,
                departments=DEPARTMENTS,
                user_role=user_role,
                username=username,
                user_department=user_department
            )

        # 添加数据并生成文档
        add_data_entry(CHUFEN_FILE, student_name, sex, student_class, reason, level, user_department)
        file_name = create_document(student_name, sex, student_class, reason, level, user_department)
        data, columns = load_data(CHUFEN_FILE, user_role, user_class)
        return render_template(
            'index.html',
            file_name=file_name,
            data=data,
            columns=columns,
            departments=DEPARTMENTS,
            user_role=user_role,
            username=username,
            user_department=user_department
        )

    # GET 请求，或角色不匹配时，直接读取数据
    data, columns = load_data(CHUFEN_FILE, user_role, user_class)
    return render_template(
        'index.html',
        data=data,
        columns=columns,
        departments=DEPARTMENTS,
        user_role=user_role,
        username=username,
        user_department=user_department
    )


@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    用户注册路由：
    - GET: 显示注册表单
    - POST: 处理注册逻辑
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        department = request.form['department']
        user_class = request.form['class']

        success, message = create_user(username, password, department, user_class, role='normal_user')
        if success:
            return redirect(url_for('login'))
        else:
            return render_template('register.html', error=message, departments=DEPARTMENTS)

    return render_template('register.html', departments=DEPARTMENTS)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    用户登录路由：
    - GET: 显示登录页面
    - POST: 验证登录
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        success, role, department, user_class = verify_user(username, password)
        if success:
            session['logged_in'] = True
            session['user_role'] = role
            session['department'] = department
            session['class'] = user_class
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error="用户名或密码错误")
    return render_template('login.html')


@app.route('/logout')
def logout():
    """
    用户登出路由，清空 session 并重定向到登录页。
    """
    session.clear()
    return redirect(url_for('login'))


@app.route('/revoke', methods=['POST'])
@login_required(roles=['department_admin','super_admin'])
def revoke():
    data_json = request.get_json()
    record_id = data_json.get('record_id')
    if record_id:
        success = revoke_data_entry(CHUFEN_FILE, record_id)
        if success:
            return jsonify({"success": True, "message": "已撤销"})
        else:
            return jsonify({"success": False, "message": "撤销失败"})
    else:
        return jsonify({"success": False, "message": "没有选中数据"})


@app.route('/delete', methods=['POST'])
@login_required(roles=['super_admin','department_admin'])
def delete():
    """
    删除数据记录的路由
    """
    data_json = request.get_json()
    record_id = data_json.get('record_id')
    if record_id:
        success, message = delete_data_entry(CHUFEN_FILE, record_id)
        if success:
            return jsonify({"success": True, "message": message})
        else:
             return jsonify({"success": False, "message": message})
    else:
        return jsonify({"success": False, "message": "没有选中数据"})


@app.route('/download/<filename>')
@login_required()
def download_file(filename):
    """
    文件下载路由：下载生成的处分文档。
    """
    file_path = os.path.join(ARCHIVE_DIR, filename)
    if not os.path.exists(file_path):
        return "文件未找到", 404

    return send_file(
        file_path,
        as_attachment=True,
        download_name=filename,
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    )

# 启动应用（开发环境下）
if __name__ == '__main__':
    app.run()
