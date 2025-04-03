# 将required_role装饰器移动到 utils/decorators.py
from functools import wraps
from flask import abort, session, current_app, redirect, url_for
import redis

def required_role(roles):  # 强制角色为字符串列表
    """
    权限装饰器，检查用户是否拥有指定的角色。

    Args:
        roles: 允许访问的角色列表 (字符串列表)。

    Returns:
        装饰器函数。
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_role = session.get('role')

            # 1. 检查用户是否已登录（session中是否存在role）
            if not user_role:
                current_app.logger.warning("Unauthorized access: No role found in session.") # 记录日志
                abort(401)  # 401 Unauthorized 更合适，表示需要认证

            # 2. 检查用户角色是否在允许的角色列表中
            if user_role not in roles:
                current_app.logger.warning(f"Unauthorized access: User role '{user_role}' not in allowed roles '{roles}'.") # 记录日志
                abort(403)  # 403 Forbidden，表示无权限

            return f(*args, **kwargs)
        return decorated_function
    return decorator

def check_redis_session(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 如果 session 中没有用户标识，直接视为未登录
        if 'username' not in session:
            return redirect(url_for('index'))
        
        # 获取浏览器中的 session_id
        browser_session_id = session.sid  # Flask-Session 提供的 session ID
        
        # 从 Flask 配置中获取 Redis 连接
        redis_conn = current_app.config['SESSION_REDIS']
        
        # 构造 Redis 中存储 Session 的键名（需与 Flask-Session 的存储格式一致）
        redis_session_key = f"session:{browser_session_id}"
        
        # 检查 Redis 中是否存在此 Session
        if not redis_conn.exists(redis_session_key):
            # 若不存在，清空浏览器 Session 并重定向到登录页
            session.clear()
            return redirect(url_for('index'))
        
        # 如果 Session 有效，正常执行路由逻辑
        return f(*args, **kwargs)
    return decorated_function