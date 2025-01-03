# models/user_management.py

import os
import json
import bcrypt
from config import USER_DB

def load_users():
    """
    从 JSON 文件加载用户数据。
    如果文件不存在则创建一个空文件并返回空字典。
    """
    if not os.path.exists(USER_DB):
        with open(USER_DB, 'w', encoding='utf-8') as f:
            json.dump({}, f)
        return {}
    with open(USER_DB, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_users(users):
    """
    将用户数据保存到 JSON 文件。
    """
    with open(USER_DB, 'w', encoding='utf-8') as f:
        json.dump(users, f, indent=4, ensure_ascii=False)


def create_user(username, password, department, user_class, role='normal_user'):
    """
    创建新用户并保存到数据库 (JSON 文件)。
    
    :param username: 用户名
    :param password: 明文密码（在此函数内进行哈希）
    :param department: 用户所属系部
    :param user_class: 用户所属班级
    :param role: 用户角色，默认为 normal_user
    :return: (bool, str) -> (是否创建成功, 消息)
    """
    users = load_users()
    if username in users:
        return False, "用户名已存在"

    # 使用 bcrypt 对密码进行哈希
    hashed_password = password
    users[username] = {
        'password': hashed_password,
        'department': department,
        'class': user_class,
        'role': role
    }
    save_users(users)
    return True, "注册成功"


def verify_user(username, password):
    """
    验证用户名和密码，成功则返回用户信息 (角色, 系部, 班级)，否则返回 False。
    """
    users = load_users()
    if username in users:
        user = users[username]
        stored_hash = user['password'].encode('utf-8')
        # 验证明文密码和数据库中的哈希是否匹配
        if password == user['password']:
            return True, user['role'], user['department'], user['class']
    return False, None, None, None

