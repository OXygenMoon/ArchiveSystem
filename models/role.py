from functools import wraps
from flask import Flask, request, jsonify, session, redirect, url_for, render_template
import json

def load_user():
    with open('../data/user.json', 'r') as f:
        users = json.load(f)
        return users

def get_user_role():
    # users = load_user()
    # token = request.headers.get('Authorization')
    role = session.get('role')
    return role

# 权限检查装饰器
def required_role(role):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user_role = get_user_role()
            if user_role == role:
                return func(*args, **kwargs)
            else:
                # return jsonify({'message': 'Unauthorized'}), 403  # 403 Forbidden
                error = '权限不足 Unauthorized 403'
                return render_template('error.html', error = error)
        return wrapper
    return decorator