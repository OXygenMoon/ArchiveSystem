# config.py

import os
import secrets

# 项目根目录
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# CSV 文件路径
CHUFEN_FILE = os.path.join(BASE_DIR, 'data/chufen.csv')
DELETE_FILE = os.path.join(BASE_DIR, 'data/delete.csv')

# 存放生成的处分文档的文件夹
ARCHIVE_DIR = os.path.join(BASE_DIR, '违纪违规处理')

# 用户信息存储文件 (JSON)
USER_DB = os.path.join(BASE_DIR, 'users.json')

# Flask 的 SECRET_KEY
SECRET_KEY = secrets.token_urlsafe(32)

# 用户角色和系部
USER_ROLES = {
    'super_admin': '超级管理员',
    'department_admin': '系部管理员',
    'normal_user': '班主任'
}

DEPARTMENTS = [
    '智能制造系',
    '高职系',
    '经艺系'
]

