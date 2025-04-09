# config.py

import os
import secrets

# 项目根目录
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# CSV 文件路径
DATA_FILE_JINGYI = os.path.join(BASE_DIR, 'data/weiji_jingyixi.csv')
DATA_FILE_ZHIZAO = os.path.join(BASE_DIR, 'data/weiji_zhizaoxi.csv')
ARCHIVE_CSV = 'data/archive.csv'  # 用于存储删除记录的 CSV


# 存放生成的处分文档的文件夹
# ARCHIVE_DIR = os.path.join(BASE_DIR, '违纪处分存档')

# 用户信息存储文件 (JSON)
USER_DB = os.path.join(BASE_DIR, 'data/user.json')

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

# 上传路径
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')

# 允许上传的文件拓展名
ALLOWED_UPLOAD_EXTENSIONS = {'csv', 'xlsx'}

# 处分等级
WEIJI_LEVELS = [
    '警告',
    '严重警告',
    '记过',
    '留校察看',
    '开除学籍'
]


# 处分类型
WEIJI_TYPES = [
    '手机管理',
    '课堂纪律',
    '男女关系',
    '同学关系',
    '寝室违纪',
    '破坏公物',
    '抽烟',
    '打架',
    '出勤',
    '其他原因'
]