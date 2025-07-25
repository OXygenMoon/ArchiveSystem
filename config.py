import os
import secrets

# 项目根目录
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Flask 的 SECRET_KEY
SECRET_KEY = secrets.token_urlsafe(32)

# 荣誉类型
HONOR_TYPE = (
    '教学比武',
    '技能比武',
    '学生竞赛',
    '荣誉',
    '论文',
    '课题',
    '成果',
    '报告',
    '案例',
    '讲座',
    '说课',
    '公开课',
    '研修',
    '教材',
    '班级',
    '其他'
)

# 等级
LEVEL_TYPE = (
    '国家级',
    '省级',
    '市级',
    '县级',
    '校级'
)

# 专业
MAJOR_TYPE = (
    '语文',
    '数学',
    '英语',
    '政治',
    '历史',
    '地理',
    '财会',
    '文秘',
    '国贸',
    '幼儿',
    '体育',
    '心理',
    '工美',
    '计算机',
    '机械',
    '电子'    
)