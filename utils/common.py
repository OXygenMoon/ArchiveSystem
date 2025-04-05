# utils/common.py
from flask import session
import pandas as pd
import os

# CSV 文件路径
DATA_FILE_JINGYI = os.path.join('data/weiji_jingyixi.csv')
DATA_FILE_ZHIZAO = os.path.join('data/weiji_zhizaoxi.csv')

def load_session() -> dict:
    '''
    加载session中身份的相关信息, 用于路由中处理相关逻辑
    '''
    user_role = session.get('role')
    user_department = session.get('department')
    user_class = session.get('class')
    user_name = session.get('username')
    user_truename = session.get('truename')
    response_data = {
        "user_role": user_role,
        "user_department": user_department,
        "user_class": user_class,
        "user_name": user_name,
        "user_truename": user_truename
    }
    return response_data

def load_data(department):
    '''
    根据系部来选择对应的数据表
    '''
    if department == '经艺系':
        data = pd.read_csv(DATA_FILE_JINGYI, encoding = 'utf-8')
    elif department == '智能制造系':
        data = pd.read_csv(DATA_FILE_ZHIZAO, encoding = 'utf-8')
    elif department == '高职系':
        pass

    # 将所有的 NaN 填充为空字符串
    data = data.fillna('')
    return data

