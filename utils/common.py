# utils/common.py
from flask import session

def load_session() -> dict:
    user_role = session.get('role')
    user_department = session.get('department')
    user_class = session.get('class')
    user_name = session.get('username')
    response_data = {
        "user_role": user_role,
        "user_department": user_department,
        "user_class": user_class,
        "user_name": user_name
    }
    return response_data