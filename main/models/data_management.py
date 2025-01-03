import pandas as pd
from config import CHUFEN_FILE, DELETE_FILE
from flask import session
import datetime
import os

def format_date_string(date_str):
    """
    格式化日期字符串为 "YYYY.MM.DD" 格式，确保月和日都有前导零。
    """
    try:
        date_obj = datetime.datetime.strptime(date_str, "%Y.%m.%d")
        return date_obj.strftime("%Y.%m.%d")
    except ValueError:
        # 如果日期格式不符合，返回原字符串或者抛出异常
        print(f"Warning: Invalid date format: {date_str}")
        return date_str  # 或者可以抛出异常 raise ValueError(f"Invalid date format: {date_str}")

def get_today_date_str():
    """
    获取当前日期并返回 "YYYY.MM.DD" 格式的字符串。
    """
    today = datetime.date.today()
    return today.strftime("%Y.%m.%d")

def load_data(filepath, user_role=None, user_class=None, user_department=None):
    try:
        df = pd.read_csv(filepath, header=0, encoding='utf-8')
    except FileNotFoundError:
        print("Error: CSV file not found.")
        return None, None

    # 关键修改：将所有 NA 值替换为空字符串
    df = df.fillna('')

    if user_department is None:
        user_department = session.get('department')

    # 如果是超级管理员，不做任何过滤
    if user_role == 'super_admin':
        pass  # df 保持原样

    # 如果是系部管理员，只能查看自己系部的数据
    elif user_role == 'department_admin' and user_department:
        df = df[df['系部'] == user_department]

    # 如果是班主任（normal_user），只能看自己班级的数据
    elif user_role == 'normal_user' and user_class:
        df = df[df['班级'].astype(str).str.contains(str(user_class))]

    # 这里的班级列如果仍需要提取数字化的逻辑，可以保留
    # 在这里做这个操作是因为，这样你就能够用str来处理班级
    df['班级'] = df['班级'].astype(str).str.extract(r'(\d+)').astype(float, errors='ignore').astype('Int64').astype(str)

    # 将 DataFrame 转换为列表
    data = df.values.tolist()

    return data, df.columns.tolist()

def add_data_entry(filepath, student_name, sex, student_class, reason, level, department):
    """
    往 CSV 中添加新的处分记录，如果文件不存在则新建 CSV 文件。
    每次在已有最大 ID 的基础上 +1，实现自增。
    """
    import pandas as pd
    import numpy as np

    today_str = get_today_date_str()

    # 先尝试读取 CSV
    try:
        df = pd.read_csv(filepath, header=0, encoding='utf-8')
        df = df.fillna('')  # 填充空值
        # 如果 DataFrame 里没有记录，或者没有 ID 列，需要额外处理
        if 'ID' not in df.columns:
            # 如果历史上真的没有 ID 列，补上并给已有行设置 ID
            # 这里简单示例：np.arange(1, len(df)+1)
            df.insert(0, 'ID', np.arange(1, len(df)+1))
        
        if df.empty:
            # 如果 CSV 中没有任何记录，则从 1 开始
            new_id = 1
        else:
            # 若已有记录，找出最大 ID
            current_max_id = df['ID'].max()
            if pd.isnull(current_max_id):
                # 如果出现异常或都是空值，默认从 1 开始
                new_id = 1
            else:
                new_id = int(current_max_id) + 1
    except FileNotFoundError:
        # 如果文件不存在则新建 DataFrame
        print("Error: CSV file not found. Creating a new file.")
        df = pd.DataFrame()
        new_id = 1

    # 拼装新增记录
    new_row = {
        'ID': new_id,               # 自增 ID
        '姓名': student_name,
        '性别': sex,                # 如果你也想存性别，可以新增列
        '班级': student_class,
        '系部': department,
        '处分等级': level,
        '日期': today_str,
        '原因': reason,
        '撤销信息': ''
    }

    # 如果 CSV 原先没有列名或列数不匹配，做下对齐
    if df.empty:
        # 全新 CSV，指定完整列顺序
        CSV_COLUMNS = ['ID','姓名','性别','班级','系部','处分等级','日期','原因','撤销信息']
        df = pd.DataFrame([new_row], columns=CSV_COLUMNS)
    else:
        # 已有记录时，按已有列名进行合并
        new_row_filtered = {col: new_row[col] for col in df.columns if col in new_row}
        df = pd.concat([df, pd.DataFrame([new_row_filtered])], ignore_index=True)
    
    # 保存回 CSV
    df.to_csv(filepath, index=False, encoding='utf-8')

def revoke_data_entry(filepath, record_id):
    try:
        df = pd.read_csv(filepath, encoding='utf-8')
        if '撤销信息' not in df.columns:
            df['撤销信息'] = ''

        # 找到 ID 等于 record_id 的行
        today_str = get_today_date_str()
        df.loc[df['ID'] == record_id, '撤销信息'] = f'{today_str} 已撤销'
        df.to_csv(filepath, index=False, encoding='utf-8')
        return True
    except Exception as e:
        print(f"Error: Could not revoke data. {e}")
        return False

def delete_data_entry(filepath, record_id):
    """
    删除数据，并将删除的数据添加到单独的 csv 文件
    """
    try:
        df = pd.read_csv(filepath, encoding='utf-8')

        # 找到要删除的行
        deleted_row = df[df['ID'] == record_id]

        if deleted_row.empty:
            return False, "未找到要删除的记录"

        # 从原数据中删除
        df = df[df['ID'] != record_id]
        df.to_csv(filepath, index=False, encoding='utf-8')

         # 记录删除时间
        today_str = get_today_date_str()
        deleted_row['删除时间'] = today_str

        # 添加到 4.csv
        try:
            deleted_df = pd.read_csv(DELETE_FILE, encoding='utf-8')
            deleted_df = pd.concat([deleted_df, deleted_row], ignore_index=True)
        except FileNotFoundError:
             deleted_df = deleted_row
            
        deleted_df.to_csv(DELETE_FILE, index=False, encoding='utf-8')

        return True, "记录删除成功！"
    except Exception as e:
        print(f"Error: Could not delete data. {e}")
        return False, f"删除失败，错误信息：{e}"
