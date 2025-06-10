import os
import datetime

def is_Should_Process(filename, relative_path_str, output_md_filename, script_name,
                      active_include_list, 
                      normalized_exclude_suffixes, # 如果 normalized_include_suffixes 生效，此列表会为空
                      normalized_include_suffixes): # 新增参数
    """
    辅助函数，根据各种过滤器判断一个文件是否应该被处理。
    """
    # 1. 过滤隐藏文件 (文件名以 '.' 开头)
    if filename.startswith('.'):
        return False

    # 2. 过滤脚本自身和输出的 Markdown 文件
    if filename == output_md_filename or filename == script_name:
        return False

    _file_base, file_ext = os.path.splitext(filename)
    file_ext_lower = file_ext.lower()

    # 3. 根据包含的后缀名进行过滤 (如果激活状态)
    if normalized_include_suffixes: # 如果提供了这个列表并且它不为空
        if file_ext_lower not in normalized_include_suffixes:
            return False
        # 如果后缀在包含列表中，则通过此检查。
        # 此时 normalized_exclude_suffixes 在 pack_dir_and_file 中已被设置为空，所以无需额外处理。
    elif normalized_exclude_suffixes: # 仅当 normalized_include_suffixes 未激活时，才检查排除的后缀
        if file_ext_lower in normalized_exclude_suffixes:
            return False

    # 4. 根据包含列表进行过滤 (如果激活状态)
    if active_include_list:
        path_components = os.path.normpath(relative_path_str).split(os.sep)
        match_found_in_include_list = False
        for part in path_components:
            if part in active_include_list:
                match_found_in_include_list = True
                break
        if not match_found_in_include_list:
            return False

    return True # 如果所有检查都通过，或者相关过滤器未激活

def pack_dir_and_file(include_list=None, exclude_suffixes=None, include_suffixes=None): # 新增 include_suffixes 参数
    """
    将当前目录及其子目录下的文件内容拷贝到一个新的 Markdown 文件中，
    支持通过 include_list 指定包含项，exclude_suffixes 指定排除的后缀名，
    以及 include_suffixes 指定只包含的后缀名 (优先于 exclude_suffixes)。

    参数:
    include_list (list, optional): 字符串列表。如果提供，则只处理其文件名或路径的任一部分
                                   出现在此列表中的文件。默认为 None (不应用此过滤器)。
    exclude_suffixes (list, optional): 字符串列表。指定要排除的文件后缀名 (例如,
                                       ['.log', 'tmp'])。后缀名不区分大小写，
                                       程序会自动处理前导的点 '.'。默认为 None (不应用此过滤器)。
                                       如果提供了 include_suffixes，此参数将被忽略。
    include_suffixes (list, optional): 字符串列表。如果提供，则只处理具有这些后缀名的文件。
                                       (例如, ['.py', '.txt'])。后缀名不区分大小写，
                                       程序会自动处理前导的点 '.'。
                                       如果此参数被提供且非空，exclude_suffixes 参数将被忽略。
                                       默认为 None (不应用此过滤器)。
    """
    # --- 参数初始化与规范化 ---
    active_include_list = include_list or [] 

    normalized_include_suffixes = []
    if include_suffixes: # 优先处理 include_suffixes
        for suffix in include_suffixes:
            s = suffix.lower()
            if not s.startswith('.'):
                s = '.' + s
            normalized_include_suffixes.append(s)
        # 如果 include_suffixes 生效，则 exclude_suffixes 失效
        normalized_exclude_suffixes = []
    else: # 如果 include_suffixes 未提供或为空，则处理 exclude_suffixes
        normalized_exclude_suffixes = []
        if exclude_suffixes:
            for suffix in exclude_suffixes:
                s = suffix.lower()
                if not s.startswith('.'):
                    s = '.' + s
                normalized_exclude_suffixes.append(s)

    # --- 文件命名与设置 ---
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    output_md_filename = f"archive_{timestamp}.md" 
    script_name = os.path.basename(__file__)
    current_directory = os.getcwd()

    print(f"脚本开始运行...")
    print(f"当前工作目录: {current_directory}")
    print(f"输出 Markdown 文件: {output_md_filename}")

    if active_include_list:
        print(f"只包含文件名或路径部分在以下列表中的项: {active_include_list}")
    
    if normalized_include_suffixes: # 如果 include_suffixes 生效
        print(f"只打包以下后缀名的文件: {normalized_include_suffixes} (参数 exclude_suffixes 将被忽略)")
    elif normalized_exclude_suffixes: # 否则，如果 exclude_suffixes 生效
        print(f"排除以下后缀名的文件: {normalized_exclude_suffixes}")
        
    print("将忽略所有名称以 '.' 开头的隐藏文件和文件夹。")
    print("-" * 30)

    files_processed_count = 0
    try:
        with open(output_md_filename, 'w', encoding='utf-8', errors='ignore') as md_file:
            for root, dirs, files in os.walk(current_directory, topdown=True):
                dirs[:] = [d for d in dirs if not d.startswith('.')]

                for filename in files:
                    full_file_path = os.path.join(root, filename)
                    relative_path_for_file = os.path.relpath(full_file_path, current_directory)

                    if is_Should_Process(filename, relative_path_for_file,
                                         output_md_filename, script_name,
                                         active_include_list, 
                                         normalized_exclude_suffixes, # 传递规范化后的列表
                                         normalized_include_suffixes): # 传递规范化后的列表
                        try:
                            md_file.write(f'''file_dir: {relative_path_for_file}\n\n''')
                            print(f"正在处理: {relative_path_for_file}")

                            with open(full_file_path, 'r', encoding='utf-8', errors='ignore') as f_content:
                                content = f_content.read()
                                md_file.write(f"{content}\n\n")
                            files_processed_count += 1
                        except Exception as e:
                            error_message = f"处理文件 {relative_path_for_file} 时发生错误: {e}\n\n"
                            md_file.write(f"无法读取文件: {relative_path_for_file}\n错误: {e}\n\n")
                            print(f"错误: 处理 {relative_path_for_file} - {e}")
        
        print("-" * 30)
        print(f"处理完成。总共处理了 {files_processed_count} 个文件。")
        print(f"所有符合条件的文件已成功拷贝到 {output_md_filename}")

    except IOError as e:
        print(f"创建或写入 Markdown 文件时发生严重错误: {e}")
    except Exception as e:
        print(f"发生未知严重错误: {e}")


if __name__ == "__main__":
    '''
    :param include_list: 只打包的文件目录和文件名
    :param exclude_suffixes: 过滤的后缀名 (如果 include_suffixes 未指定)
    :param include_suffixes: 只打包指定后缀名的文件 (优先于 exclude_suffixes)
    '''

    pack_dir_and_file(
        exclude_suffixes=['css', 'js', 'html', 'txt', 'png','jpg', 'jpeg', '.log', 'tmp', 'csv', 'md', 'pyc'])
