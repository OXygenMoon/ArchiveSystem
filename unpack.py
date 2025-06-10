import os

def unpack_md_to_structure(md_filepath, output_base_dir="unpacked_project_files"):
    """
    解析一个由 pack_dir_and_file 函数 (或类似逻辑) 创建的 Markdown 文件，
    并据此重建原始的目录结构和文件。

    参数:
    md_filepath (str): 输入的 Markdown 文件的路径。
    output_base_dir (str, optional): 用于重建文件和目录的根目录。
                                     默认为 "unpacked_project_files"。
    """
    try:
        with open(md_filepath, 'r', encoding='utf-8') as f:
            md_content = f.read()
    except FileNotFoundError:
        print(f"错误: Markdown 文件未找到: {md_filepath}")
        return
    except Exception as e:
        print(f"错误: 读取 Markdown 文件 '{md_filepath}' 失败: {e}")
        return

    # 确保输出的基础目录存在
    if not os.path.exists(output_base_dir):
        try:
            os.makedirs(output_base_dir)
        except OSError as e:
            print(f"错误: 创建输出目录 '{output_base_dir}' 失败: {e}")
            return

    print(f"将在以下目录重建文件结构: {os.path.abspath(output_base_dir)}")

    # 定位第一个 'file_dir: ' 标记，以处理 MD 文件头部可能存在的非文件内容
    # (原始的 pack_dir_and_file 脚本会直接以 'file_dir: ' 开头)
    first_marker_pos = md_content.find('file_dir: ')
    if first_marker_pos == -1:
        print(f"错误: MD 文件 '{md_filepath}' 中未找到 'file_dir: ' 标记。无法解析。")
        return

    # 从第一个标记开始处理内容
    content_to_process = md_content[first_marker_pos:]

    # 按 'file_dir: ' 分割内容。
    # 由于 content_to_process 以 'file_dir: ' 开头（除非 MD 文件被手动修改过），
    # 分割后的第一个元素将是空字符串。
    # 后续每个块将是 "相对路径\n\n文件内容\n\n" 的形式。
    file_entry_blocks = content_to_process.split('file_dir: ')

    files_created_count = 0
    # 跳过第一个空块 (来自split的结果，如果 'file_dir: ' 在开头)
    for block_content in file_entry_blocks[1:]:  # Start from index 1
        if not block_content.strip():  # 以防万一有其他空块或意外的格式
            continue

        relative_path_local = "未知路径"  # 用于错误日志
        try:
            # 每个块的结构是 "相对路径\n\n文件实际内容\n\n"
            # 我们只在第一个 '\n\n' 处分割，以区分路径和内容主体
            path_part, content_body_part = block_content.split('\n\n', 1)

            relative_path_local = path_part.strip()  # 清理路径两端可能存在的空白

            if not relative_path_local:
                print(f"警告: 在块中找到空的相对路径，跳过。块起始: {block_content[:70].replace(os.linesep, ' ')}...")
                continue

            # pack_dir_and_file 会在文件原始内容后添加 "\n\n"
            # 因此 content_body_part 的形式是 "原始内容\n\n"
            # 我们需要移除这个由打包脚本添加的尾部 "\n\n"
            if content_body_part.endswith('\n\n'):
                actual_content = content_body_part[:-2]
            else:
                # 如果结尾不是 "\n\n"，可能表示文件不完整或MD格式略有不同
                # (例如，MD文件最后一条记录可能不完整)
                actual_content = content_body_part  # 保留原始内容
                print(f"警告: 文件 '{relative_path_local}' 的内容块结尾未找到预期的 '\\n\\n'。内容可能不完整或格式有变。")

            full_output_path = os.path.join(output_base_dir, relative_path_local)
            output_file_dir = os.path.dirname(full_output_path)

            # 如果文件在子目录中，创建子目录
            if output_file_dir:  # 只有当路径包含目录时才创建
                os.makedirs(output_file_dir, exist_ok=True)

            with open(full_output_path, 'w', encoding='utf-8') as out_f:
                out_f.write(actual_content)

            # print(f"已创建: {full_output_path}") # 取消注释以获得每个文件的创建信息
            files_created_count += 1

        except ValueError:  # .split('\n\n', 1) 引发 ValueError 如果 '\n\n' 未找到
            print(
                f"警告: 无效的文件条目格式 (缺少 '\\n\\n' 分隔符)，跳过块: {block_content[:100].replace(os.linesep, ' ')}...")
        except Exception as e:
            print(
                f"错误: 处理块时发生意外错误 (路径可能为 '{relative_path_local}'): {e}。块起始: {block_content[:100].replace(os.linesep, ' ')}...")

    print("-" * 30)
    if files_created_count > 0:
        print(f"反向创建完成。总共创建了 {files_created_count} 个文件在目录 '{os.path.abspath(output_base_dir)}' 中。")
    else:
        print(f"未创建任何文件。请检查MD文件 '{md_filepath}' 的内容和格式是否正确，")
        print(f"并确认它是由兼容的打包脚本生成的。")

if __name__ == "__main__":
    # 1. 传入结构化文件
    dummy_md_filename = "archive_20250603_025911_936655.md"

    print("-" * 30)

    # 2. 调用解包函数
    output_directory_name = "."  # 定义输出目录名
    unpack_md_to_structure(dummy_md_filename, output_directory_name)

    print("-" * 30)
    print(f"请检查目录 '{os.path.abspath(output_directory_name)}' 的内容以确认结果。")

