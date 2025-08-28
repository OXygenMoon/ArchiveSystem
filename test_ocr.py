import os
from PIL import Image
import pytesseract

print("--- 开始Tesseract独立测试 ---")

# 1. 设置我们之前确认的TESSDATA_PREFIX路径
tessdata_path = '/usr/share/tesseract-ocr/5/tessdata'
os.environ['TESSDATA_PREFIX'] = tessdata_path
print(f"已设置 TESSDATA_PREFIX = {tessdata_path}")

# 2. 检查路径和文件是否存在
print(f"检查目录是否存在: {os.path.exists(tessdata_path)}")
lang_file_path = os.path.join(tessdata_path, 'chi_sim.traineddata')
print(f"检查语言文件是否存在: {os.path.exists(lang_file_path)}")

# 3. 尝试初始化Tesseract
try:
    # 创建一个纯白的临时图片来测试
    dummy_image = Image.new('RGB', (200, 50), color = 'white')

    # 核心测试：调用pytesseract
    text = pytesseract.image_to_string(dummy_image, lang='chi_sim')

    print("\n✅✅✅ 测试成功! ✅✅✅")
    print("Pytesseract成功初始化并识别出以下内容 (来自一张白纸，所以应该是空的):")
    print(f"---识别结果开始---\n{text}\n---识别结果结束---")

except Exception as e:
    print("\n❌❌❌ 测试失败! ❌❌❌")
    print("错误详情:")
    print(e)

print("\n--- 测试结束 ---")