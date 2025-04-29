from werkzeug.utils import secure_filename
from pypinyin import lazy_pinyin
filename = secure_filename('全国青少年信息素养大赛 优秀指导教师.jpg')
print(filename)