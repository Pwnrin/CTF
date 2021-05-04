Use "\xF1: icebp" bypass signal_handler
Use syscall in handler bypass seccomp sandbox
# 感觉把队友坑了，最开始拿到题目自己造的爆破轮子，因为没有控制好阻塞判断，跑出 "\xF1" 后自己手动 Ctrl + C 了，白白浪费了大片时间
