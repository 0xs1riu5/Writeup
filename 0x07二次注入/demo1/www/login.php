<?php
require_once 'inc.php';
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>Login</title>
    <link rel="stylesheet" href="static/css/bootstrap.min.css" type="text/css" />
</head>
<body>

<div class="container">
    <div class="row">
        <div class="col-lg-4"></div>
        <div class="col-lg-4">
            <hr>
            <h3 class="text-center">Tips</h3>
            <p>
                你能获得美眉的手机号吗？  就在这里，存在一个高危漏洞，并且使用工具是无法达到目的的，追女神还是要用真心呀！！
            </p>
            <hr>
            <form role="form">
                <div class="form-group">
                    <h2>登录页面</h2>
                    <label for="name">用户名</label>
                    <input type="text" class="form-control" id="username" placeholder="请输入名称">
                </div>
                <div class="form-group">
                    <label for="password">密码</label>
                    <input type="password" id="password" class="form-control" placeholder="请输入密码">
                </div>
                <button type="button" class="btn btn-default" id="login">登录</button>
                <button type="button" class="btn btn-default" id="register">注册</button>
            </form>
        </div>
        <div class="col-lg-4"></div>
    </div>
</div>
<script src="static/js/jquery.min.js" type="application/javascript"></script>
<script src="static/js/bootstrap.min.js" type="application/javascript"></script>
<script>
    $("#login").bind('click',function(){
        var usernameObj = $("#username");
        var passwordObj = $("#password");
        var usernameVal = usernameObj.val();
        var passwordVal = passwordObj.val();
        if(usernameVal == "" && usernameVal.length < 4){
            alert("Username is empty or short!");
            return false;
        }
        if(passwordVal == "" && passwordVal.length < 4){
            alert("Password is empty or short!");
            return false;
        }
        $.post("/api.php?method=login",{
            "username":usernameVal,"password":passwordVal
        },function(data,status){
            var obj = jQuery.parseJSON(data);
            console.log(obj.status);
            if(obj.status){
                alert(obj.data);
                window.location.href='/index.php';
                return true;
            }else{
                alert("Error :" + obj.data);
                return false;
            }
        })
    });
    $("#register").bind('click',function(){
        window.location.href='/register.php';
    });
</script>
</body>
</html>


