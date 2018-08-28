<?php
/**
 * Created by PhpStorm.
 * User: liyingzhe
 * Date: 13/11/17
 * Time: 下午9:19
 */
session_start();
session_destroy();
$_SESSION = array();
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>退出！</title>
</head>
<body>
    退出成功！！
<script>
    window.location.href='login.php';
</script>

</body>
</html>
