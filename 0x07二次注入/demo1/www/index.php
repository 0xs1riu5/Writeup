<?php
require_once 'inc.php';
check_login();
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>主页</title>
    <link rel="stylesheet" href="static/css/bootstrap.min.css" type="text/css" />
</head>
<body>
<script src="static/js/bootstrap.min.js" type="application/javascript"></script>
<div class="container">
    <div class="row">
        <div class="col-lg-4"></div>
        <div class="col-lg-4">
            <h2>Hello,<?php echo $_SESSION['username'];?></h2>
            <p>
                Your phone is <?php echo hex2asc($_SESSION['phone']);?>
                <!-- Code by 倾旋 -->
            </p>

            <p>
                <button class="btn btn-default" id="check">check</button>
                <button class="btn btn-default" id="logout">logout</button>
            </p>
        </div>
        <div class="col-lg-4"></div>
    </div>
</div>
<hr>
<script src="static/js/jquery.min.js" type="application/javascript"></script>
<script>
    $("#logout").bind('click',function(){
        window.location.href="/logout.php";
    });
    $("#check").bind('click',function(){
        window.location.href="/check.php";
    });
</script>
</body>
</html>


