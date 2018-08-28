<?php
require_once 'inc.php';
check_login();
$sql = "SELECT phone FROM user where username = '{$_SESSION['username']}'";
if(!$res = $mysqli->query($sql)->fetch_assoc()){
    die( 'db error !!!');
}
$phone = hex2asc($res['phone']);
$sql = "SELECT COUNT(*) FROM user WHERE phone = '{$phone}'";
if(!$row = $mysqli->query($sql)->fetch_all()){
    die( 'db error ');
}
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>Check</title>
    <link rel="stylesheet" href="static/css/bootstrap.min.css" type="text/css" />
</head>
<body>
<div class="container">
    <div class="row">
        <div class="col-lg-4"></div>
        <div class="col-lg-4">
            <h2>Check</h2>
            <?php foreach ($row as $r){?>
            <p>Your phone used by <?php echo $r[0] ?> people.</p>
            <?php };?>

            <button class="btn btn-default" onclick="window.location.href='index.php'">Back</button>
        </div>
        <div class="col-lg-4"></div>
    </div>
</div>
<script src="static/js/jquery.min.js" type="application/javascript"></script>
<script src="static/js/bootstrap.min.js" type="application/javascript"></script>
</body>
</html>


