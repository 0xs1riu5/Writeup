<?php

if (isset($_POST['submit'])) {
	$blacklist = array(".php", ".phtml", ".php3", ".php4");
foreach ($blacklist as $item) {
if(preg_match("/$item\$/i", $_FILES['upfile']['name'])) {
 echo "We do not allow uploading PHP files\n";
 exit;
}
}
$uploaddir = 'uploads/';
$uploadfile = $uploaddir . basename($_FILES['upfile']['name']);
if (move_uploaded_file($_FILES['upfile']['tmp_name'], $uploadfile)){
 echo "File is valid, and was successfully uploaded.\n";
} else {
 echo "File uploading failed.\n";
}
}
?>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta http-equiv="Content-Type" content="text/html;charset=utf-8"/>
    <meta http-equiv="content-language" content="zh-CN"/>
    <title>上传</title>
<body>
<h3>上传</h3>

<form action="" method="post" enctype="multipart/form-data" name="upload" onsubmit="return true">
    <input type="hidden" name="MAX_FILE_SIZE" value="204800"/>
    请选择要上传的文件：<input type="file" name="upfile"/>
    <input type="submit" name="submit" value="上传"/>
</form>
</body>
</html>
