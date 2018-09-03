<?php
$sandbox = '/var/www/html/upload/' . md5("phpIsBest" . $_SERVER['REMOTE_ADDR']);
@mkdir($sandbox);
@chdir($sandbox);

if (!empty($_FILES['file'])) {
    #mime check
    if (!in_array($_FILES['file']['type'], ['image/jpeg', 'image/png', 'image/gif'])) {
        die('This type is not allowed!');
    }

    #check filename
    $file = empty($_POST['filename']) ? $_FILES['file']['name'] : $_POST['filename'];
    if (!is_array($file)) {
        $file = explode('.', strtolower($file));
    }
    $ext = end($file);
    if (!in_array($ext, ['jpg', 'png', 'gif'])) {
        die('This file is not allowed!');
    }

    $filename = reset($file) . '.' . $file[count($file) - 1];
    if (move_uploaded_file($_FILES['file']['tmp_name'], $sandbox . '/' . $filename)) {
        echo 'Success!';
        echo 'filepath:' . $sandbox . '/' . $filename;
    } else {
        echo 'Failed!';
    }
}
show_source(__file__);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Upload Your Shell</title>
</head>
<body>
<form action="" method="post" enctype="multipart/form-data">
    <label for="file">Filename:</label>
    <input type="text" name="filename"><br>
    <input type="file" name="file" id="file" />
    <input type="submit" name="submit" value="Submit" />
</form>
</body>
</html>
Filename:  

 