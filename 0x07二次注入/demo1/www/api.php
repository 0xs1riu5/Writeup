<?php
/**
 * Created by PhpStorm.
 * User: liyingzhe
 * Date: 13/11/17
 * Time: 下午8:22
 */
require_once 'inc.php';
$_API = $_GET['method'];
$api_result = array('status'=>false,'data'=>'');
if($_API=="login"){
    $username = safeStr($_POST['username'],$mysqli);
    $password = !empty($_POST['password'])?md5($_POST['password']):NULL;
    if(empty($username) or empty($password)){
        $api_result['data'] = 'password or username is empty !';
        echo json_encode($api_result);
        return false;
    }
    $SQL = "SELECT username,phone FROM user WHERE username ='{$username}' AND password = '{$password}'";
    $res = $mysqli->query($SQL)->fetch_assoc();
    if(!empty($res['username']) && !empty($res['phone'])){
        $_SESSION['is_login'] = true;
        $_SESSION['username'] = $res['username'];
        $_SESSION['phone'] = $res['phone'];
        $api_result['data'] = 'login success !';
        $api_result['status'] = true;
        echo json_encode($api_result);
        return true;
    }
    $api_result['data'] = 'unknown error !';
    echo json_encode($api_result);
    return true;
}


if($_API=="register"){
    $phone = !empty($_POST['phone']) && is_numeric($_POST['phone'])?$_POST['phone']:NULL;
    $username = safeStr($_POST['username'],$mysqli);
    $password = !empty($_POST['password'])?md5($_POST['password']):NULL;
    if(empty($username) or empty($password) or empty($phone)){
        $api_result['data'] = 'password / username / phone is empty !';
        echo json_encode($api_result);
        return false;
    }
    // $SQL = "SELECT username,phone FROM user WHERE username ='{$username}' AND password = '{$password}'";
    $sql = "SELECT username FROM user where username = '{$username}'";
    if(!empty($mysqli->query($sql)->fetch_assoc())){
        $api_result['data'] = 'The user name already exists !';
        echo json_encode($api_result);
        return false;
    }
    $SQL = "INSERT INTO user(username, password, phone) VALUE ('${username}','{$password}','{$phone}')";
    $res = $mysqli->query($SQL);
    if($res){
        $_SESSION['is_login'] = true;
        $_SESSION['username'] = $username;
        $_SESSION['phone'] = $phone;
        $api_result['data'] = 'login success !';
        $api_result['status'] = true;
        echo json_encode($api_result);
        return true;
    }
    $api_result['data'] = 'unknown error !!';
    echo json_encode($api_result);
    return true;
}