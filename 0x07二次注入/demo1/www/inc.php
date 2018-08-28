<?php
session_start();
define("FLAG","flag{x4dsj-x87f-1dkj}");
$SQLConnect = array(
    'DB_HOST'=> 'db',
    'DB_USER'=> 'root',
    'DB_PASS'=>'shadow',
    'DB_NAME'=>'test'
);
$mysqli = new mysqli($SQLConnect['DB_HOST'],$SQLConnect['DB_USER'],$SQLConnect['DB_PASS'],$SQLConnect['DB_NAME']);
function hex2asc($str) {
    if(substr($str,0,2)!="0x"){
        return $str;
    }
    $data = "";
    $str = join('',explode('\x',$str));
    $len = strlen($str);
    for ($i=0;$i<$len;$i+=2)
        $data.=chr(hexdec(substr($str,$i,2)));

    $data = str_replace("\0", '', $data);

    return $data;
}

function check_login(){
    if(empty($_SESSION['username']) or empty($_SESSION['phone'])){
        header("Location: /login.php");
        die();
    }
}

function safeStr($val,$mysqli){
    return  !empty($val)?$mysqli->real_escape_string($val):'';
}
