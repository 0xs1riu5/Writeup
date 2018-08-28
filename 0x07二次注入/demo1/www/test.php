<?php

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

echo hex2asc("0x313233343536");

?>

