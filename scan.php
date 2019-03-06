<?php

/** 
 * Author: Caio Agiani
 * Description: IP Blacklist abuse scan
 * Website: https://apility.io
 */

extract($_GET);
define('WEBSITE', 'https://api.apility.net/v2.0/ip/'. $ip .'?items=100');
define('TOKEN', 'fbe33ac7-ee38-468d-bb07-37ceca3f317a');

if (isset($_GET['ip'])) {

    class iPScan {

        public function _cURL($url, $post = false, $header = array('')) {
            
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
            curl_setopt($ch, CURLOPT_USERAGENT, $_SERVER['HTTP_USER_AGENT']);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);

            if ($post)
                curl_setopt($ch, CURLOPT_POSTFIELDS, $post);
    
            $data = curl_exec($ch);
            curl_close($ch);

            return $data;
        }
    }

    function color($hex, $text) {
        return '<font class="label label-danger" style="background-color:' .$hex. '">' .$text. '</font>';
    }

    if (filter_var($ip, FILTER_VALIDATE_IP)) {
        $new = new iPScan;
        $url = $new->_cURL(WEBSITE, false, array('Content-Type: application/json','X-Auth-Token: '.TOKEN));
        $obj = json_decode($url, true);

        $j = $obj['fullip']['badip'];

        if (!is_array($j))
            die('TOKEN '.TOKEN.' Inválido.');

        $score = $j['score'];

        if ($score !== 0) {
            $msg = '';

            foreach ($j as $key => $value) {
                $num = is_array($value) ? count($value) : 0;
            }
            
            foreach ($value as $key => $value) {
                $msg .= ' '. color('#FF0000', $value);
            }

            echo $ip. ' WAS FOUND IN <b>' .$num. '</b> BLACK LIST(S): '. $msg;
        }
        else {
            echo $ip. ' ' .color('#00FF00', 'NOT FOUND'). ' BLACK LIST(S)';
        }

        if ($obj['fullip']['history']['score'] !== 0) {
            $j = $obj['fullip']['history']['activity'];

            echo "<hr />IP address historic information: <br />";

            foreach ($j as $key => $value) {
                echo "<pre />";

                $cmd = $value['command'];
                $blacklist = $value['blacklists'] ? $value['blacklists'] : $value['blacklist_change'];

                $final = str_replace('add', '+ '.color('#FF0000', 'IP was added to blacklist(s)'), $cmd. ' -> ['. $blacklist. ']');
                echo $final = str_replace('rem', '- '.color('#00FF00', 'IP was removed from blacklist(s)'), $final);
            }
        }
        else {
            echo '<hr />IP address historic information: '. color('#00FF00', '0');
        }
    } 
    else {
        echo 'IP inválido';
    }
}
else {
    echo 'Use ?ip=198.46.178.97';
}
