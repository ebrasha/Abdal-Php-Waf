<?php
/**
 * Created by Abdal Security Group.
 * Programmer: Ebrahim Shafiei
 * Programmer WebSite: https://hackers.zone/
 * Programmer Email: Prof.Shafiei@Gmail.com
 * License : AGCL
 * Current Date : 2020-09-01
 * Current Time : 7:46 PM
 */


namespace ABDALPHPWAF;
require_once 'class-central-utility.php';


class PROXY_PROTECTION
{

    public static $attack_status = false;

    public static function proxy_detector()
    {


//####################################################
        /**
         * This feature slows down your site
         */
//        $proxy_ports = array(
//            8080,
//            80,
//            81,
//            1080,
//            6588,
//            8000,
//            3128,
//            553,
//            554,
//            4480
//        );

//        foreach ($proxy_ports as $port) {
//            if (@fsockopen($_SERVER['REMOTE_ADDR'], $port, $errno, $err_str, 1)) {
//                self::$attack_status = true;
//            }
//        }
//
//####################################################


        $proxy_headers = array(
            'HTTP_VIA',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_FORWARDED',
            'HTTP_CLIENT_IP',
            'HTTP_FORWARDED_FOR_IP',
            'VIA',
            'X_FORWARDED_FOR',
            'FORWARDED_FOR',
            'X_FORWARDED',
            'FORWARDED',
            'CLIENT_IP',
            'FORWARDED_FOR_IP',
            'HTTP_PROXY_CONNECTION'
        );


        foreach ($proxy_headers as $header) {
            if (isset($_SERVER[$header])) {
                self::$attack_status = true;
            }
        }




        return self::$attack_status;


    }

}