<?php namespace ANTI_XSS_CORE;
/**
 * Created by Abdal Security Group.
 * Programmer: Ebrahim Shafiei
 * Programmer WebSite: https://hackers.zone/
 * Programmer Email: Prof.Shafiei@Gmail.com
 * License : AGCL
 */

namespace ABDALPHPWAF;
require_once 'class-central-utility.php';


class Anti_CRLF extends Central_Utility
{
    public static $attack_status = false;



    public static function crlf_detector($uri)
    {

        $crlf_pattern = array(
            "%0d%0a"
        );

        if ($_SERVER['REQUEST_METHOD'] === "GET") {

            foreach ($crlf_pattern as $key => $value) {
                if (strpos(self::url_normalizer($uri), "{$value}") !== false) {
                    self::$attack_status = true;
                }
            }


        } elseif ($_SERVER['REQUEST_METHOD'] === "POST") {

            foreach ($_POST as $item => $value) {
                $postData = self::url_normalizer("{$value}");
                foreach ($crlf_pattern as $xss_array_value) {
                    if ($postData == $xss_array_value) {

                        self::$attack_status = true;

                    }
                }
            }
        } else {
            foreach ($crlf_pattern as $key => $value) {
                if (strpos(self::url_normalizer($uri), "{$value}") !== false) {
                    self::$attack_status = true;
                }
            }

        }


        return self::$attack_status;
    }


}