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


class Anti_XSS extends Central_Utility
{
    public static $attack_status = false;



    public static function xss_detector($uri)
    {

        $xss_pattern = array(
            "%27", // '
            "'",
            "Jw==", // ' in Base64 encode
            "!)P``", // ' in UUencode
            "&#39;", // ' in HTML Decimal with optional semicolons
            "&#x27;", // ' in HTML Hexadecimal with optional semicolons
            '"',
            "%22", // "
            "%3C", // < in URL encode
            "<",
            "%21", // >
            ">",
            "PA==", // <  in Base64
            "&lt;", // <  in HTML encode
            "!/```", // <  in UUencode
            "&#60", // < in HTML (without semicolons):
            "&#60;", // < HTML Decimal with optional semicolons
            "&#x3c;" // < in HTML (with semicolons)
        );

        if ($_SERVER['REQUEST_METHOD'] === "GET") {

            foreach ($xss_pattern as $key => $value) {
                if (strpos(self::url_normalizer($uri), "{$value}") !== false) {
                    self::$attack_status = true;
                }
            }


        } elseif ($_SERVER['REQUEST_METHOD'] === "POST") {

            foreach ($_POST as $item => $value) {
                $postData = self::url_normalizer("{$value}");
                foreach ($xss_pattern as $xss_array_value) {
                    if ($postData == $xss_array_value) {

                        self::$attack_status = true;

                    }
                }
            }
        } else {
            foreach ($xss_pattern as $key => $value) {
                if (strpos(self::url_normalizer($uri), "{$value}") !== false) {
                    self::$attack_status = true;
                }
            }

        }


        return self::$attack_status;
    }


}