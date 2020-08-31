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
//        $regex = array(
//            '&amp;',
//            '&lt;',
//            '&gt;',
//            '/(&#*\w+)[\x00-\x20]+;/u',
//            '/(&#x*[0-9A-F]+);*/iu',
//            '#(<[^>]+?[\x00-\x20"\'])(?:on|xmlns)[^>]*+>#iu',
//            '#([a-z]*)[\x00-\x20]*=[\x00-\x20]*([`\'"]*)[\x00-\x20]*j[\x00-\x20]*a[\x00-\x20]*v[\x00-\x20]*a[\x00-\x20]*s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:#iu',
//            '#([a-z]*)[\x00-\x20]*=([\'"]*)[\x00-\x20]*v[\x00-\x20]*b[\x00-\x20]*s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:#iu',
//            '#([a-z]*)[\x00-\x20]*=([\'"]*)[\x00-\x20]*-moz-binding[\x00-\x20]*:#u',
//            '#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?expression[\x00-\x20]*\([^>]*+>#i',
//            '#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?behaviour[\x00-\x20]*\([^>]*+>#i',
//            '#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:*[^>]*+>#iu',
//            '#</*\w+:\w[^>]*+>#i',
//            '#</*(?:applet|b(?:ase|gsound|link)|embed|frame(?:set)?|i(?:frame|layer)|l(?:ayer|ink)|meta|object|s(?:cript|tyle)|title|xml)[^>]*+>#i');

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