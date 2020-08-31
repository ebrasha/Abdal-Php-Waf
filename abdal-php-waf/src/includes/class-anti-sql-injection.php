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


class Anti_SQL_Injection extends Central_Utility
{
    public static $attack_status = false;


    /**
     * @param $uri
     * @return bool
     */
    public static function sql_injection_detector($uri)
    {


        $xss_pattern = array(
            "tz_offset",
            "&apos;%20OR",
            " as ",
            " or ",
            " distinct ",
            " like ",
            "x27UNION",
            "\..\..",
            "../../",
            "union",
            "**/",
            "/**",
            "0x3a",
            "null",
            "DR/**/OP/",
            " drop",
            "')",
            "%20drop",
            "/*",
            "*/",
            "*",
            "--",
            ";",
            "||",
            "' #",
            "or 1=1",
            "'1'='1",
            "BUN",
            "S@BUN",
            " char ",
            "OR%",
            "`",
            "[",
            "]",
            "++",
            "script",
            "1,1",
            "ascii",
            "insert",
            "between",
            "values",
            "truncate",
            "benchmark",
            "%27",
            "%22",
            "(",
            ")",
            "<?",
            "<?php",
            "?>",
            "127.0.0.1",
            "loopback",
            "../",
            "%0A",
            "%0D",
            "%3C",
            "%3E",
            "%00",
            "%2e%2e",
            "input_file",
            "path=.",
            "mod=.",
            "eval\(",
            "javascript:",
            "base64_",
            "boot.ini",
            "etc/passwd",
            "self/environ",
            "echo.*kae",
            "=%27$"
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