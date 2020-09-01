<?php namespace ANTI_rfi_CORE;
/**
 * Created by Abdal Security Group.
 * Programmer: Ebrahim Shafiei
 * Programmer WebSite: https://hackers.zone/
 * Programmer Email: Prof.Shafiei@Gmail.com
 * License : AGCL
 */

namespace ABDALPHPWAF;
require_once 'class-central-utility.php';


class Anti_RFI extends Central_Utility
{
    public static $attack_status = false;



    public static function rfi_detector($uri)
    {

        $rfi_pattern = array(
            "/https?:\/\//",
            "/http?:\/\//",
            "/ftp?:\/\//",
            "/([a-z0-9\-\.]*)\.(([a-z]{2,4})|([0-9]{1,3}\.([0-9]{1,3})\.([0-9]{1,3})))/",
        );

        $regex_first_stage = "/(http|https|ftp):/"; // SCHEME
        $regex_second_stage = "/([a-z0-9\-\.]*)\.(([a-z]{2,4})|([0-9]{1,3}\.([0-9]{1,3})\.([0-9]{1,3})))/"; // Host or IP


        if ($_SERVER['REQUEST_METHOD'] === "GET") {

            foreach ($rfi_pattern as $key => $value) {
                if (preg_match($value,self::url_normalizer($uri))) {
                    self::$attack_status = true;
                }
            }


        } elseif ($_SERVER['REQUEST_METHOD'] === "POST") {

            foreach ($_POST as $item => $value) {
                foreach ($rfi_pattern as $rfi_array_value) {
                    if (preg_match($value,self::url_normalizer($uri))) {

                        self::$attack_status = true;

                    }
                }
            }
        } else {
            foreach ($rfi_pattern as $key => $value) {
                if (strpos(self::url_normalizer($uri), "{$value}") !== false) {
                    self::$attack_status = true;
                }
            }

        }


        return self::$attack_status;
    }


}