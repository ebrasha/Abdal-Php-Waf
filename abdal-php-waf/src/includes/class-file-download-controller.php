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


class File_Download_Controller extends Central_Utility
{
    public static $attack_status = false;


    /**
     * @param $get_parameter => like $_GET['file']
     * @param $white_list_extension => must be array - example = $white_list_extension = array("rar","7z","zip","apk","exe","mp3","wav","mp4","pdf","docx");
     */
    public static function extension_controller($get_parameter, $white_list_extension)
    {


        if (isset($get_parameter) AND $get_parameter != "" ){
            $FileName = $get_parameter;
            $ext = pathinfo($FileName, PATHINFO_EXTENSION);
            $ext = strtolower($ext);
            if (!in_array($ext,$white_list_extension) ){
                self::$attack_status = true;
            }

        }else{
            self::$attack_status = true;

        }

    }


}