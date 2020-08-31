<?php
/**
 * Created by Abdal Security Group.
 * Programmer: Ebrahim Shafiei
 * Programmer WebSite: https://hackers.zone/
 * Programmer Email: Prof.Shafiei@Gmail.com
 * License : AGCL
 * Current Date : 2020-08-31
 * Current Time : 4:27 AM
 */


namespace ABDALPHPWAF;


class Central_Utility
{

    public static function url_normalizer($url)
    {
//        $nURL = mb_convert_encoding($url, 'ASCII');
        $nURL = rawurldecode($url);
        $nURLLower = strtolower($nURL);

        return $nURLLower;
    }



}