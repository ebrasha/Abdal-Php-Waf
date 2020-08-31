<?php
/**
 * Created by Abdal Security Group.
 * Programmer: Ebrahim Shafiei
 * Programmer WebSite: https://hackers.zone/
 * Programmer Email: Prof.Shafiei@Gmail.com
 * License : AGCL
 * Current Date : 2020-08-30
 * Current Time : 11:15 PM
 */


namespace ABDALPHPWAF;
require_once 'class-central-utility.php';


class Request_Method_Protector extends Central_Utility
{

    /**
     * @param $method = any method like GET,HEAD,POST,PUT,DELETE,OPTIONS,TRACE,PATCH
     * @return string = allow (Means request is accepted) and block (Means request is denied)
     */
    public static function request_methods_only_allow($method)
    {

//        $request_methods = array(
//            "GET",
//            "HEAD",
//            "POST",
//            "PUT",
//            "DELETE",
//            "OPTIONS",
//            "TRACE",
//            "PATCH"
//        );

        if (is_array($method)) {
            if (in_array($method, $_SERVER['REQUEST_METHOD'])) {
                return "allow";
            } else {
                return "block";
            }
        } else {

            if ($_SERVER['REQUEST_METHOD'] === $method) {
                return "allow";
            } else {
                return "block";
            }

        }
    }

}