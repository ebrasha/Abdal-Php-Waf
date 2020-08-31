<?php
/**
 * Created by Abdal Security Group.
 * Programmer: Ebrahim Shafiei
 * Programmer WebSite: https://hackers.zone/
 * Programmer Email: Prof.Shafiei@Gmail.com
 * License : AGCL
 * Current Date : 2020-08-31
 * Current Time : 3:50 AM
 */


namespace ABDALPHPWAF;
require_once 'class-central-utility.php';

class Dos_Protector extends Central_Utility
{

    public function __construct()
    {
        if (session_id() == ''){
            ob_start();
            session_start();
        }

    }


    public static function dos_detection() {


        if ( @$_SESSION['last_request'] > time() - 0.5 ) {

            return true;
        }

        @$_SESSION['last_request'] = time();


    }


}