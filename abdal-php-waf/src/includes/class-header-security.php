<?php
/**
 * Created by Abdal Security Group.
 * Programmer: Ebrahim Shafiei
 * Programmer WebSite: https://hackers.zone/
 * Programmer Email: Prof.Shafiei@Gmail.com
 * License : AGCL
 * Current Date : 2020-09-05
 * Current Time : 3:50 AM
 */


namespace ABDALPHPWAF;
require_once 'class-central-utility.php';

class Header_Security extends Central_Utility
{


    /*
  |------------------------------------------------------------------------------
  | X-Powered-By Attack
  |------------------------------------------------------------------------------
  |
  | Hackers can exploit known vulnerabilities in Express and Node if they know
  | you’re using it. Express (and other web technologies like PHP) set an X-Powered-By
  | header with every request, indicating what technology powers the server.
  | PHP , for example, sets this, which is a dead giveaway that your server is
  | powered by PHP.
  |
  */

    public static function secure_x_powered_by()
    {

        header_remove("X-Powered-By");
    }

    /*
  |--------------------------------------------------------------------------
  | DNS Prefetch Control
  |--------------------------------------------------------------------------
  |
  | The X-DNS-Prefetch-Control HTTP response header controls DNS prefetching,
  | a feature by which browsers proactively perform domain name resolution on
  | both links that the user may choose to follow as well as URLs for items
  | referenced by the document, including images, CSS, JavaScript, and so forth.
  |
  */


    public static function secure_x_dns_prefetch_control()
    {

        header("X-DNS-Prefetch-Control: off");

    }


    /*
 |--------------------------------------------------------------------------
 | XSS Attack
 |--------------------------------------------------------------------------
 |
 | Cross site scripting (XSS) is a common attack vector that injects malicious
 | code into a vulnerable web application. XSS differs from other web attack
 | vectors (e.g., SQL injections), in that it does not directly target the
 | application itself. Instead, the users of the web application are the ones
 | at risk.
 | Depending on the severity of the attack, user accounts may be compromised,
 | Trojan horse programs activated and page content modified, misleading users
 | into willingly surrendering their private data. Finally, session cookies
 | could be revealed, enabling a perpetrator to impersonate valid users and
 | abuse their private accounts.
 |
 */


    public static function secure_x_xss_protection()
    {

        header("X-XSS-Protection: 1; mode=block");

    }


    /*
|--------------------------------------------------------------------------
| Mime Sniffing Attack
|--------------------------------------------------------------------------
|
| MIME sniffing was, and still is, a technique used by some web browsers
| (primarily Internet Explorer) to examine the content of a particular asset.
| This is done for the purpose of determining an asset’s file format.
| This technique is useful in the event that there is not enough metadata
| information present for a particular asset, thus leaving the possibility that
| the browser interprets the asset incorrectly.
| Although MIME sniffing can be useful to determine an asset’s correct file format,
| it can also cause a security vulnerability. This vulnerability can be quite dangerous
| both for site owners as well as site visitors. This is because an attacker can leverage
| MIME sniffing to send an XSS (Cross Site Scripting) attack. This article will explain
| how to protect your site against MIME sniffing vulnerabilities.
|
*/


    public static function secure_x_content_type_options()
    {

        header("X-Content-Type-Options: nosniff");

    }


    /*
   |--------------------------------------------------------------------------
   | Strict-Transport-Security
   |--------------------------------------------------------------------------
   |
   | The HTTP Strict-Transport-Security response header (often abbreviated as
   | HSTS) lets a web site tell browsers that it should only be accessed using
   | HTTPS, instead of using HTTP.
   |
   */

    public static function secure_strict_transport_security()
    {

        header("Strict-Transport-Security: max-age=5184000;");

    }


    /*
       |--------------------------------------------------------------------------
       | Click Jacking Attack
       |--------------------------------------------------------------------------
       |https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
       | Clickjacking, also known as a "UI redress attack", is when an attacker
       | uses multiple transparent or opaque layers to trick a user into clicking
       | on a button or link on another page when they were intending to click on
       | the the top level page. Thus, the attacker is "hijacking" clicks meant for
       | their page and routing them to another page, most likely owned by another
       | application, domain, or both.
       |
       */


    public static function secure_x_frame_options_set_deny()
    {

        header("X-Frame-Options: DENY");

    }


    public static function secure_x_frame_options_set_sameorigin()
    {

        header("X-Frame-Options: SAMEORIGIN");

    }


    /*
  |__________________________________________________________________________
  | X_Permitted_Cross_Domain_Policies
  |__________________________________________________________________________
  | If you don’t want them to load data from your domain, set the header’s value to none
  | Adobe Flash and Adobe Acrobat can load content from your domain even from
  | other sites (in other words, cross_domain). This could cause unexpected data
  | disclosure in rare cases or extra bandwidth usage.
  |
  */

    public static function secure_x_permitted_cross_domain_policies()
    {

        header("X-Permitted-Cross-Domain-Policies: none");

    }


    /*
|------------------------------------------------------------------------------
| Cache Control Attack
|------------------------------------------------------------------------------
|
| Cache-control is an HTTP header that dictates browser caching behavior.
| In a nutshell, when someone visits a website, their browser will save certain
| resources, such as images and website data, in a store called the cache.
| When that user revisits the same website, cache-control sets the rules which
| determine whether that user will have those resources loaded from their local
| cache, or whether the browser will have to send a request to the server for
| fresh resources. In order to understand cache-control in greater depth,
| a basic understanding of browser caching and HTTP headers is required.
|
*/

    public static function secure_cache_control()
    {

        header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0, s-maxage=0");

    }


    /*
  |--------------------------------------------------------------------------
  | Cross-Origin Resource Sharing (CORS)
  |--------------------------------------------------------------------------
  |
  | Cross-Origin Resource Sharing (CORS) is a mechanism that uses additional
  | HTTP headers to tell a browser to let a web application running at one origin
  | (domain) have permission to access selected resources from a server at a
  | different origin. A web application executes a cross-origin HTTP request
  | when it requests a resource that has a different origin (domain, protocol,
  | and port) than its own origin.An example of a cross-origin request: The
  | frontend JavaScript code for a web application served from http://domain-a.com
  | uses XMLHttpRequest to make a request for http://api.domain-b.com/data.json.
  |
  */

    public static function secure_cross_origin_resource_sharing()
    {

        header("Access-Control-Allow-Origin: *");
        header("Access-Control-Allow-Headers: *");


    }


}