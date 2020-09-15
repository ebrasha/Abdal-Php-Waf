# Abdal Php Waf

A Powerful Waf To Protect The Php Applications

 

## Install With Composer
Use the package manager



```bash
composer require  abdal-security-agency/abdal-php-waf
```

## Usage

Here's a basic usage example: `Use in your main project file`


```php
//Call Abdal PHP WAF
require_once __DIR__ . '/example_address/vendor/autoload.php';
```
import Abdal PHP WAF to main file of your project

#### Filter Request By Define Request Method

```php
if (\ABDALPHPWAF\Request_Method_Protector::request_methods_only_allow('POST') == 'allow'){
    echo "this HTTP request method is allowed";
}else{
     echo "this HTTP request method is unauthorized";
}
```
Supported http method : `GET,HEAD,POST,PUT,DELETE,OPTIONS,TRACE,PATCH`

#### Detect XSS Attack

```php
if (\ABDALPHPWAF\Anti_XSS::xss_detector($_SERVER['REQUEST_URI'])){
    echo "XSS Attack Detected";
}
```

#### Detect SQL Injection Attack

```php
if (\ABDALPHPWAF\Anti_SQL_Injection::sql_injection_detector($_SERVER['REQUEST_URI'])){
    echo "SQL Injection Attack Detected";
}
```

#### Detect DOS Attack (limit 0.5 ms for every request)

```php
if (\ABDALPHPWAF\Dos_Protector::dos_detection()){
    echo "DOS Attack Detected";
}
```



#### Detect CRLF Attack 

```php
if (\ABDALPHPWAF\Anti_CRLF::crlf_detector($_SERVER['REQUEST_URI'])){
    echo "CRLF Attack Detected";
}
```

#### Detect RFI Attack 

```php
if (\ABDALPHPWAF\Anti_RFI::rfi_detector($_SERVER['REQUEST_URI'])){
    echo "RFI Attack Detected";
}
```





#### File Download Controller (Prevent access to sensitive files)

```php
$get_parameter = $_GET['file'];
$white_list_extension = array("rar","7z","zip","apk","exe","mp3","wav","mp4","pdf","docx");

if (\ABDALPHPWAF\File_Download_Controller::extension_controller($get_parameter,$white_list_extension)){
    echo "Access Denied";
}

```

#### Detect Proxy

```php
if (\ABDALPHPWAF\PROXY_PROTECTION::proxy_detector()){
    echo "Proxy Access Denied";
}
```

#### remove X-Powered-By from Response

```php
\ABDALPHPWAF\Header_Security::secure_x_powered_by();
```

#### Secure DNS Prefetch Control

```php
\ABDALPHPWAF\Header_Security::secure_x_dns_prefetch_control();
```

#### Block pages from loading when they detect reflected XSS attacks

```php
\ABDALPHPWAF\Header_Security::secure_x_xss_protection();
```


#### Block Mime Sniffing Attack

```php
\ABDALPHPWAF\Header_Security::secure_x_content_type_options();
```

#### Set Strict-Transport-Security

```php
\ABDALPHPWAF\Header_Security::secure_strict_transport_security();
```


#### Anti Click Jacking Attack

```php
\ABDALPHPWAF\Header_Security::secure_x_frame_options_set_deny();
# OR
\ABDALPHPWAF\Header_Security::secure_x_frame_options_set_sameorigin();

```


#### X-Permitted-Cross-Domain-Policies
If you don’t want them to load data from your domain

```php
\ABDALPHPWAF\Header_Security::secure_x_permitted_cross_domain_policies();
```


#### Cache Control Attack

```php
\ABDALPHPWAF\Header_Security::secure_cache_control();
```



#### Cross-Origin Resource Sharing (CORS)

```php
\ABDALPHPWAF\Header_Security::secure_cross_origin_resource_sharing();
```







### About Programmer
Ebrahim Shafiei from Iran (Ready to cooperate with international projects)
  - Email : Prof.Shafiei@Gmail.com
  - WebSite https://hackers.zone/


## License
Abdal Php Waf is open-source software licensed under the [MIT license.](https://choosealicense.com/licenses/mit/)
