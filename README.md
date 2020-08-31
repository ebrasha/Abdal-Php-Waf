# Abdal Php Waf

A Powerful Waf To Protect The Php Applications


#### Install With Composer
Use the package manager


```bash
composer require  abdal-security-agency/abdal-php-waf
```

#### Usage

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



#### File Download Controller (Prevent access to sensitive files)

```php
$get_parameter = $_GET['file'];
$white_list_extension = array("rar","7z","zip","apk","exe","mp3","wav","mp4","pdf","docx");

if (\ABDALPHPWAF\File_Download_Controller::extension_controller($get_parameter,$white_list_extension)){
    echo "Access Denied";
}

```





### About Programmer
Ebrahim Shafiei 
  - Email : Prof.Shafiei@Gmail.com
  - WebSite https://hackers.zone/
  - +98 09022223301


## License
[MIT](https://choosealicense.com/licenses/mit/)
