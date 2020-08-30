# Abdal Php Waf

A Powerful Waf To Protect The Php Applications


#### Install With Composer
Use the package manager


```bash
composer require  abdal-security-agency/abdal-php-waf
```

#### Usage

Here's a basic usage example: 


```php
//Call Abdal PHP WAF
require_once __DIR__ . '/example_address/vendor/autoload.php';
```
import Abdal PHP WAF to main file of your project

#### Filter Request By Define Request Method

```php
if (\ABDALPHPWAF\REQMETHOD::request_methods_only_allow('POST') == 'allow'){
    echo "this HTTP request method is allowed";
}else{
     echo "this HTTP request method is unauthorized";
}
```
Support http method : GET,HEAD,POST,PUT,DELETE,OPTIONS,TRACE,PATCH


### About Programmer
Ebrahim Shafiei   - [WebSite](https://hackers.zone/)


## License
[MIT](https://choosealicense.com/licenses/mit/)
