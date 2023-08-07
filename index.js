const express = require('express');
const validate = require('express-validation');
const Joi = require('joi');
const bodyParser = require('body-parser');
const _ = require('lodash');
const vm = require('vm');

function createApp() {
  const app = express();

  app.use(bodyParser.json({ limit: '1mb' }));

  const postOrderSchema = {
    body: Joi.object({
      email: Joi.string().email().required(),
      currency: Joi.string().valid('EUR', 'USD').required(),
    }),
  };
  app.post('/api/orders', validate(postOrderSchema), (req, res, next) => {
    // 将用户的请求IP加到order中，_.merge有原型链污染漏洞
    const clientOrder = _.merge({}, req.body, { ipAddress: req.ip });

    const newObj = {};
    // Object.prototype.admin被污染, newObj.admin返回true造成权限提升
    console.log('newObj.admin', newObj.admin);

    res.json({
      status: 'ok',
    });
  });


  const getOrderSchema = {
    params: {
      orderId: Joi.string().regex(/^[0-9]{4}$/).required(),
    },
  };
  app.get('/api/orders/:orderId', validate(getOrderSchema), (req, res, next) => {
    const newObj = {};
    console.log('newObj.admin:', newObj.admin);

    // 这种情况下newObj2.admin将会返回false，因为自身有admin属性，不会往原型链上查找
    const newObj2 = { admin: false };
    console.log('newObj2.admin:', newObj2.admin);

    res.json({
      status: 'ok',
    });
  });


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

  return app;
}

function main() {
  const app = createApp();
  app.listen(9999, () => {
    console.log('Express server listening on http://localhost:9999/')
  });
}

if (require.main === module) {
  main();
}
