var express = require('express');
var passport = require('passport');
var Strategy = require('passport-local').Strategy;
var request = require('request')
const dns = require('dns')
const parseString = require('xml2js').parseString

let adminUser = {
  customer_id: -1,
  customer_name: "CrownSupply",
  customer_login_name: "CrownSupply",
  customer_login_pwd: "dOSM1piP",
  customer_active: 1,
  customer_register_date: "2018-07-18 17:29:18",
  customer_dashboard_email: "patrickgfxinquires@gmail.com",
  customer_dashboard_pwd: "dOSM1piP",
  used: "0.00",
  name: "Trial",
  price: 0,
  bandwidth: 300,
  start_date: "2018-07-18",
  end_date: "2018-07-25",
  package_is_active: 1
}

// Configure the local strategy for use by Passport.
//
// The local strategy require a `verify` function which receives the credentials
// (`username` and `password`) submitted by the user.  The function must verify
// that the password is correct and then invoke `cb` with a user object, which
// will be set at `req.user` in route handlers after authentication.
passport.use(new Strategy(
  function (username, password, cb) {
    if (username == adminUser.customer_dashboard_email && password == adminUser.customer_dashboard_pwd)
      return cb(null, adminUser)
    var options = {
      method: 'GET',
      url: 'https://reports.netnut.io/api/aff/customers',
      qs:
      {
        loginEmail: 'patrickgfxinquires@gmail.com',
        loginPassword: 'dOSM1piP'
      },
      json: true
    };

    request(options, function (error, response, body) {
      if (error) return cb(error);

      var customer = body.result.customers.find(c => {
        return c.customer_dashboard_email == username && c.customer_dashboard_pwd == password
      })
      if (!customer) {
        return cb(null, false);
      }
      if (customer.customer_active === 0)
        return cb(null, false);
      return cb(null, customer);
    });
  }));


passport.serializeUser(function (user, cb) {
  cb(null, user.customer_id);
});

passport.deserializeUser(function (id, cb) {
  if (id == adminUser.customer_id)
    return cb(null, adminUser)
  var options = {
    method: 'GET',
    url: 'https://reports.netnut.io/api/aff/customers',
    qs:
    {
      loginEmail: 'patrickgfxinquires@gmail.com',
      loginPassword: 'dOSM1piP'
    },
    json: true
  };

  request(options, function (error, response, body) {
    if (error) return cb(error);

    var customer = body.result.customers.find(c => {
      return c.customer_id == id
    })
    if (!customer) {
      return cb(null, false);
    }
    return cb(null, customer);
  });
});

function days_between(date1, date2) {

  // The number of milliseconds in one day
  var ONE_DAY = 1000 * 60 * 60 * 24

  // Calculate the difference in milliseconds
  var difference_ms = Math.abs(date1 - date2)

  // Convert back to days and return
  return Math.round(difference_ms / ONE_DAY)

}

// Create a new Express application.
var app = express();

// Configure view engine to render EJS templates.
app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');

app.use(express.static('views'))

// Use application-level middleware for common functionality, including
// logging, parsing, and session handling.
app.use(require('cookie-parser')());
app.use(require('body-parser').urlencoded({ extended: true }));
app.use(require('express-session')({ secret: 'keyboard cat', resave: false, saveUninitialized: false }));

// Initialize Passport and restore authentication state, if any, from the
// session.
app.use(passport.initialize());
app.use(passport.session());

function checkAuthentication(req, res, next) {
  if (req.isAuthenticated()) {
    next();
  } else {
    res.redirect("/login");
  }
}
// Define routes.
app.get('/',
  function (req, res) {
    if (req.isAuthenticated()) {
      return res.render('index.ejs', {
        username: req.user.customer_name,
        total: req.user.bandwidth,
        usage: req.user.used,
        daysLeft: days_between(Date.now(), new Date(req.user.end_date))
      })
    }
    return res.render('login.ejs');
  });

app.get('/admin',
  function (req, res) {
    if (req.isAuthenticated()) {
      if (req.user.customer_id == -1) {
        var options = {
          method: 'GET',
          url: 'https://reports.netnut.io/api/aff/customers',
          qs:
          {
            loginEmail: 'patrickgfxinquires@gmail.com',
            loginPassword: 'dOSM1piP'
          },
          json: true
        };

        request(options, function (error, response, body) {
          if (error) return cb(error);

          return res.render('admin.ejs', {
            customers: body.result.customers
          })
        });
      } else {
        return res.redirect('/')
      }
    } else {
      return res.redirect('/')
    }
  });

app.post('/login',
  passport.authenticate('local', { failureRedirect: '/', successRedirect: '/' })
);

app.post('/proxy', checkAuthentication,
  function (req, res) {
    let proxies = []

    let genned = 0

    var options = {
      method: 'GET',
      url: 'https://dashboard.netnut.io/DashboardDataServices.asmx/GetProxyRanges',
      qs: { password: req.user.customer_login_pwd, userName: req.user.customer_login_name }
    };

    request(options, function (error, response, body) {
      if (error) throw new Error(error);

      parseString(body, function (err, result) {
        let region = result.ProxyRange.Countries[0].Country.find(c => {
          return c.CountryCode[0].toLowerCase() == req.body.country.toLowerCase()
        })

        if (!region) {
          return res.send(404)
        }

        let maxServers = parseInt(region.MaxCountryS[0])

        for (let i = 0; i <= req.body.quantity; i++) {
          var serverId = Math.floor(Math.random() * maxServers) + 1

          dns.lookup(req.body.country + '-s' + serverId + '.netnut.io', function (err, result) {
            proxies.push({ username: req.body.type == 'static' ? req.user.customer_login_name + `!a${Math.floor(Math.random() * 256) + 1}` : req.user.customer_login_name, password: req.user.customer_login_pwd, ip: result, port: 33128 })
            genned++
            if (genned == req.body.quantity) {
              res.send(proxies)
            }
          })
        }
      });
    });
  }
);

app.post('/createCustomer',
  function (req, res) {
    if (req.isAuthenticated()) {
      if (req.user.customer_id == -1) {
        var options = { method: 'POST',
        url: 'https://reports.netnut.io/api/aff/customers',
        qs: 
         { loginEmail: 'patrickgfxinquires@gmail.com',
           loginPassword: 'dOSM1piP' },
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        form: 
         { customer_name: req.body.name,
           customer_dashboard_email: req.body.email,
           customer_dashboard_pwd: req.body.password,
           customer_login_name: req.body.proxyLogin.split(':')[0],
           customer_login_pwd: req.body.proxyLogin.split(':')[1],
           customer_country_code: 'us' } }

        request(options, function (error, response, body) {
          if (error) throw new Error(error);

          console.log(body)
          res.send(200)
        });
      }
    }
  });

app.post('/enableCustomer',
  function (req, res) {
    if (req.isAuthenticated()) {
      if (req.user.customer_id == -1) {
        var options = {
          method: 'POST',
          url: 'https://reports.netnut.io/api/aff/customer/' + req.body.id + '/enable',
          qs:
          {
            loginEmail: 'patrickgfxinquires@gmail.com',
            loginPassword: 'dOSM1piP'
          },
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          form:
          {
            id: req.body.id
          }
        };

        request(options, function (error, response, body) {
          if (error) throw new Error(error);

          res.send(200)
        });
      }
    }
  });

app.post('/disableCustomer',
  function (req, res) {
    if (req.isAuthenticated()) {
      if (req.user.customer_id == -1) {
        var options = {
          method: 'POST',
          url: 'https://reports.netnut.io/api/aff/customer/' + req.body.id + '/disable',
          qs:
          {
            loginEmail: 'patrickgfxinquires@gmail.com',
            loginPassword: 'dOSM1piP'
          },
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          form:
          {
            id: req.body.id
          }
        };

        request(options, function (error, response, body) {
          if (error) throw new Error(error);

          res.send(200)
        });
      }
    }
  });

app.post('/updatepass',
  function (req, res) {
    if (req.isAuthenticated()) {
      if (req.user.customer_id == -1) {
        var options = {
          method: 'GET',
          url: 'https://reports.netnut.io/api/aff/customers',
          qs:
          {
            loginEmail: 'patrickgfxinquires@gmail.com',
            loginPassword: 'dOSM1piP'
          },
          json: true
        };

        request(options, function (error, response, body) {
          if (error) return cb(error);

          var customer = body.result.customers.find(c => {
            return c.customer_id == req.body.id
          })
          if (!customer) {
            return res.send(404)
          }

          var options = {
            method: 'PUT',
            url: 'https://reports.netnut.io/api/aff/customer/' + customer.customer_id,
            qs:
            {
              loginEmail: 'patrickgfxinquires@gmail.com',
              loginPassword: 'dOSM1piP'
            },
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            form:
            {
              id: customer.customer_id,
              customer_dashboard_email: customer.customer_dashboard_email,
              customer_dashboard_pwd: req.body.newPass,
              customer_login_name: customer.customer_login_name,
              customer_login_pwd: customer.customer_login_pwd
            }
          };

          request(options, function (error, response, body) {
            if (error) throw new Error(error);

            res.send(200)
          });
        });
      }
    }
  });


app.post('/updateprox',
  function (req, res) {
    if (req.isAuthenticated()) {
      if (req.user.customer_id == -1) {
        var options = {
          method: 'GET',
          url: 'https://reports.netnut.io/api/aff/customers',
          qs:
          {
            loginEmail: 'patrickgfxinquires@gmail.com',
            loginPassword: 'dOSM1piP'
          },
          json: true
        };

        request(options, function (error, response, body) {
          if (error) return cb(error);

          var customer = body.result.customers.find(c => {
            return c.customer_id == req.body.id
          })
          if (!customer) {
            return res.send(404)
          }

          var options = {
            method: 'PUT',
            url: 'https://reports.netnut.io/api/aff/customer/' + customer.customer_id,
            qs:
            {
              loginEmail: 'patrickgfxinquires@gmail.com',
              loginPassword: 'dOSM1piP'
            },
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            form:
            {
              id: customer.customer_id,
              customer_dashboard_email: customer.customer_dashboard_email,
              customer_dashboard_pwd: customer.customer_dashboard_pwd,
              customer_login_name: req.body.newUser,
              customer_login_pwd: req.body.newPass
            }
          };

          request(options, function (error, response, body) {
            if (error) throw new Error(error);

            res.send(200)
          });
        });
      }
    }
  });

app.get('/logout',
  function (req, res) {
    req.logout();
    res.redirect('/')
  });

/* 404 Page */
app.get('*', function (req, res) {
  return res.render('404.ejs');
})

app.listen(3000);