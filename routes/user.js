var express = require('express');
var router = express.Router();

var User = require('../models/user')
var passport = require('passport')
var LocalStrategy = require('passport-local').Strategy

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

passport.use('local.signup', new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password'
}, function (email, password, done) {

    User.findOne({
        'email': email
    }, function (err, user) {

        if (err) { return done(err) }

        if (user) {
            return done(null, false, { message: 'Email already in use' })
        }

        var newUser = new User();

        newUser.email = email;
        newUser.password = password;
        newUser.save(function (err, user) {
            if (err) { return done(err) }
            return done(null, user);
        })
    })
}))

router.get('/signup', function(req, res, next) {
  res.render('user/signup')
});

/*
router.post('/signup', function(req, res, next) {
    res.send(req.body)
});
*/

router.post('/signup', passport.authenticate('local.signup', {
    successRedirect: '/user/profile',
    failureRedirect: "/user/signup"
}));

router.get('/profile', function(req, res, next) {
  res.send(req.user)
});

module.exports = router;
