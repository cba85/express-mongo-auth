var express = require("express");
var router = express.Router();

var User = require("../models/user");
var passport = require("passport");
var LocalStrategy = require("passport-local").Strategy;

passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});

passport.use(
    "local.signup",
    new LocalStrategy(
        {
            usernameField: "email",
            passwordField: "password"
        },
        function(email, password, done) {
            User.findOne(
                {
                    email: email
                },
                function(err, user) {
                    if (err) {
                        return done(err);
                    }

                    if (user) {
                        return done(null, false, {
                            message: "Email already in use"
                        });
                    }

                    var newUser = new User();

                    newUser.email = email;
                    newUser.password = newUser.hashPassword(password);
                    newUser.save(function(err, user) {
                        if (err) {
                            return done(err);
                        }
                        return done(null, user);
                    });
                }
            );
        }
    )
);

passport.use(
    "local.signin",
    new LocalStrategy(
        {
            usernameField: "email",
            passwordField: "password"
        },
        function(email, password, done) {
            User.findOne(
                {
                    email: email
                },
                function(err, user) {
                    if (err) {
                        return done(err);
                    }

                    if (!user || !user.verifyPassword(password)) {
                        return done(null, false, {
                            message: "User doesn't exist"
                        });
                    }

                    return done(null, user);
                }
            );
        }
    )
);

router.get("/signup", guest, function(req, res, next) {
    res.render("user/signup");
});

/*
router.post('/signup', function(req, res, next) {
    res.send(req.body)
});
*/

router.post(
    "/signup",
    passport.authenticate("local.signup", {
        successRedirect: "/user/profile",
        failureRedirect: "/user/signup"
    })
);

router.get("/signin", guest, function(req, res, next) {
    res.render("user/signin");
});

router.post(
    "/signin",
    passport.authenticate("local.signin", {
        successRedirect: "/user/profile",
        failureRedirect: "/user/signin"
    })
);

router.get("/profile", signed, function(req, res, next) {
    res.render("user/profile");
});

router.get("/signout", signed, function(req, res) {
    req.logout()
    res.redirect('/')
});

function signed(req, res, next)
{
    if (!req.isAuthenticated()) {
        res.redirect('/')
    }

    next()
}

function guest(req, res, next)
{
    if (req.isAuthenticated()) {
        res.redirect('/')
    }

    next()
}

module.exports = router;
