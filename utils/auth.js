function isLoggedIn(req, res, next) {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    next(); // user is logged in → move ahead
}

module.exports = isLoggedIn;
