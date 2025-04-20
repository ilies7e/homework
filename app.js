require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const path = require('path');

const app = express();


app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');


app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(session({
    secret: process.env.SESSION_SECRET || 'secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { 
        secure: false,
        httpOnly: true
    }
}));


app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    next();
});


const users = {
    'administrator': {
        password: 'admin',
        role: 'ADMIN',
        email: 'admin@example.com'
    },
    'wiener': {
        password: 'peter',
        role: 'NORMAL',
        email: 'peter@example.com'
    },
    'carlos': {
        password: 'montoya',
        role: 'NORMAL',
        email: 'carlos@example.com'
    }
};


const requireAuth = (req, res, next) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    next();
};


const requireAdmin = (req, res, next) => {
    if (req.session.user?.role !== 'ADMIN') {
        return res.status(401).json("Unauthorized");
    }
    next();
};


app.get('/', (req, res) => {
    res.render('home');
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users[username];
    
    if (user && user.password === password) {
        req.session.user = {
            username,
            role: user.role,
            email: user.email
        };
        return res.redirect('/my-account');
    }
    
    res.render('login', { error: 'Invalid credentials' });
});

app.get('/my-account', requireAuth, (req, res) => {
    res.render('my-account', { user: req.session.user });
});

app.get('/admin', requireAuth, requireAdmin, (req, res) => {
    res.render('admin', { 
        users: Object.entries(users).map(([username, data]) => ({
            username,
            role: data.role
        }))
    });
});


app.post('/admin-roles', requireAuth, (req, res) => {
    
    if ((req.body.action === 'upgrade' || req.body.action === 'downgrade') && 
        req.body.username && !req.body.confirmed) {
        
        if (req.session.user?.role !== 'ADMIN') {
            return res.status(401).json("Unauthorized");
        }
        
        req.session.pendingRoleChange = {
            username: req.body.username,
            action: req.body.action
        };
        
        return res.render('confirm-role-change', {
            username: req.body.username,
            action: req.body.action
        });
    }
    
    
    if ((req.body.action === 'upgrade' || req.body.action === 'downgrade') && 
        req.body.confirmed === 'true' && req.body.username) {
        
        const username = req.body.username;
        
        if (!users[username]) {
            return res.status(400).send('Bad Request');
        }
        
       
        if (req.body.action === 'upgrade') {
            users[username].role = 'ADMIN';
        } else if (req.body.action === 'downgrade') {
            users[username].role = 'NORMAL';
        } else {
            return res.status(400).send('Bad Request');
        }
        
        
        if (username === req.session.user?.username) {
            req.session.user.role = users[username].role;
        }
        
        return res.redirect(302, '/admin');
    }
    
    res.status(400).send('Bad Request');
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
