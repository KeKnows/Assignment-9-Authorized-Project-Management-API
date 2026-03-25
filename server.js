const express = require('express');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const { User } = require('./database/setup'); 

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());


function requireAuth(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Authentication required' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }
}


function requireManager(req, res, next) {
    if (!['manager', 'admin'].includes(req.user.role)) {
        return res.status(403).json({ error: 'Manager access required' });
    }
    next();
}

function requireAdmin(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
}


app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ where: { email } });

        if (!user || user.password !== password) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role
            },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN }
        );

        res.json({
            message: 'Login successful',
            token,
            user
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


app.post('/api/register', async (req, res) => {
    const { name, email, password, role } = req.body;

    try {
        const user = await User.create({
            name,
            email,
            password,
            role
        });

        const token = jwt.sign(
            {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role
            },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN }
        );

        res.status(201).json({ token, user });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


app.get('/api/my-projects', requireAuth, (req, res) => {
    res.json({
        message: `Projects for user ${req.user.id}`
    });
});


app.post('/api/projects', requireAuth, requireManager, (req, res) => {
    res.json({ message: 'Project created' });
});

app.put('/api/projects/:id', requireAuth, requireManager, (req, res) => {
    res.json({ message: 'Project updated' });
});

app.post('/api/projects/:id/tasks', requireAuth, requireManager, (req, res) => {
    res.json({ message: 'Task created' });
});

app.delete('/api/tasks/:id', requireAuth, requireManager, (req, res) => {
    res.json({ message: 'Task deleted' });
});


app.get('/api/users', requireAuth, requireAdmin, async (req, res) => {
    const users = await User.findAll();
    res.json(users);
});

app.delete('/api/projects/:id', requireAuth, requireAdmin, (req, res) => {
    res.json({ message: 'Project deleted' });
});


app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
