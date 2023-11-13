const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const db = new sqlite3.Database(':memory:'); // Используем память для хранения базы данных для примера

app.use(express.json());

const JWT_SECRET = 'your_jwt_secret'; // В реальном приложении используйте безопасный ключ

// Инициализация базы данных
db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT, role TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS goals (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT, description TEXT, FOREIGN KEY (user_id) REFERENCES users(id))");
    db.run("CREATE TABLE IF NOT EXISTS goal_comments (id INTEGER PRIMARY KEY AUTOINCREMENT, goal_id INTEGER, user_id INTEGER, comment TEXT, FOREIGN KEY (goal_id) REFERENCES goals(id), FOREIGN KEY (user_id) REFERENCES users(id))");
});

// Регистрация пользователя
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).send('Username and password are required');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], function(err) {
        if (err) {
            return res.status(500).send('Error registering new user');
        }
        res.status(201).send('User created');
    });
});

// Вход пользователя
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).send('Username and password are required');
    }

    db.get('SELECT * FROM users WHERE username = ?', [username], async function(err, user) {
        if (err) {
            return res.status(500).send('Error logging in');
        }
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).send('Invalid credentials');
        }

        const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
        res.status(200).send({ token });
    });
});

// Миддлвэр для проверки JWT
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).send('Access denied');
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).send('Invalid token');
        }
        req.user = user;
        next();
    });
}

// Создание цели
app.post('/goals', authenticateToken, (req, res) => {
    const { name, description } = req.body;
    const userId = req.user.id;

    if (!name || !description) {
        return res.status(400).send('Name and description are required');
    }

    db.run('INSERT INTO goals (user_id, name, description) VALUES (?, ?, ?)', [userId, name, description], function(err) {
        if (err) {
            return res.status(500).send('Error creating goal');
        }
        res.status(201).send({ goalId: this.lastID });
    });
});

// Добавление комментария к цели
app.post('/goals/:goalId/comments', authenticateToken, (req, res) => {
    const { comment } = req.body;
    const goalId = req.params.goalId;
    const userId = req.user.id;

    if (!comment) {
        return res.status(400).send('Comment is required');
    }

    db.run('INSERT INTO goal_comments (goal_id, user_id, comment) VALUES (?, ?, ?)', [goalId, userId, comment], function(err) {
        if (err) {
            return res.status(500).send('Error adding comment');
        }
        res.status(201).send({ commentId: this.lastID });
    });
});

// Получение всех целей текущего пользователя
app.get('/goals', authenticateToken, (req, res) => {
    const userId = req.user.id;

    db.all('SELECT * FROM goals WHERE user_id = ?', [userId], (err, goals) => {
        if (err) {
            return res.status(500).send('Error fetching goals');
        }
        res.status(200).send(goals);
    });
});

// Получение всех целей и комментариев определенного пользователя (для администратора)
app.get('/admin/users/:userId/goals', authenticateToken, (req, res) => {
    // Проверка, является ли пользователь администратором
    if (req.user.role !== 'admin') {
        return res.status(403).send('Access denied');
    }

    const targetUserId = req.params.userId;

    db.all('SELECT * FROM goals WHERE user_id = ?', [targetUserId], (err, goals) => {
        if (err) {
            return res.status(500).send('Error fetching goals');
        }

        const goalsWithComments = goals.map((goal) => {
            return new Promise((resolve, reject) => {
                db.all('SELECT * FROM goal_comments WHERE goal_id = ?', [goal.id], (err, comments) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve({...goal, comments});
                    }
                });
            });
        });

        Promise.all(goalsWithComments)
            .then(results => res.status(200).send(results))
            .catch(err => res.status(500).send('Error fetching comments'));
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
