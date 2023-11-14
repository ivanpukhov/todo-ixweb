const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
const db = new sqlite3.Database(':memory:'); // Используем память для хранения базы данных для примера

app.use(express.json());
app.use(cors());

const JWT_SECRET = 'your_jwt_secret'; // В реальном приложении используйте безопасный ключ

// Инициализация базы данных
db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT, role TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS goals (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT, description TEXT, is_completed BOOLEAN DEFAULT FALSE, parent_id INTEGER, goal_type TEXT, FOREIGN KEY (user_id) REFERENCES users(id), FOREIGN KEY (parent_id) REFERENCES goals(id))");
    db.run("CREATE TABLE IF NOT EXISTS goal_comments (id INTEGER PRIMARY KEY AUTOINCREMENT, goal_id INTEGER, user_id INTEGER, comment TEXT, FOREIGN KEY (goal_id) REFERENCES goals(id), FOREIGN KEY (user_id) REFERENCES users(id))");
});

// Функция для рекурсивного получения дерева целей
async function getGoalTree(goalId) {
    return new Promise((resolve, reject) => {
        db.get('SELECT * FROM goals WHERE id = ?', [goalId], async (err, goal) => {
            if (err) {
                reject(err);
                return;
            }
            if (!goal) {
                resolve(null);
                return;
            }

            db.all('SELECT * FROM goals WHERE parent_id = ?', [goalId], async (err, subGoals) => {
                if (err) {
                    reject(err);
                    return;
                }

                let tree = { ...goal, subGoals: [] };
                for (const subGoal of subGoals) {
                    tree.subGoals.push(await getGoalTree(subGoal.id));
                }

                resolve(tree);
            });
        });
    });
}

// Роут для получения цели по ID и её подцелей
app.get('/goals/:goalId', authenticateToken, async (req, res) => {
    const goalId = req.params.goalId;

    try {
        const goalTree = await getGoalTree(goalId);
        if (!goalTree) {
            return res.status(404).send('Goal not found');
        }
        res.status(200).send(goalTree);
    } catch (err) {
        res.status(500).send('Error fetching goal: ' + err.message);
    }
});


// Регистрация пользователя
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).send('Username and password are required');
    }

    // Проверка на существование пользователя
    db.get('SELECT id FROM users WHERE username = ?', [username], async (err, row) => {
        if (err) {
            return res.status(500).send('Error during registration');
        }

        if (row) {
            return res.status(409).send('User already exists');
        }

        // Хеширование пароля
        const hashedPassword = await bcrypt.hash(password, 10);

        // Добавление пользователя в базу данных
        db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], function(err) {
            if (err) {
                return res.status(500).send('Error registering new user');
            }

            // Создание JWT токена
            const userId = this.lastID; // получаем ID нового пользователя
            const token = jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: '24h' });

            // Отправляем ответ с токеном
            res.status(201).send({ token });
        });
    });
});

// Обновление статуса выполнения цели
app.put('/goals/:goalId/complete', authenticateToken, (req, res) => {
    const goalId = req.params.goalId;
    const isCompleted = req.body.isCompleted; // true или false

    db.run('UPDATE goals SET is_completed = ? WHERE id = ?', [isCompleted, goalId], function(err) {
        if (err) {
            return res.status(500).send('Error updating goal status');
        }
        res.status(200).send({ message: 'Goal status updated successfully' });
    });
});

app.get('/goals', authenticateToken, (req, res) => {
    const userId = req.user.id;

    db.all('SELECT * FROM goals WHERE user_id = ?', [userId], (err, goals) => {
        if (err) {
            return res.status(500).send('Error fetching goals');
        }
        res.status(200).send(goals.map(goal => ({ ...goal, is_completed: Boolean(goal.is_completed) })));
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
        console.log('Новая авторизация')
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
    const { name, description, goalType, parentId } = req.body;
    const userId = req.user.id;

    // Проверка основных данных
    if (!name || !description || !goalType) {
        return res.status(400).send('Name, description, and goal type are required');
    }

    // Проверка типа цели
    const validGoalTypes = ['global', 'monthly', 'weekly', 'daily'];
    if (!validGoalTypes.includes(goalType)) {
        return res.status(400).send('Invalid goal type');
    }

    const createGoal = () => {
        db.run('INSERT INTO goals (user_id, name, description, goal_type, parent_id) VALUES (?, ?, ?, ?, ?)', [userId, name, description, goalType, parentId || null], function(err) {
            if (err) {
                return res.status(500).send('Error creating goal');
            }
            res.status(201).send({ goalId: this.lastID });
        });
    };

    // Для не-глобальных целей проверяем наличие и тип родительской цели
    if (goalType !== 'global' && parentId) {
        db.get('SELECT * FROM goals WHERE id = ?', [parentId], (err, parentGoal) => {
            if (err) {
                return res.status(500).send('Error fetching parent goal');
            }
            if (!parentGoal) {
                return res.status(400).send('Parent goal not found');
            }

            // Проверка соответствия типов родительской и дочерней целей
            const parentGoalTypeIndex = validGoalTypes.indexOf(parentGoal.goal_type);
            const currentGoalTypeIndex = validGoalTypes.indexOf(goalType);
            if (parentGoalTypeIndex >= currentGoalTypeIndex) {
                return res.status(400).send('Invalid parent goal type for the specified goal type');
            }

            createGoal();
        });
    } else {
        createGoal();
    }
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
        // return res.status(403).send('Access denied');
        console.log('admin')
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


const PORT = 5555;
const HOST = '0.0.0.0'; // Это позволит вам слушать на всех доступных сетевых интерфейсах

app.listen(PORT, HOST, () => {
    console.log(`Сервер запущен на http://${HOST}:${PORT}`);
});

