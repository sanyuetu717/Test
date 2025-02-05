require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const User = require('./models/User');
const sessionManager = require('./utils/sessionManager');

const app = express();
const PORT = process.env.PORT || 3000;

// 数据库连接
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => {
    console.log('数据库连接成功');
    console.log('MongoDB URI:', process.env.MONGODB_URI);
})
.catch(err => {
    console.error('数据库连接失败:', err);
    console.error('MongoDB URI:', process.env.MONGODB_URI);
});

// 中间件
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

// 会话中间件
const sessionAuth = async (req, res, next) => {
    const sessionId = req.headers['x-session-id'];
    if (sessionId) {
        const session = await sessionManager.getSession(sessionId);
        if (session) {
            req.session = session;
            await sessionManager.updateSession(sessionId);
            next();
        } else {
            res.status(401).json({ error: '会话已过期' });
        }
    } else {
        next();
    }
};

app.use(sessionAuth);

// 注册路由
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // 检查用户是否已存在
        const existingUser = await User.findOne({ 
            $or: [{ email }, { username }] 
        });

        if (existingUser) {
            return res.status(400).json({
                error: '用户名或邮箱已被注册'
            });
        }

        // 创建新用户
        const user = new User({
            username,
            email,
            password
        });

        await user.save();

        // 生成JWT
        const token = jwt.sign(
            { userId: user._id, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.status(201).json({
            message: '注册成功',
            token,
            user: {
                id: user._id,
                username: user.username,
                email: user.email
            }
        });
    } catch (error) {
        console.error('注册错误:', error);
        res.status(500).json({
            error: '注册失败',
            details: error.message
        });
    }
});

// 登录路由
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const deviceInfo = {
            userAgent: req.headers['user-agent'],
            ip: req.ip
        };

        const user = await User.findOne({ username }).select('+password');
        
        if (!user || !(await user.comparePassword(password))) {
            return res.status(401).json({ error: '用户名或密码错误' });
        }

        // 创建新会话
        const sessionId = await sessionManager.createSession(user._id.toString(), deviceInfo);

        // 更新最后登录时间
        user.lastLogin = new Date();
        await user.save();

        // 生成JWT
        const token = jwt.sign(
            { userId: user._id, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            message: '登录成功',
            token,
            sessionId,
            user: {
                id: user._id,
                username: user.username,
                email: user.email
            }
        });
    } catch (error) {
        console.error('登录错误:', error);
        res.status(500).json({ error: '服务器错误' });
    }
});

// 登出路由
app.post('/api/logout', async (req, res) => {
    const sessionId = req.headers['x-session-id'];
    if (sessionId) {
        await sessionManager.removeSession(sessionId);
    }
    res.json({ message: '已成功登出' });
});

// 获取用户所有会话
app.get('/api/sessions', authenticateToken, async (req, res) => {
    try {
        const sessions = await sessionManager.getUserSessions(req.user.userId);
        res.json({ sessions });
    } catch (error) {
        res.status(500).json({ error: '获取会话信息失败' });
    }
});

// 结束指定会话
app.delete('/api/sessions/:sessionId', authenticateToken, async (req, res) => {
    try {
        const session = await sessionManager.getSession(req.params.sessionId);
        if (!session || session.userId !== req.user.userId) {
            return res.status(403).json({ error: '无权限结束此会话' });
        }
        
        await sessionManager.removeSession(req.params.sessionId);
        res.json({ message: '会话已结束' });
    } catch (error) {
        res.status(500).json({ error: '结束会话失败' });
    }
});

// 验证令牌的中间件
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: '未提供认证令牌' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: '令牌无效' });
        }
        req.user = user;
        next();
    });
};

// 获取用户资料
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user) {
            return res.status(404).json({ error: '用户不存在' });
        }

        res.json({
            message: '获取个人资料成功',
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                role: user.role,
                createdAt: user.createdAt,
                lastLogin: user.lastLogin
            }
        });
    } catch (error) {
        res.status(500).json({ error: '服务器错误' });
    }
});

app.listen(PORT, () => {
    console.log(`服务器运行在 http://localhost:${PORT}`);
}); 