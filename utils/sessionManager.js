const redis = require('redis');
const { promisify } = require('util');

class SessionManager {
    constructor() {
        this.client = redis.createClient({
            url: process.env.REDIS_URL
        });

        this.client.on('error', (err) => console.log('Redis Client Error', err));
        this.client.connect().catch(console.error);
    }

    async createSession(userId, deviceInfo) {
        const sessionId = require('uuid').v4();
        const session = {
            userId,
            deviceInfo,
            createdAt: new Date().toISOString(),
            lastActivity: new Date().toISOString()
        };

        await this.client.set(`session:${sessionId}`, JSON.stringify(session));
        // 设置会话过期时间为24小时
        await this.client.expire(`session:${sessionId}`, 24 * 60 * 60);

        return sessionId;
    }

    async getSession(sessionId) {
        const session = await this.client.get(`session:${sessionId}`);
        return session ? JSON.parse(session) : null;
    }

    async updateSession(sessionId) {
        const session = await this.getSession(sessionId);
        if (session) {
            session.lastActivity = new Date().toISOString();
            await this.client.set(`session:${sessionId}`, JSON.stringify(session));
            await this.client.expire(`session:${sessionId}`, 24 * 60 * 60);
        }
    }

    async removeSession(sessionId) {
        await this.client.del(`session:${sessionId}`);
    }

    async getUserSessions(userId) {
        const keys = await this.client.keys(`session:*`);
        const sessions = [];
        
        for (const key of keys) {
            const session = await this.getSession(key.split(':')[1]);
            if (session && session.userId === userId) {
                sessions.push({
                    sessionId: key.split(':')[1],
                    ...session
                });
            }
        }
        
        return sessions;
    }
}

module.exports = new SessionManager(); 