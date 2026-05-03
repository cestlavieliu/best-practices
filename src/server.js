const crypto = require('crypto');
const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcrypt');

const app = express();
app.use(express.json());

const db = mysql.createConnection({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'myapp_user',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'myapp'
});

const tokens = new Map();

function authenticate(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token || !tokens.has(token)) {
    return res.status(401).json({ error: '未授权' });
  }
  req.userId = tokens.get(token);
  next();
}

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: '用户名和密码必填' });
  }

  db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
    if (err) {
      return res.status(500).json({ error: '服务器错误' });
    }
    if (results.length === 0) {
      return res.status(401).json({ error: '用户名或密码错误' });
    }

    bcrypt.compare(password, results[0].password_hash, (err, match) => {
      if (err) {
        return res.status(500).json({ error: '服务器错误' });
      }
      if (!match) {
        return res.status(401).json({ error: '用户名或密码错误' });
      }

      const token = crypto.randomUUID();
      tokens.set(token, results[0].id);
      res.json({ token });
    });
  });
});

app.get('/user/:id', authenticate, (req, res) => {
  db.query('SELECT id, username, name FROM users WHERE id = ?', [req.params.id], (err, results) => {
    if (err) {
      return res.status(500).json({ error: '服务器错误' });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: '用户不存在' });
    }
    res.json(results[0]);
  });
});

app.delete('/user/:id', authenticate, (req, res) => {
  if (req.userId !== Number(req.params.id)) {
    return res.status(403).json({ error: '无权删除其他用户' });
  }

  db.query('DELETE FROM users WHERE id = ?', [req.params.id], (err, result) => {
    if (err) {
      return res.status(500).json({ error: '服务器错误' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: '用户不存在' });
    }
    tokens.delete(req.headers.authorization?.replace('Bearer ', ''));
    res.json({ deleted: true });
  });
});

const port = process.env.PORT || 3000;
app.listen(port);
