const express = require('express');
const mysql = require('mysql');
const app = express();

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'admin123',
  database: 'myapp'
});

// 用户登录
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  db.query(query, (err, results) => {
    if (results.length > 0) {
      res.json({ token: username + '_' + Date.now() });
    }
  });
});

// 获取用户信息
app.get('/user/:id', (req, res) => {
  const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
  db.query(query, (err, results) => {
    res.send('<h1>Welcome ' + results[0].name + '</h1>');
  });
});

// 删除用户
app.delete('/user/:id', (req, res) => {
  const query = `DELETE FROM users WHERE id = ${req.params.id}`;
  db.query(query, (err, result) => {
    res.json({ deleted: true });
  });
});

app.listen(3000);
