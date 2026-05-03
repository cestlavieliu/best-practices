process.env.NODE_ENV = 'test';

const request = require('supertest');
const crypto = require('crypto');

// Mock mysql2
jest.mock('mysql2', () => {
  const mockQuery = jest.fn();
  const mockConnection = {
    query: mockQuery,
  };
  return {
    createConnection: jest.fn(() => mockConnection),
    __mockQuery: mockQuery,
    __mockConnection: mockConnection,
  };
});

// Mock bcrypt
jest.mock('bcrypt', () => ({
  compare: jest.fn(),
}));

const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const { app, tokens } = require('../server');

const mockQuery = mysql.__mockQuery;

describe('POST /login', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    tokens.clear();
  });

  it('应该返回400当用户名缺失时', async () => {
    const res = await request(app)
      .post('/login')
      .send({ password: '123456' });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('用户名和密码必填');
  });

  it('应该返回400当密码缺失时', async () => {
    const res = await request(app)
      .post('/login')
      .send({ username: 'testuser' });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('用户名和密码必填');
  });

  it('应该返回400当用户名和密码都缺失时', async () => {
    const res = await request(app)
      .post('/login')
      .send({});

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('用户名和密码必填');
  });

  it('应该返回500当数据库查询出错时', async () => {
    mockQuery.mockImplementation((sql, params, cb) => {
      cb(new Error('DB error'), null);
    });

    const res = await request(app)
      .post('/login')
      .send({ username: 'testuser', password: '123456' });

    expect(res.status).toBe(500);
    expect(res.body.error).toBe('服务器错误');
  });

  it('应该返回401当用户不存在时', async () => {
    mockQuery.mockImplementation((sql, params, cb) => {
      cb(null, []);
    });

    const res = await request(app)
      .post('/login')
      .send({ username: 'nonexistent', password: '123456' });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('用户名或密码错误');
  });

  it('应该返回500当bcrypt比较出错时', async () => {
    mockQuery.mockImplementation((sql, params, cb) => {
      cb(null, [{ id: 1, username: 'testuser', password_hash: 'hashed' }]);
    });
    bcrypt.compare.mockImplementation((pass, hash, cb) => {
      cb(new Error('bcrypt error'), null);
    });

    const res = await request(app)
      .post('/login')
      .send({ username: 'testuser', password: '123456' });

    expect(res.status).toBe(500);
    expect(res.body.error).toBe('服务器错误');
  });

  it('应该返回401当密码不匹配时', async () => {
    mockQuery.mockImplementation((sql, params, cb) => {
      cb(null, [{ id: 1, username: 'testuser', password_hash: 'hashed' }]);
    });
    bcrypt.compare.mockImplementation((pass, hash, cb) => {
      cb(null, false);
    });

    const res = await request(app)
      .post('/login')
      .send({ username: 'testuser', password: 'wrongpass' });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('用户名或密码错误');
  });

  it('应该返回token当登录成功时', async () => {
    const fakeUUID = 'fake-uuid-1234';
    jest.spyOn(crypto, 'randomUUID').mockReturnValue(fakeUUID);

    mockQuery.mockImplementation((sql, params, cb) => {
      cb(null, [{ id: 42, username: 'testuser', password_hash: 'hashed' }]);
    });
    bcrypt.compare.mockImplementation((pass, hash, cb) => {
      cb(null, true);
    });

    const res = await request(app)
      .post('/login')
      .send({ username: 'testuser', password: 'correctpass' });

    expect(res.status).toBe(200);
    expect(res.body.token).toBe(fakeUUID);
    expect(tokens.get(fakeUUID)).toBe(42);

    crypto.randomUUID.mockRestore();
  });
});

describe('GET /user/:id', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    tokens.clear();
  });

  it('应该返回401当没有提供token时', async () => {
    const res = await request(app).get('/user/1');

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('未授权');
  });

  it('应该返回401当token无效时', async () => {
    const res = await request(app)
      .get('/user/1')
      .set('Authorization', 'Bearer invalid-token');

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('未授权');
  });

  it('应该返回500当数据库查询出错时', async () => {
    const validToken = 'valid-token-123';
    tokens.set(validToken, 1);

    mockQuery.mockImplementation((sql, params, cb) => {
      cb(new Error('DB error'), null);
    });

    const res = await request(app)
      .get('/user/1')
      .set('Authorization', `Bearer ${validToken}`);

    expect(res.status).toBe(500);
    expect(res.body.error).toBe('服务器错误');
  });

  it('应该返回404当用户不存在时', async () => {
    const validToken = 'valid-token-123';
    tokens.set(validToken, 1);

    mockQuery.mockImplementation((sql, params, cb) => {
      cb(null, []);
    });

    const res = await request(app)
      .get('/user/999')
      .set('Authorization', `Bearer ${validToken}`);

    expect(res.status).toBe(404);
    expect(res.body.error).toBe('用户不存在');
  });

  it('应该返回用户信息当查询成功时', async () => {
    const validToken = 'valid-token-123';
    tokens.set(validToken, 1);

    const mockUser = { id: 1, username: 'testuser', name: '测试用户' };
    mockQuery.mockImplementation((sql, params, cb) => {
      cb(null, [mockUser]);
    });

    const res = await request(app)
      .get('/user/1')
      .set('Authorization', `Bearer ${validToken}`);

    expect(res.status).toBe(200);
    expect(res.body).toEqual(mockUser);
  });

  it('应该允许查询其他用户的信息当已认证时', async () => {
    const validToken = 'valid-token-123';
    tokens.set(validToken, 1);

    const otherUser = { id: 2, username: 'other', name: '其他用户' };
    mockQuery.mockImplementation((sql, params, cb) => {
      cb(null, [otherUser]);
    });

    const res = await request(app)
      .get('/user/2')
      .set('Authorization', `Bearer ${validToken}`);

    expect(res.status).toBe(200);
    expect(res.body).toEqual(otherUser);
  });
});

describe('DELETE /user/:id', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    tokens.clear();
  });

  it('应该返回401当没有提供token时', async () => {
    const res = await request(app).delete('/user/1');

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('未授权');
  });

  it('应该返回401当token无效时', async () => {
    const res = await request(app)
      .delete('/user/1')
      .set('Authorization', 'Bearer invalid-token');

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('未授权');
  });

  it('应该返回403当尝试删除其他用户时', async () => {
    const validToken = 'valid-token-123';
    tokens.set(validToken, 1);

    const res = await request(app)
      .delete('/user/2')
      .set('Authorization', `Bearer ${validToken}`);

    expect(res.status).toBe(403);
    expect(res.body.error).toBe('无权删除其他用户');
  });

  it('应该返回500当数据库删除出错时', async () => {
    const validToken = 'valid-token-123';
    tokens.set(validToken, 1);

    mockQuery.mockImplementation((sql, params, cb) => {
      cb(new Error('DB error'), null);
    });

    const res = await request(app)
      .delete('/user/1')
      .set('Authorization', `Bearer ${validToken}`);

    expect(res.status).toBe(500);
    expect(res.body.error).toBe('服务器错误');
  });

  it('应该返回404当要删除的用户不存在时', async () => {
    const validToken = 'valid-token-123';
    tokens.set(validToken, 1);

    mockQuery.mockImplementation((sql, params, cb) => {
      cb(null, { affectedRows: 0 });
    });

    const res = await request(app)
      .delete('/user/1')
      .set('Authorization', `Bearer ${validToken}`);

    expect(res.status).toBe(404);
    expect(res.body.error).toBe('用户不存在');
  });

  it('应该成功删除用户并清除token当删除自己时', async () => {
    const validToken = 'valid-token-123';
    tokens.set(validToken, 1);

    mockQuery.mockImplementation((sql, params, cb) => {
      cb(null, { affectedRows: 1 });
    });

    const res = await request(app)
      .delete('/user/1')
      .set('Authorization', `Bearer ${validToken}`);

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ deleted: true });
    expect(tokens.has(validToken)).toBe(false);
  });
});

describe('authenticate 中间件', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    tokens.clear();
  });

  it('应该返回401当Authorization头完全缺失时', async () => {
    const res = await request(app).get('/user/1');

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('未授权');
  });

  it('应该返回401当Bearer token为空字符串时', async () => {
    const res = await request(app)
      .get('/user/1')
      .set('Authorization', 'Bearer ');

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('未授权');
  });

  it('应该正确解析Bearer token并设置userId', async () => {
    const validToken = 'valid-token-xyz';
    tokens.set(validToken, 99);

    const mockUser = { id: 99, username: 'user99', name: '用户99' };
    mockQuery.mockImplementation((sql, params, cb) => {
      cb(null, [mockUser]);
    });

    const res = await request(app)
      .get('/user/99')
      .set('Authorization', `Bearer ${validToken}`);

    expect(res.status).toBe(200);
  });
});
