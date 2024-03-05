import supertest from 'supertest';
import app from '../blog';

const request = supertest(app);

describe('API Tests', () => {
  it('should return a list of blogs for a given author', async () => {
    const res = await request.get('/getBlogs/001');
    expect(res.status).toBe(200);
    expect(res.body).toBeInstanceOf(Array);
  });

  it('should insert a new blog', async () => {
    const newBlog = {
      id: '123',
      blogTitle: 'Test Blog',
      blogContent: 'This is a test blog.',
      authorId: 'author123',
      subscribedUserId: 'subscriber123',
      activeSubscriber: true,
    };

    const res = await request.post('/api/blogs/insert').send(newBlog);
    expect(res.status).toBe(200);
  });
});
