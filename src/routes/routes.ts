import express from 'express';
const router = express.Router();

router.post('/api/v1/auth/authenticate', (req, res) => {
    res.send('Hello World!');
});
export default router;