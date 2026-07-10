import express from 'express';
import { NaxiumSafeguard, createExpressMiddleware } from '../src/index.js';

const app = express();
app.set('trust proxy', 1); // only if behind a trusted reverse proxy
app.use(express.json({ limit: '64kb' }));

const guard = new NaxiumSafeguard({ securityLevel: 6 });

app.post(
  '/chat',
  createExpressMiddleware(guard, {
    channel: 'input',
    extractText: (req) => req.body.message,
    // sessionId is for your app logs; rate/lockout use connection identity
    extractContext: (req) => ({ sessionId: req.body.sessionId }),
  }),
  async (req, res) => {
    const protectionKey = req.ip || 'unknown';
    // Call your actual model here with req.body.message
    const modelReply = `Echo: ${req.body.message}`;

    const outputCheck = guard.guardOutput(modelReply, {
      sessionId: req.body.sessionId,
      protectionKey,
    });
    if (!outputCheck.safe) {
      return res.status(403).json({ error: outputCheck.alertMessage });
    }

    res.json({ reply: modelReply });
  },
);

app.listen(3000, () => console.log('demo chat server on :3000'));
