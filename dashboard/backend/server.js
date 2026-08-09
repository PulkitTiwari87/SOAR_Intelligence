require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const connectDB = require('./config/db');

// Route imports
const authRoutes = require('./routes/auth');
const aiRoutes = require('./routes/ai');
const incidentRoutes = require('./routes/incidents');
const systemRoutes = require('./routes/system');
const soarRoutes = require('./routes/soar');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Middleware ───
app.use(helmet());
app.use(cors({
  origin: ['http://localhost', 'http://localhost:5173', 'http://localhost:5174', 'http://localhost:5175', 'http://127.0.0.1:5173', 'http://127.0.0.1:5174'],
  credentials: true,
}));
app.use(express.json({ limit: '10mb' }));
app.use(morgan('dev'));

// ─── Routes ───
app.use('/api/auth', authRoutes);
app.use('/api/ai', aiRoutes);
app.use('/api/incidents', incidentRoutes);
app.use('/api/system', systemRoutes);
app.use('/api/soar', soarRoutes);

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', service: 'SOAR Dashboard API', timestamp: new Date().toISOString() });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: `Route ${req.method} ${req.path} not found` });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Server error:', err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

// ─── Start ───
const start = async () => {
  await connectDB();
  app.listen(PORT, () => {
    console.log(`\n  ╔══════════════════════════════════════╗`);
    console.log(`  ║  SOAR Dashboard API                  ║`);
    console.log(`  ║  http://localhost:${PORT}               ║`);
    console.log(`  ╚══════════════════════════════════════╝\n`);
  });
};

start();
