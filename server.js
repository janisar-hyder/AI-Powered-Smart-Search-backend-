require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');

// Import routes
const auth = require('./src/routes/auth');
const jobsRoutes = require('./src/routes/jobsRoutes');
const productsRoutes = require('./src/routes/productsRoutes');
const universitiesRoutes = require('./src/routes/universitiesRoutes');
const scholarshipsRoutes = require('./src/routes/scholarshipsRoutes');
const adminRoutes = require('./src/routes/admin'); // Add this line

const app = express();
const PORT = process.env.PORT || 3001; // Changed to 3001 to match your API

// Security middleware
app.use(helmet());

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);

// CORS configuration - FIXED
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://your-frontend-domain.com'] 
    : ['http://localhost:3000', 'http://localhost:3001', 'http://localhost:8080'], // Added 8080
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Handle preflight requests
app.options('*', cors());

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Logging middleware
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    service: 'express-server', 
    port: PORT,
    timestamp: new Date().toISOString()
  });
});

// API routes
app.use('/api/auth', auth);
app.use('/api/search/jobs', jobsRoutes);
app.use('/api/search/products', productsRoutes);
app.use('/api/search/universities', universitiesRoutes);
app.use('/api/search/scholarships', scholarshipsRoutes);
app.use('/api/admin', adminRoutes); // Add this line

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(err.status || 500).json({
    error: process.env.NODE_ENV === 'production' ? 'Internal Server Error' : err.message,
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

app.listen(PORT, () => {
  console.log(`🚀 Express server is running on port ${PORT}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 Health check: http://localhost:${PORT}/health`);
  console.log(`🌐 CORS enabled for: http://localhost:8080`);
});