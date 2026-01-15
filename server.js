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
const adminRoutes = require('./src/routes/admin');

const app = express();

// Get PORT from Railway environment variable or default
const PORT = process.env.PORT || 3000; // Changed back to 3000 as Railway prefers it

// Security middleware
app.use(helmet());

// Rate limiting - adjusted for Railway
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100, // Limit each IP to 100 requests per windowMs
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  message: {
    error: 'Too many requests from this IP, please try again later.',
    retryAfter: '15 minutes'
  },
  skip: (req) => req.path === '/health' // Skip rate limiting for health checks
});

app.use(limiter);

// CORS configuration - UPDATED for Railway
const allowedOrigins = process.env.NODE_ENV === 'production' 
  ? [
      process.env.FRONTEND_URL, // Your actual frontend URL
      'https://your-frontend-domain.com',
      'https://*.railway.app' // Allow Railway preview deployments
    ].filter(Boolean) // Remove undefined values
  : [
      'http://localhost:3000',
      'http://localhost:3001',
      'http://localhost:8080',
      'http://localhost:5173', // Added for Vite
      'http://127.0.0.1:3000'
    ];

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = `The CORS policy for this site does not allow access from the specified Origin: ${origin}`;
      console.warn('CORS Blocked:', origin);
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  exposedHeaders: ['Content-Range', 'X-Content-Range']
}));

// Handle preflight requests
app.options('*', cors());

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Logging middleware - Enhanced for Railway
if (process.env.NODE_ENV !== 'test') {
  const morganFormat = process.env.NODE_ENV === 'production' ? 'combined' : 'dev';
  app.use(morgan(morganFormat, {
    skip: (req) => req.path === '/health' && req.method === 'GET' // Skip health checks from logs
  }));
}

// Enhanced Health check endpoint for Railway
app.get('/health', (req, res) => {
  const healthData = {
    status: 'healthy',
    service: 'express-backend-api',
    timestamp: new Date().toISOString(),
    port: PORT,
    nodeVersion: process.version,
    environment: process.env.NODE_ENV || 'development',
    uptime: process.uptime(),
    memory: process.memoryUsage()
  };
  
  // Set cache headers for health endpoint
  res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  
  res.status(200).json(healthData);
});

// API routes with versioning
const API_PREFIX = '/api';
app.use(`${API_PREFIX}/auth`, auth);
app.use(`${API_PREFIX}/search/jobs`, jobsRoutes);
app.use(`${API_PREFIX}/search/products`, productsRoutes);
app.use(`${API_PREFIX}/search/universities`, universitiesRoutes);
app.use(`${API_PREFIX}/search/scholarships`, scholarshipsRoutes);
app.use(`${API_PREFIX}/admin`, adminRoutes);

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'Express Backend API',
    version: '1.0.0',
    documentation: `${req.protocol}://${req.get('host')}/api-docs`, // If you add Swagger later
    endpoints: [
      `${API_PREFIX}/auth`,
      `${API_PREFIX}/search/jobs`,
      `${API_PREFIX}/search/products`,
      `${API_PREFIX}/search/universities`,
      `${API_PREFIX}/search/scholarships`,
      `${API_PREFIX}/admin`
    ],
    health: `${req.protocol}://${req.get('host')}/health`
  });
});

// Enhanced Error handling middleware
app.use((err, req, res, next) => {
  console.error('API Error:', {
    message: err.message,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
    path: req.path,
    method: req.method,
    timestamp: new Date().toISOString()
  });
  
  // Handle CORS errors specifically
  if (err.message.includes('CORS')) {
    return res.status(403).json({
      error: 'CORS Error',
      message: 'Request blocked by CORS policy'
    });
  }
  
  res.status(err.status || 500).json({
    error: process.env.NODE_ENV === 'production' ? 'Internal Server Error' : err.message,
    ...(process.env.NODE_ENV === 'development' && { 
      stack: err.stack,
      details: err.details 
    })
  });
});

// 404 handler - Improved
app.use('*', (req, res) => {
  console.warn('404 Not Found:', {
    path: req.originalUrl,
    method: req.method,
    ip: req.ip,
    timestamp: new Date().toISOString()
  });
  
  res.status(404).json({
    error: 'Route not found',
    path: req.originalUrl,
    availableEndpoints: [
      '/',
      '/health',
      '/api/auth',
      '/api/search/jobs',
      '/api/search/products',
      '/api/search/universities',
      '/api/search/scholarships',
      '/api/admin'
    ]
  });
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  // In production, you might want to restart the process
  if (process.env.NODE_ENV === 'production') {
    process.exit(1);
  }
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

// Start server with Railway-specific logging
const server = app.listen(PORT, () => {
  console.log('='.repeat(50));
  console.log(`🚀 Express server is running!`);
  console.log(`📦 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔌 Port: ${PORT}`);
  console.log(`🌐 URL: http://localhost:${PORT}`);
  console.log(`🏥 Health: http://localhost:${PORT}/health`);
  console.log('='.repeat(50));
  
  // Log CORS origins
  console.log('🔗 CORS Allowed Origins:');
  if (process.env.NODE_ENV === 'production') {
    console.log('   Production origins configured');
    if (process.env.FRONTEND_URL) {
      console.log(`   Frontend: ${process.env.FRONTEND_URL}`);
    }
  } else {
    allowedOrigins.forEach(origin => console.log(`   ${origin}`));
  }
  console.log('='.repeat(50));
});

// Graceful shutdown for Railway
const gracefulShutdown = () => {
  console.log('Received shutdown signal, closing server gracefully...');
  
  server.close(() => {
    console.log('Server closed successfully');
    process.exit(0);
  });
  
  // Force close after 10 seconds
  setTimeout(() => {
    console.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 10000);
};

// Listen for shutdown signals
process.on('SIGTERM', gracefulShutdown); // Railway sends SIGTERM
process.on('SIGINT', gracefulShutdown);  // Ctrl+C

module.exports = { app, server }; // For testing