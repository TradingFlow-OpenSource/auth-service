require("dotenv").config();

module.exports = {
	PORT: process.env.PORT || 3001,
	NODE_ENV: process.env.NODE_ENV || "development",

	// Database
	MONGODB_URI: process.env.MONGODB_URI || "mongodb://localhost:27017/tradingflow-auth",
	REDIS_URL: process.env.REDIS_URL || "redis://localhost:6379",

	// JWT
	JWT_SECRET: process.env.JWT_SECRET,
	JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET,
	JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || "24h",
	JWT_REFRESH_EXPIRES_IN: process.env.JWT_REFRESH_EXPIRES_IN || "7d",

	// Session
	SESSION_SECRET: process.env.SESSION_SECRET,
	SESSION_NAME: process.env.SESSION_NAME || "tf-session",
	SESSION_DOMAIN: process.env.SESSION_DOMAIN || ".tradingflow.pro",

	// OAuth
	GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID,
	GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET,
	GOOGLE_CALLBACK_URL: process.env.GOOGLE_CALLBACK_URL || "http://localhost:3001/auth/google/callback",

	// Telegram
	TELEGRAM_BOT_TOKEN: process.env.TELEGRAM_BOT_TOKEN,

	// CORS
	ALLOWED_ORIGINS: process.env.ALLOWED_ORIGINS
		? process.env.ALLOWED_ORIGINS.split(",")
		: ["http://localhost:3000", "http://localhost:5173"],

	// Security
	RATE_LIMIT_WINDOW_MS: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000, // 15 minutes
	RATE_LIMIT_MAX_REQUESTS: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,

	// TradingFlow Backend
	TF_BACKEND_URL: process.env.TF_BACKEND_URL || "http://localhost:3000",
}; 