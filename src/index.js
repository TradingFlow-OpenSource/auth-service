const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");

// Configuration and database
const config = require("./config");
const { connectMongoDB, connectRedis, gracefulShutdown } = require("./config/database");
const { createSessionMiddleware } = require("./middleware/session");

// Routes
const authRoutes = require("./routes/auth");

// Passport configuration
require("./config/passport");

const app = express();

// Trust proxy for proper IP detection
app.set("trust proxy", 1);

// Basic middleware
app.use(helmet());
app.use(morgan("combined"));
app.use(cookieParser());

// CORS configuration
app.use(
	cors({
		origin: config.ALLOWED_ORIGINS,
		credentials: true,
		methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
		allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
	})
);

// Rate limiting
const limiter = rateLimit({
	windowMs: config.RATE_LIMIT_WINDOW_MS,
	max: config.RATE_LIMIT_MAX_REQUESTS,
	message: {
		error: "Too many requests from this IP, please try again later.",
	},
	standardHeaders: true,
	legacyHeaders: false,
});
app.use(limiter);

// Body parsing middleware
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

let redisClient;

// Initialize the application
const initializeApp = async () => {
	try {
		// Connect to databases
		await connectMongoDB();
		redisClient = await connectRedis();

		// Session middleware (needs Redis client)
		app.use(createSessionMiddleware(redisClient));

		// Initialize Passport
		const passport = require("passport");
		app.use(passport.initialize());

		// Routes
		app.use("/auth", authRoutes);

		// Health check endpoint
		app.get("/health", (req, res) => {
			res.json({
				status: "ok",
				service: "TradingFlow Auth Service",
				timestamp: new Date().toISOString(),
				version: "1.0.0",
			});
		});

		// API status endpoint
		app.get("/", (req, res) => {
			res.json({
				message: "TradingFlow 统一认证服务",
				version: "1.0.0",
				endpoints: {
					health: "/health",
					auth: "/auth",
					session: "/auth/session/validate",
					google: "/auth/google",
					telegram: "/auth/telegram",
					wallet: "/auth/wallet",
					sso: "/auth/sso/:platform",
				},
			});
		});

		// 404 handler
		app.use("*", (req, res) => {
			res.status(404).json({
				error: "Endpoint not found",
				message: "The requested endpoint does not exist",
			});
		});

		// Global error handler
		app.use((err, req, res, next) => {
			console.error("Unhandled error:", err);

			if (err.name === "ValidationError") {
				return res.status(400).json({
					error: "Validation error",
					details: err.message,
				});
			}

			if (err.name === "MongoError" || err.name === "MongoServerError") {
				return res.status(500).json({
					error: "Database error",
					message: "A database error occurred",
				});
			}

			res.status(500).json({
				error: "Internal server error",
				message: config.NODE_ENV === "development" ? err.message : "Something went wrong",
			});
		});

		// Start server
		const server = app.listen(config.PORT, () => {
			console.log(`🚀 TradingFlow Auth Service running on port ${config.PORT}`);
			console.log(`📖 Environment: ${config.NODE_ENV}`);
			console.log(`🌐 CORS origins:`, config.ALLOWED_ORIGINS);
		});

		// Graceful shutdown
		const shutdownHandler = async signal => {
			console.log(`\n${signal} received, shutting down gracefully...`);
			server.close(() => {
				gracefulShutdown(redisClient);
			});
		};

		process.on("SIGTERM", () => shutdownHandler("SIGTERM"));
		process.on("SIGINT", () => shutdownHandler("SIGINT"));

		return server;
	} catch (error) {
		console.error("Failed to initialize application:", error);
		process.exit(1);
	}
};

// Start the application
if (require.main === module) {
	initializeApp();
}

module.exports = app; 