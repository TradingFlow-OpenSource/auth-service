const mongoose = require("mongoose");
const redis = require("redis");
const { MONGODB_URI, REDIS_URL, NODE_ENV } = require("./index");

// MongoDB connection
const connectMongoDB = async () => {
	try {
		await mongoose.connect(MONGODB_URI, {
			useNewUrlParser: true,
			useUnifiedTopology: true,
		});
		console.log("MongoDB connected successfully");
	} catch (error) {
		console.error("MongoDB connection error:", error);
		process.exit(1);
	}
};

// Redis connection
const connectRedis = async () => {
	try {
		const client = redis.createClient({
			url: REDIS_URL,
		});

		client.on("error", err => {
			console.error("Redis connection error:", err);
		});

		client.on("connect", () => {
			console.log("Redis connected successfully");
		});

		await client.connect();
		return client;
	} catch (error) {
		console.error("Redis connection error:", error);
		process.exit(1);
	}
};

// Graceful shutdown
const gracefulShutdown = async redisClient => {
	console.log("Received kill signal, shutting down gracefully...");

	// Close Redis connection
	if (redisClient) {
		await redisClient.quit();
		console.log("Redis connection closed");
	}

	// Close MongoDB connection
	await mongoose.connection.close();
	console.log("MongoDB connection closed");

	process.exit(0);
};

module.exports = {
	connectMongoDB,
	connectRedis,
	gracefulShutdown,
}; 