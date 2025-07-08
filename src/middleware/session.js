const session = require("express-session");
const RedisStore = require("connect-redis").default;
const { SESSION_SECRET, SESSION_NAME, SESSION_DOMAIN, NODE_ENV } = require("../config");

const createSessionMiddleware = redisClient => {
	return session({
		store: new RedisStore({
			client: redisClient,
			prefix: "tf-session:",
		}),
		name: SESSION_NAME,
		secret: SESSION_SECRET,
		resave: false,
		saveUninitialized: false,
		cookie: {
			secure: NODE_ENV === "production", // HTTPS in production
			httpOnly: true,
			maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
			domain: SESSION_DOMAIN, // Cross-domain session
			sameSite: NODE_ENV === "production" ? "none" : "lax",
		},
	});
};

module.exports = {
	createSessionMiddleware,
}; 