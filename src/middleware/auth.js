const jwtService = require("../services/jwtService");
const User = require("../models/User");
const Identity = require("../models/Identity");

/**
 * Required authentication middleware
 * Verifies JWT token and attaches user to request
 */
const auth = async (req, res, next) => {
	try {
		const token = req.header("Authorization")?.replace("Bearer ", "") || req.cookies?.token;

		if (!token) {
			return res.status(401).json({ error: "Authentication required" });
		}

		const decoded = jwtService.verifyAccessToken(token);

		// Handle verification tokens
		if (decoded.type === "verification") {
			req.verification = decoded;
			return next();
		}

		// Handle authentication tokens
		const identity = await Identity.findById(decoded.identityId).populate("userId");

		if (!identity) {
			return res.status(401).json({ error: "Invalid authentication" });
		}

		// Update last used timestamp
		identity.lastUsedAt = Date.now();
		await identity.save();

		req.user = identity.userId;
		req.identity = identity;
		next();
	} catch (error) {
		res.status(401).json({ error: "Invalid authentication" });
	}
};

/**
 * Optional authentication middleware
 * Attempts to verify JWT token but continues if not present
 */
const optAuth = async (req, res, next) => {
	try {
		const token = req.header("Authorization")?.replace("Bearer ", "") || req.cookies?.token;

		if (token) {
			const decoded = jwtService.verifyAccessToken(token);

			// Handle verification tokens
			if (decoded.type === "verification") {
				req.verification = decoded;
				return next();
			}

			// Handle authentication tokens
			const identity = await Identity.findById(decoded.identityId).populate("userId");

			if (identity) {
				// Update last used timestamp
				identity.lastUsedAt = Date.now();
				await identity.save();

				req.user = identity.userId;
				req.identity = identity;
			}
		}
		next();
	} catch (error) {
		// Continue without authentication
		next();
	}
};

/**
 * Admin authentication middleware
 * Checks if user has admin privileges
 */
const adminAuth = async (req, res, next) => {
	try {
		await auth(req, res, () => {});

		if (!req.user || !req.user.isAdmin) {
			return res.status(403).json({ error: "Admin access required" });
		}

		next();
	} catch (error) {
		res.status(401).json({ error: "Invalid authentication" });
	}
};

/**
 * Cross-domain session validation
 * Validates session tokens from different domains
 */
const validateCrossDomainSession = async (req, res, next) => {
	try {
		const sessionToken = req.query.sessionToken || req.cookies?.["tf-session"];

		if (!sessionToken) {
			return res.status(401).json({ error: "No session token provided" });
		}

		const decoded = jwtService.verifyAccessToken(sessionToken);
		const identity = await Identity.findById(decoded.identityId).populate("userId");

		if (!identity) {
			return res.status(401).json({ error: "Invalid session" });
		}

		req.user = identity.userId;
		req.identity = identity;
		next();
	} catch (error) {
		res.status(401).json({ error: "Invalid session token" });
	}
};

module.exports = {
	auth,
	optAuth,
	adminAuth,
	validateCrossDomainSession,
}; 