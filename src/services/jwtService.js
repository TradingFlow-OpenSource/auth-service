const jwt = require("jsonwebtoken");
const { JWT_SECRET, JWT_REFRESH_SECRET, JWT_EXPIRES_IN, JWT_REFRESH_EXPIRES_IN } = require("../config");

class JWTService {
	// Generate access token
	generateAccessToken(payload) {
		return jwt.sign(payload, JWT_SECRET, {
			expiresIn: JWT_EXPIRES_IN,
		});
	}

	// Generate refresh token
	generateRefreshToken(payload) {
		return jwt.sign(payload, JWT_REFRESH_SECRET, {
			expiresIn: JWT_REFRESH_EXPIRES_IN,
		});
	}

	// Generate token pair
	generateTokenPair(payload) {
		const accessToken = this.generateAccessToken(payload);
		const refreshToken = this.generateRefreshToken(payload);

		return {
			accessToken,
			refreshToken,
			expiresIn: JWT_EXPIRES_IN,
		};
	}

	// Verify access token
	verifyAccessToken(token) {
		try {
			return jwt.verify(token, JWT_SECRET);
		} catch (error) {
			throw new Error("Invalid access token");
		}
	}

	// Verify refresh token
	verifyRefreshToken(token) {
		try {
			return jwt.verify(token, JWT_REFRESH_SECRET);
		} catch (error) {
			throw new Error("Invalid refresh token");
		}
	}

	// Decode token without verification (for expired tokens)
	decodeToken(token) {
		try {
			return jwt.decode(token);
		} catch (error) {
			throw new Error("Invalid token format");
		}
	}

	// Generate verification token (for email/phone verification)
	generateVerificationToken(payload, expiresIn = "15m") {
		return jwt.sign(
			{
				...payload,
				type: "verification",
				expiresAt: Date.now() + 15 * 60 * 1000, // 15 minutes
			},
			JWT_SECRET,
			{ expiresIn }
		);
	}

	// Verify verification token
	verifyVerificationToken(token) {
		try {
			const decoded = jwt.verify(token, JWT_SECRET);
			if (decoded.type !== "verification") {
				throw new Error("Invalid verification token type");
			}
			if (decoded.expiresAt < Date.now()) {
				throw new Error("Verification token expired");
			}
			return decoded;
		} catch (error) {
			throw new Error("Invalid verification token");
		}
	}
}

module.exports = new JWTService(); 