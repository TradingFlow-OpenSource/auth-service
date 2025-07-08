const jwtService = require("./jwtService");
const User = require("../models/User");
const Identity = require("../models/Identity");

class SSOService {
	// 生成SSO token，用于跨域登录
	generateSSOToken(userId, identityId, targetDomain) {
		const payload = {
			userId,
			identityId,
			targetDomain,
			type: "sso",
			timestamp: Date.now(),
		};

		return jwtService.generateAccessToken(payload);
	}

	// 验证SSO token
	async validateSSOToken(token) {
		try {
			const decoded = jwtService.verifyAccessToken(token);

			if (decoded.type !== "sso") {
				throw new Error("Invalid SSO token type");
			}

			// 检查时间戳，SSO token 只有5分钟有效期
			if (Date.now() - decoded.timestamp > 5 * 60 * 1000) {
				throw new Error("SSO token expired");
			}

			const identity = await Identity.findById(decoded.identityId).populate("userId");

			if (!identity) {
				throw new Error("Identity not found");
			}

			return {
				user: identity.userId,
				identity,
				targetDomain: decoded.targetDomain,
			};
		} catch (error) {
			throw new Error(`SSO validation failed: ${error.message}`);
		}
	}

	// 创建跨域会话
	async createCrossDomainSession(userId, identityId, redisClient) {
		try {
			const sessionData = {
				userId,
				identityId,
				timestamp: Date.now(),
			};

			const sessionKey = `sso:session:${userId}:${identityId}`;
			await redisClient.setEx(sessionKey, 7 * 24 * 60 * 60, JSON.stringify(sessionData)); // 7天过期

			return sessionKey;
		} catch (error) {
			throw new Error(`Failed to create cross-domain session: ${error.message}`);
		}
	}

	// 验证跨域会话
	async validateCrossDomainSession(sessionKey, redisClient) {
		try {
			const sessionData = await redisClient.get(sessionKey);

			if (!sessionData) {
				throw new Error("Session not found or expired");
			}

			const parsed = JSON.parse(sessionData);
			const identity = await Identity.findById(parsed.identityId).populate("userId");

			if (!identity) {
				throw new Error("Identity not found");
			}

			// 更新会话时间
			await redisClient.setEx(sessionKey, 7 * 24 * 60 * 60, JSON.stringify({
				...parsed,
				lastAccessed: Date.now(),
			}));

			return {
				user: identity.userId,
				identity,
			};
		} catch (error) {
			throw new Error(`Session validation failed: ${error.message}`);
		}
	}

	// 销毁跨域会话
	async destroyCrossDomainSession(userId, identityId, redisClient) {
		try {
			const sessionKey = `sso:session:${userId}:${identityId}`;
			await redisClient.del(sessionKey);
			return true;
		} catch (error) {
			console.error("Failed to destroy session:", error);
			return false;
		}
	}

	// 获取平台配置
	getPlatformConfig(platform) {
		const configs = {
			tf: {
				name: "TradingFlow",
				url: process.env.TF_FRONTEND_URL || "https://tradingflow.pro",
				authCallback: "/auth/callback",
			},
			tn: {
				name: "TradingNodes",
				url: process.env.TN_FRONTEND_URL || "https://node.tradingflow.pro",
				authCallback: "/auth/callback",
			},
			ts: {
				name: "TradingSignal",
				url: process.env.TS_FRONTEND_URL || "https://signal.tradingflow.pro",
				authCallback: "/auth/callback",
			},
		};

		return configs[platform] || null;
	}

	// 生成平台跳转URL
	generatePlatformRedirectUrl(platform, token, additionalParams = {}) {
		const config = this.getPlatformConfig(platform);
		if (!config) {
			throw new Error("Invalid platform");
		}

		const url = new URL(config.authCallback, config.url);
		url.searchParams.set("token", token);
		url.searchParams.set("platform", platform);

		// 添加额外参数
		Object.entries(additionalParams).forEach(([key, value]) => {
			if (value !== undefined && value !== null) {
				url.searchParams.set(key, value.toString());
			}
		});

		return url.toString();
	}
}

module.exports = new SSOService(); 