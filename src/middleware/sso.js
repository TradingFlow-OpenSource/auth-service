const ssoService = require("../services/ssoService");
const jwtService = require("../services/jwtService");

// SSO登录中间件
const ssoLogin = async (req, res, next) => {
	try {
		const { platform, returnUrl } = req.query;
		const token = req.header("Authorization")?.replace("Bearer ", "") || req.cookies?.token;

		if (!token) {
			return res.status(401).json({ error: "No authentication token provided" });
		}

		if (!platform) {
			return res.status(400).json({ error: "Platform parameter required" });
		}

		// 验证token
		const decoded = jwtService.verifyAccessToken(token);
		
		// 生成SSO token
		const ssoToken = ssoService.generateSSOToken(decoded.userId, decoded.identityId, platform);
		
		// 生成重定向URL
		const redirectUrl = ssoService.generatePlatformRedirectUrl(platform, ssoToken, {
			returnUrl,
		});

		res.json({
			success: true,
			redirectUrl,
			platform: ssoService.getPlatformConfig(platform),
		});
	} catch (error) {
		console.error("SSO login error:", error);
		res.status(401).json({ error: "Authentication failed" });
	}
};

// SSO回调验证中间件
const ssoCallback = async (req, res, next) => {
	try {
		const { token, platform, returnUrl } = req.query;

		if (!token) {
			return res.status(400).json({ error: "SSO token required" });
		}

		const ssoData = await ssoService.validateSSOToken(token);
		
		// 生成新的访问token
		const tokens = jwtService.generateTokenPair({
			userId: ssoData.user._id,
			identityId: ssoData.identity._id,
		});

		// 设置cookie
		res.cookie("token", tokens.accessToken, {
			httpOnly: true,
			secure: process.env.NODE_ENV === "production",
			domain: process.env.SESSION_DOMAIN,
			maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
			sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
		});

		req.ssoData = {
			user: ssoData.user,
			identity: ssoData.identity,
			tokens,
			platform,
			returnUrl,
		};

		next();
	} catch (error) {
		console.error("SSO callback error:", error);
		res.status(401).json({ error: "SSO authentication failed" });
	}
};

// 跨域会话同步中间件
const syncSession = redisClient => {
	return async (req, res, next) => {
		try {
			const { user, identity } = req;
			
			if (user && identity) {
				// 创建或更新跨域会话
				await ssoService.createCrossDomainSession(user._id, identity._id, redisClient);
			}

			next();
		} catch (error) {
			console.error("Session sync error:", error);
			// 不阻断流程，只记录错误
			next();
		}
	};
};

module.exports = {
	ssoLogin,
	ssoCallback,
	syncSession,
}; 