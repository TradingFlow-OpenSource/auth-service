const express = require("express");
const passport = require("passport");
const jwtService = require("../services/jwtService");
const ssoService = require("../services/ssoService");
const User = require("../models/User");
const Identity = require("../models/Identity");
const { auth, optAuth, validateCrossDomainSession } = require("../middleware/auth");
const { ssoLogin, ssoCallback } = require("../middleware/sso");
const { ALLOWED_ORIGINS } = require("../config");

const router = express.Router();

// 跨域会话验证路由
router.get("/session/validate", validateCrossDomainSession, async (req, res) => {
	try {
		const user = await User.findById(req.user._id);
		const identities = await Identity.find({ userId: req.user._id });

		res.json({
			success: true,
			user,
			identities,
			identity: req.identity,
		});
	} catch (error) {
		res.status(500).json({ error: "Failed to validate session" });
	}
});

// 获取当前用户信息
router.get("/me", auth, async (req, res) => {
	try {
		const user = await User.findById(req.user._id);
		const identities = await Identity.find({ userId: req.user._id });

		res.json({
			user,
			identities,
			identity: req.identity,
		});
	} catch (error) {
		res.status(500).json({ error: "Failed to fetch user data" });
	}
});

// Google OAuth 认证
router.get("/google", (req, res, next) => {
	const origin = req.query.origin;
	if (origin && ALLOWED_ORIGINS.includes(origin)) {
		req.session.authOrigin = origin;
	}
	passport.authenticate("google", {
		scope: ["profile", "email"],
	})(req, res, next);
});

router.get("/google/callback", passport.authenticate("google", { session: false }), async (req, res) => {
	try {
		const identity = req.user;
		const tokens = jwtService.generateTokenPair({
			identityId: identity._id,
			userId: identity.userId._id,
		});

		// 设置跨域cookie
		res.cookie("token", tokens.accessToken, {
			httpOnly: true,
			secure: process.env.NODE_ENV === "production",
			domain: process.env.SESSION_DOMAIN,
			maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
		});

		// 重定向到原始域名
		const origin = req.session.authOrigin || ALLOWED_ORIGINS[0];
		const redirectUrl = new URL("/auth/callback", origin);
		redirectUrl.searchParams.set("token", tokens.accessToken);
		redirectUrl.searchParams.set("type", "google");

		res.redirect(redirectUrl.toString());
	} catch (error) {
		console.error("Google auth callback error:", error);
		res.redirect("/auth/error");
	}
});

// Telegram 认证
router.post("/telegram", async (req, res) => {
	try {
		const { id, first_name, last_name, username, auth_date, hash } = req.body;

		// TODO: 验证 Telegram 数据
		// 这里应该验证 hash 和 auth_date

		const identifier = id.toString();
		let identity = await Identity.findOne({
			type: "telegram",
			identifier,
			chain: "google", // Telegram 使用 google chain
		}).populate("userId");

		let user;
		if (!identity) {
			// 创建新用户
			user = new User({
				name: first_name + (last_name ? ` ${last_name}` : ""),
			});
			await user.save();

			// 创建身份
			identity = new Identity({
				userId: user._id,
				type: "telegram",
				identifier,
				chain: "google",
				metadata: {
					telegram: {
						chatId: id.toString(),
						username,
						firstName: first_name,
						lastName: last_name,
					},
				},
			});
			await identity.save();
			identity.userId = user;
		} else {
			user = identity.userId;
		}

		const tokens = jwtService.generateTokenPair({
			identityId: identity._id,
			userId: user._id,
		});

		res.json({
			success: true,
			token: tokens.accessToken,
			refreshToken: tokens.refreshToken,
			user,
			identity,
		});
	} catch (error) {
		console.error("Telegram auth error:", error);
		res.status(500).json({ error: "Authentication failed" });
	}
});

// 钱包认证 - 获取 nonce
router.get("/wallet/nonce", async (req, res) => {
	try {
		const { address, chain = "ethereum" } = req.query;

		if (!address) {
			return res.status(400).json({ error: "Address is required" });
		}

		// 生成随机 nonce
		const nonce = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);

		// 存储 nonce 到 Redis (临时存储)
		// TODO: 实现 Redis 存储逻辑

		const message = `Please sign this message to authenticate with TradingFlow.\n\nNonce: ${nonce}\nTimestamp: ${Date.now()}`;

		res.json({
			nonce,
			message,
		});
	} catch (error) {
		console.error("Nonce generation error:", error);
		res.status(500).json({ error: "Failed to generate nonce" });
	}
});

// 钱包认证 - 验证签名
router.post("/wallet/verify", optAuth, async (req, res) => {
	try {
		const { address, pubKey = "", signature, walletType, chain = "ethereum", nonce } = req.body;

		if (!address || !signature || !walletType || !nonce) {
			return res.status(400).json({ error: "Missing required parameters" });
		}

		// TODO: 验证签名
		// 这里需要根据 chain 类型实现不同的签名验证逻辑

		const identifier = address.toLowerCase();

		if (req.user) {
			// 已登录用户 - 绑定新的钱包身份
			let identity = await Identity.findOne({
				type: "wallet",
				identifier,
				chain,
			});

			if (identity) {
				return res.status(400).json({ error: "Wallet already bound to another account" });
			}

			identity = new Identity({
				userId: req.user._id,
				type: "wallet",
				identifier,
				chain,
				metadata: {
					wallet: {
						address: identifier,
						provider: walletType,
						chain,
						network: "mainnet",
					},
				},
			});
			await identity.save();

			const tokens = jwtService.generateTokenPair({
				identityId: identity._id,
				userId: req.user._id,
			});

			res.json({
				success: true,
				token: tokens.accessToken,
				user: req.user,
				identity,
				bound: true,
			});
		} else {
			// 未登录用户 - 创建新用户或登录现有用户
			let identity = await Identity.findOne({
				type: "wallet",
				identifier,
				chain,
			}).populate("userId");

			let user;
			if (!identity) {
				// 创建新用户
				user = new User({
					name: `User ${address.substring(0, 6)}...${address.substring(address.length - 4)}`,
				});
				await user.save();

				// 创建身份
				identity = new Identity({
					userId: user._id,
					type: "wallet",
					identifier,
					chain,
					metadata: {
						wallet: {
							address: identifier,
							provider: walletType,
							chain,
							network: "mainnet",
						},
					},
				});
				await identity.save();
				identity.userId = user;
			} else {
				user = identity.userId;
			}

			const tokens = jwtService.generateTokenPair({
				identityId: identity._id,
				userId: user._id,
			});

			res.json({
				success: true,
				token: tokens.accessToken,
				refreshToken: tokens.refreshToken,
				user,
				identity,
				bound: false,
			});
		}
	} catch (error) {
		console.error("Wallet verification error:", error);
		res.status(500).json({ error: "Authentication failed" });
	}
});

// 刷新 token
router.post("/refresh", async (req, res) => {
	try {
		const { refreshToken } = req.body;

		if (!refreshToken) {
			return res.status(400).json({ error: "Refresh token required" });
		}

		const decoded = jwtService.verifyRefreshToken(refreshToken);
		const identity = await Identity.findById(decoded.identityId).populate("userId");

		if (!identity) {
			return res.status(401).json({ error: "Invalid refresh token" });
		}

		const tokens = jwtService.generateTokenPair({
			identityId: identity._id,
			userId: identity.userId._id,
		});

		res.json({
			success: true,
			accessToken: tokens.accessToken,
			refreshToken: tokens.refreshToken,
		});
	} catch (error) {
		console.error("Token refresh error:", error);
		res.status(401).json({ error: "Invalid refresh token" });
	}
});

// 注销
router.post("/logout", auth, async (req, res) => {
	try {
		// 清除 cookie
		res.clearCookie("token", {
			domain: process.env.SESSION_DOMAIN,
		});

		res.json({ success: true, message: "Logged out successfully" });
	} catch (error) {
		console.error("Logout error:", error);
		res.status(500).json({ error: "Logout failed" });
	}
});

// SSO 登录端点
router.get("/sso/login", ssoLogin);

// SSO 回调端点
router.get("/sso/callback", ssoCallback, (req, res) => {
	const { user, tokens, platform, returnUrl } = req.ssoData;
	
	// 如果有返回URL，重定向到指定页面
	if (returnUrl) {
		return res.redirect(returnUrl);
	}

	// 返回用户信息和token
	res.json({
		success: true,
		user,
		token: tokens.accessToken,
		refreshToken: tokens.refreshToken,
		platform,
	});
});

// 平台间跳转端点
router.get("/sso/:platform", async (req, res) => {
	try {
		const { platform } = req.params;
		const { returnUrl } = req.query;
		const token = req.header("Authorization")?.replace("Bearer ", "") || req.cookies?.token;

		if (!token) {
			return res.status(401).json({ error: "Authentication required" });
		}

		const decoded = jwtService.verifyAccessToken(token);
		
		// 生成SSO token
		const ssoToken = ssoService.generateSSOToken(decoded.userId, decoded.identityId, platform);
		
		// 生成重定向URL
		const redirectUrl = ssoService.generatePlatformRedirectUrl(platform, ssoToken, {
			returnUrl,
		});

		res.redirect(redirectUrl);
	} catch (error) {
		console.error("SSO redirect error:", error);
		res.status(401).json({ error: "Authentication failed" });
	}
});

module.exports = router; 