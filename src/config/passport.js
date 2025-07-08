const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const User = require("../models/User");
const Identity = require("../models/Identity");
const { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_CALLBACK_URL } = require("./index");

// Google OAuth Strategy
passport.use(
	new GoogleStrategy(
		{
			clientID: GOOGLE_CLIENT_ID,
			clientSecret: GOOGLE_CLIENT_SECRET,
			callbackURL: GOOGLE_CALLBACK_URL,
		},
		async (accessToken, refreshToken, profile, done) => {
			try {
				const googleId = profile.id;
				const email = profile.emails?.[0]?.value;
				const name = profile.displayName;
				const picture = profile.photos?.[0]?.value;

				// 查找现有身份
				let identity = await Identity.findOne({
					type: "google",
					identifier: googleId,
					chain: "google",
				}).populate("userId");

				let user;
				if (!identity) {
					// 创建新用户
					user = new User({
						name,
						avatar: picture,
					});
					await user.save();

					// 创建身份
					identity = new Identity({
						userId: user._id,
						type: "google",
						identifier: googleId,
						chain: "google",
						metadata: {
							google: {
								accessToken,
								refreshToken,
								profile: {
									name,
									email,
									picture,
								},
							},
						},
					});
					await identity.save();
					identity.userId = user;
				} else {
					// 更新现有身份的 token
					identity.metadata.google = {
						accessToken,
						refreshToken,
						profile: {
							name,
							email,
							picture,
						},
					};
					await identity.save();
					user = identity.userId;

					// 更新用户信息
					if (picture && !user.avatar) {
						user.avatar = picture;
						await user.save();
					}
				}

				return done(null, identity);
			} catch (error) {
				console.error("Google OAuth error:", error);
				return done(error, null);
			}
		}
	)
);

// Serialize/deserialize user for session
passport.serializeUser((identity, done) => {
	done(null, identity._id);
});

passport.deserializeUser(async (id, done) => {
	try {
		const identity = await Identity.findById(id).populate("userId");
		done(null, identity);
	} catch (error) {
		done(error, null);
	}
});

module.exports = passport; 