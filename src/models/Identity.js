const mongoose = require("mongoose");

const identitySchema = new mongoose.Schema({
	userId: {
		type: mongoose.Schema.Types.ObjectId,
		ref: "User",
		required: true,
	},
	type: {
		type: String,
		enum: ["google", "telegram", "wallet"],
		required: true,
	},
	identifier: {
		type: String,
		required: true,
	},
	chain: {
		type: String,
		enum: ["ethereum", "bsc", "aptos", "flow", "google"],
		required: true,
	},
	metadata: {
		// Google OAuth metadata
		google: {
			accessToken: String,
			refreshToken: String,
			profile: {
				name: String,
				email: String,
				picture: String,
			},
		},
		// Telegram metadata
		telegram: {
			chatId: String,
			username: String,
			firstName: String,
			lastName: String,
		},
		// Wallet metadata
		wallet: {
			address: String,
			chain: {
				type: String,
				enum: ["ethereum", "bsc", "aptos", "flow"],
			},
			network: {
				type: String,
				enum: ["mainnet", "testnet"],
			},
			provider: {
				type: String,
				enum: ["metamask", "okx"],
			},
		},
	},
	createdAt: {
		type: Date,
		default: Date.now,
	},
	lastUsedAt: {
		type: Date,
		default: Date.now,
	},
	isActive: {
		type: Boolean,
		default: true,
	},
});

// Ensure unique combination of type and identifier
identitySchema.index({ type: 1, identifier: 1, chain: 1 }, { unique: true });

identitySchema.pre("save", function (next) {
	this.lastUsedAt = Date.now();
	next();
});

module.exports = mongoose.model("Identity", identitySchema); 