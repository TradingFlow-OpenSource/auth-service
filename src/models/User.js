const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
	// 用户基本信息
	name: {
		type: String,
		trim: true,
	},
	avatar: {
		type: String,
	},

	// 时间戳
	createdAt: {
		type: Date,
		default: Date.now,
	},
	updatedAt: {
		type: Date,
		default: Date.now,
	},
});

userSchema.pre("save", function (next) {
	this.updatedAt = Date.now();
	next();
});

module.exports = mongoose.model("User", userSchema); 