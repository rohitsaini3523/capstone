import mongoose from "mongoose";

const Schema = mongoose.Schema;

const userSchema = new Schema({
	userName: {
		type: String,
		required: true,
	},
	email: {
		type: String,
		required: true,
		unique: true,
	},
	password: {
		type: String,
		required: true,
	},
	roles: {
		type: [String],
		enum: ["user", "admin"],
		default: ["user"],
	},
	connected_accouts: {
		type: [String],
		default: [],
	},
});

const User = mongoose.model("User", userSchema);

export default User;
