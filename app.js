import express from "express";
import { config } from "dotenv";
import bodyParser from 'body-parser';
import passport from "passport";
import session from 'express-session';
import dbConnect from "./config/dbConnect.js";
import authRoutes from "./routes/auth.js";
import refreshTokenRoutes from "./routes/refreshToken.js";
import userRoutes from "./routes/users.js";
import User from "./models/User.js";

const app = express();

config();
dbConnect();
app.set('view engine', 'ejs');
app.use(express.json());
app.use(session({
    secret: process.env.SESSION_SECRET, // Replace with a strong, random string
    resave: false,
    saveUninitialized: true,
}));
app.use(passport.initialize());
app.use(passport.session());

// Add the serializeUser and deserializeUser code here
passport.serializeUser((User, done) => {
    done(null, User.userName);
});

passport.deserializeUser(async (userName, done) => {
    try {
        const user = await User.findOne({ userName });
        done(null, user);
    } catch (error) {
        done(error, null);
    }
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use("/", authRoutes);
app.use("/refreshToken", refreshTokenRoutes);
app.use("/users", userRoutes);

const port = process.env.PORT || 8080;
app.listen(port, () => console.log(`Listening on port ${port}.`));
