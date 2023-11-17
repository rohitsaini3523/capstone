import { Router } from 'express';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { signUpBodyValidation, logInBodyValidation } from '../utils/validationSchema.js';
import User from '../models/User.js';
import UserToken from '../models/UserToken.js';
import bcrypt from 'bcrypt';
import generateTokens from '../utils/generateTokens.js';
import session from 'express-session';

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "928388932838-6n58nnred0umaetr2bm2t44511ucl0vv.apps.googleusercontent.com";
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "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";

const router = Router();

router.use(
	session({
		secret: process.env.SESSION_SECRET || '329e6bf2e50bb5280f06c96f43eba17cc170e9ea6941de6293c108b31ea49903af86c2cc08f924c87bbaca0fa95fbd9231d6822075c274536788c48b7095932c',
		resave: false,
		saveUninitialized: true,
	})
);
//homepage
router.get('/', (req, res) => {
	res.render('homepage');
});


// signup or register
router.get('/signUp', (req, res) => {
	res.render('register');
});

router.post("/signUp", async (req, res) => {
	try {
		const { error } = signUpBodyValidation(req.body);
		if (error)
			return res
				.status(400)
				.json({ error: true, message: error.details[0].message });

		const user = await User.findOne({ email: req.body.email });
		if (user)
			return res
				.status(400)
				.json({ error: true, message: "User with given email already exists" });

		const salt = await bcrypt.genSalt(Number(process.env.SALT));
		const hashPassword = await bcrypt.hash(req.body.password, salt);

		await new User({ ...req.body, password: hashPassword }).save();

		res
			.status(201)
			.json({ error: false, message: "Account created successfully" });
	} catch (err) {
		console.log(err);
		res.status(500).json({ error: true, message: "Internal Server Error" });
	}
});

// login 
router.get('/logIn', async (req, res) => {
	// Get cookie accessToken from browser
	const cookieHeader = req.headers['cookie'];
	if (!cookieHeader) {
		// Handle the case when the cookie header is not present
		return res.render('logIn');
	}
	else {
		const cookiesArray = cookieHeader.split('; ');
		// Extracting the values of specific cookies
		let accessToken, connectSid;

		for (const cookie of cookiesArray) {
			const [name, value] = cookie.split('=');

			if (name === 'accessToken') {
				accessToken = value;
			} else if (name === 'connect.sid') {
				connectSid = value;
			}
		}
		// Now accessToken and connectSid contain the values of the respective cookies
		/* console.log('accessToken:', accessToken);
		console.log('connect.sid:', connectSid);
		console.log('req.session:', req.session); */
		if (req.session && req.session.passport && req.session.passport.user) {
			// console.log('req.session.passport.user:', req.session.passport.user);
			// fetch the user from the mongodb usertoken collection
			const user = await User.findOne({ userName: req.session.passport.user });
			if (user) {
				const usertoken = await UserToken.findOne({ userId: user._id });
				if (usertoken && usertoken.token === accessToken) {
					// Check accessToken cookie and mongodb accessToken
					console.log("dashboard");
					return res.redirect('/dashboard');
				}
			}
		}
		else {
			// Clear the cookie if accessToken cookie and mongodb accessToken don't match or if not logged in
			res.clearCookie('accessToken');
			req.session.destroy();
			return res.render('logIn');
		}
	}
});

router.post("/logIn", async (req, res) => {
	try {
		const { email, password } = req.body;
		const { error } = logInBodyValidation(req.body);
		if (error) {
			return res.status(400).json({ error: true, message: error.details[0].message });
		}
		// console.log('email:', email);
		const user = await User.findOne({ email: email });
		console.log('user:', user);
		if (!user) {
			return res.status(401).json({ error: true, message: "Invalid email or password" });
		}
		const verifiedPassword = await bcrypt.compare(password, user.password);
		if (!verifiedPassword) {
			return res.status(401).json({ error: true, message: "Invalid email or password" });
		}

		const { accessToken } = await generateTokens(user);

		// Update the user tokens in the MongoDB database
		await UserToken.updateOne(
			{ userId: user._id },
			{
				$set: {
					token: accessToken,
				}
			}
		);

		req.session.user = user;
		// Set the accessToken cookie
		res.cookie('accessToken', accessToken, {
			httpOnly: true,
			maxAge: 1000 * 60 * 60 * 24 * 30,
		});
		// Redirect to /auth/google after successful login
		res.redirect('/auth/google');
	} catch (err) {
		console.log(err);
		res.status(500).json({ error: true, message: "Internal Server Error" });
	}
});
router.get('/auth/google/callback',
	passport.authenticate('google', { failureRedirect: '/logIn' }),
	(req, res) => {
		res.redirect('/dashboard');
	}
);

function ensureAuthenticated(req, res, next) {
	if (req.path === '/logIn') {
		return next();
	}

	if (req.session && req.session.user) {
		return next();
	}
	res.redirect('/logIn');
}

const storeReqMiddleware = (req, res, next) => {
	storeReqMiddleware.req = req;
	next();
};


//logout route
router.get('/logout', (req, res) => {
	req.session.destroy(err => {
		if (err) {
			return res.redirect('/dashboard');
		}

		res.clearCookie('sid');
		// Set headers to prevent caching
		res.setHeader('Cache-Control', 'no-cache, private, no-store, must-revalidate, max-stale=0, post-check=0, pre-check=0');
		res.redirect('/logIn');
	});
});

const checkaccessToken = async (userName) => {
	//check is user is present in usertoken collection
	const user = await User.findOne({ userName: userName });
	const usertoken = await UserToken.findOne({ userId: user._id });
	if (usertoken) {
		return usertoken.token;
	}
	else {
		return "0";
	}
};

router.get('/dashboard', storeReqMiddleware, async (req, res) => {
	if (storeReqMiddleware.req.session && storeReqMiddleware.req.session.passport && storeReqMiddleware.req.session.passport.user) {
		//check if correct accessToken is present in the cookie
		const accessToken = await checkaccessToken(storeReqMiddleware.req.session.passport.user);
		console.log('storeReqMiddleware.req.session.passport.user:', storeReqMiddleware);
		if (accessToken === req.headers.cookie.split('; ').find(cookie => cookie.startsWith('accessToken=')).split('=')[1]) {
			return res.render('dashboard');
		}
		else {
			// Clear the cookie if accessToken cookie and mongodb accessToken don't match or if not logged in
			res.clearCookie('accessToken');
			storeReqMiddleware.req.session.destroy();
			return res.redirect('/logIn');
		}
	}
	else {
		// Clear the cookie if accessToken cookie and mongodb accessToken don't match or if not logged in
		res.clearCookie('accessToken');
		storeReqMiddleware.req.session.destroy();
		return res.redirect('/logIn');
	}
});


router.get('/auth/google', ensureAuthenticated, storeReqMiddleware, passport.authenticate('google', { scope: ['profile', 'email'] }));
passport.use(
	new GoogleStrategy(
		{
			clientID: GOOGLE_CLIENT_ID,
			clientSecret: GOOGLE_CLIENT_SECRET,
			callbackURL: 'http://localhost:8080/auth/google/callback',
		},
		async (accessToken, refreshToken, profile, done) => {
			//fetch data from ensureAuthenticated
			try {
				const req = storeReqMiddleware.req;
				console.log('req', req.session.user);
				const profiledata = JSON.parse(profile._raw);
				// console.log('profiledata:', profile);
				const email = profiledata.email;
				// console.log('email:', email);
				// Check if the user already exists in your database
				// console.log('profile-email:', email);
				const updateduser = await User.findOne({ userName: req.session.user.userName });
				// console.log('Google user:', user);
				// if user.conncted_accounts does not contain googleId then append it
				let connectedAccounts = updateduser.connected_accouts;
				// console.log('connectedAccounts:', updateduser.email);
				if (!connectedAccounts.includes(email) && profile.id) {
					connectedAccounts.push(email);
					updateduser.connected_accouts = connectedAccounts;
					await updateduser.save();
				}
				console.log('Updated user:', updateduser);
				return done(null, updateduser);
			} catch (error) {
				return done(error);
			}
		}
	),
);
router.all('*', (req, res) => {
	res.redirect(''); // Redirect to the error page
});



export default router;
