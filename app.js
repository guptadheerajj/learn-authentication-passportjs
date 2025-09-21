const path = require("path");
require("dotenv").config({ debug: true });
const { Pool } = require("pg");
const express = require("express");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;

const dbUser = process.env.DB_USER;
const dbPass = process.env.DB_PASSWORD;
const dbHost = process.env.DB_HOST;
const dbPort = process.env.DB_PORT;
const dbName = process.env.DB_NAME;

const connectionString = `postgresql://${dbUser}:${dbPass}@${dbHost}:${dbPort}/${dbName}`;

const pool = new Pool({ connectionString });

const app = express();
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(session({ secret: "cats", resave: false, saveUninitialized: false }));
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

passport.use(
	new LocalStrategy(async function (username, password, done) {
		try {
			const { rows } = await pool.query(
				"SELECT * FROM users WHERE username = $1",
				[username],
			);
			const user = rows[0];

			if (!user) {
				return done(null, false, {
					message: "Incorrect username or password",
				});
			}

			const matchPassword = await bcrypt.compare(password, user.password);

			if (!matchPassword) {
				return done(null, false, {
					message: "Incorrect username or password",
				});
			}

			done(null, user);
		} catch (err) {
			done(err);
		}
	}),
);

passport.serializeUser((user, done) => {
	done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
	try {
		const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [
			id,
		]);
		const user = rows[0];

		done(null, user);
	} catch (err) {
		done(err);
	}
});

app.use((req, res, next) => {
	res.locals.currentUser = req.user;
	next();
});

app.get("/log-out", (req, res, next) => {
	req.logOut(err => {
		if (err) return next(err);

		res.redirect("/");
	});
});

app.get("/", (req, res) => {
	res.render("index", { user: res.locals.currentUser });
});

app.get("/sign-up", (req, res) => {
	res.render("sign-up-form");
});

app.post("/sign-up", async (req, res, next) => {
	const { username, password } = req.body;
	const hashedPassword = await bcrypt.hash(password, 10);
	try {
		await pool.query(
			"INSERT INTO users (username, password) VALUES ($1, $2);",
			[username, hashedPassword],
		);
		console.log(`User with username: ${username} stored successfully`);
		res.redirect("/");
	} catch (error) {
		next(error);
	}
});

app.post(
	"/log-in",
	passport.authenticate("local", {
		successRedirect: "/",
		failureRedirect: "/",
	}),
);

app.listen(3000, error => {
	if (error) {
		throw error;
	}
	console.log("app listening on port 3000!");
});
