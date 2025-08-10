const { Pool } = require("pg");
require("dotenv").config({ debug: process.env.DEBUG });

const dbUser = process.env.DB_USER;
const dbPass = process.env.DB_PASSWORD;
const dbHost = process.env.DB_HOST;
const dbPort = process.env.DB_PORT;
const dbName = process.env.DB_NAME;

const connectionString = `postgresql://${dbUser}:${dbPass}@${dbHost}:${dbPort}/${dbName}`;

const pool = new Pool({ connectionString });

exports.query = async (text, params) => {
	try {
		const result = await pool.query(text, params);
		return result;
	} catch (err) {
		console.error("Database error: ", {
			message: err.message,
			code: err.code,
			psqlText: text,
			params,
			stack: err.stack,
		});
		throw err;
	}
};
