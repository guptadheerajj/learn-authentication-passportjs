# Express Template

Created this clean and well-configured Express.js template with ESLint, Prettier, and PostgreSQL database integration.

### File Structure

```
├── app.js                  # Main application file
├── package.json            # Dependencies and scripts
├── package-lock.json       # Dependency lockfile
├── .gitignore              # Git ignore rules
├── .eslintignore           # ESLint ignore rules
├── eslint.config.mjs       # ESLint configuration
├── .prettierrc             # Prettier configuration
├── .prettierignore         # Files to ignore for formatting
├── README.md               # This file
│
├── controllers/           # Request handlers and business logic
│
│
├── db/                    # Database configuration and utilities
│   ├── pool.js              # PostgreSQL connection pool
│   ├── queries.js           # Database query functions
│   └── populatedb.js        # Database seeding script
│
├── errors/                # Custom error handlers
│
│
├── public/                # Static assets (CSS, JS, images)
│
│
├── routes/                # Express route definitions
│
│
└── views/                 # EJS templates
	└── partials/            # Reusable template components

```
