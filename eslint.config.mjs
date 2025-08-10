import js from '@eslint/js';
import globals from 'globals';
import json from '@eslint/json';
import markdown from '@eslint/markdown';
import css from '@eslint/css';
import prettierConfig from 'eslint-config-prettier';

export default [
	// Global ignores
	{
		ignores: [
			'node_modules/**',
			'build/**',
			'dist/**',
			'coverage/**',
			'.nyc_output/**',
			'*.log',
			'logs/**',
			'.DS_Store',
			'Thumbs.db',
			'.env*',
			'.vscode/**',
			'.idea/**',
			'*.swp',
			'*.swo',
			'*~',
			'package-lock.json',
			'yarn.lock',
			'pnpm-lock.yaml',
		],
	},
	// JavaScript files
	{
		files: ['**/*.{js,mjs,cjs}'],
		languageOptions: {
			globals: { ...globals.browser, ...globals.node },
		},
		rules: {
			...js.configs.recommended.rules,
			'no-unused-vars': ['error', { argsIgnorePattern: '^next$' }],
		},
	},
	// CommonJS specific files
	{
		files: ['**/*.js'],
		languageOptions: {
			sourceType: 'commonjs',
		},
	},
	// JSON files
	{
		files: ['**/*.json'],
		plugins: { json },
		language: 'json/json',
		rules: {
			...json.configs.recommended.rules,
		},
	},
	// JSONC files
	{
		files: ['**/*.jsonc'],
		plugins: { json },
		language: 'json/jsonc',
		rules: {
			...json.configs.recommended.rules,
		},
	},
	// JSON5 files
	{
		files: ['**/*.json5'],
		plugins: { json },
		language: 'json/json5',
		rules: {
			...json.configs.recommended.rules,
		},
	},
	// Markdown files
	{
		files: ['**/*.md'],
		plugins: { markdown },
		language: 'markdown/gfm',
		rules: {
			...markdown.configs.recommended.rules,
		},
	},
	// CSS files
	{
		files: ['**/*.css'],
		plugins: { css },
		language: 'css/css',
		rules: {
			...css.configs.recommended.rules,
		},
	},
	// Prettier config to disable conflicting rules
	prettierConfig,
];
