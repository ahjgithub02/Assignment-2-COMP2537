require('dotenv').config();

const express = require('express');
const session = require('express-session');
const path = require('path');
const MongoStore = require('connect-mongo');
const { MongoClient, ServerApiVersion } = require('mongodb');
const bcrypt = require('bcrypt');
const port = process.env.PORT || 3000;
const app = express();
const Joi = require("joi");

const mongoURI = `mongodb+srv://${process.env.MONGODB_USER}:${encodeURIComponent(process.env.MONGODB_PASSWORD)}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(mongoURI, {
    serverApi: {
        deprecationErrors: true,
        version: ServerApiVersion.v1,
        strict: true
    }
});

async function start() {
    try {
        await client.connect();
        app.use(session({
            store: MongoStore.create({
                dbName: process.env.MONGODB_DATABASE,
                collectionName: 'sessions',
                client,
                ttl: 60 * 60,
                crypto: { secret: process.env.MONGODB_SESSION_SECRET }
            }),
            secret: process.env.NODE_SESSION_SECRET,
            cookie: { maxAge: 3600000 },
            saveUninitialized: false,
            resave: false
        }));

        // Middleware code
        app.set('view engine', 'ejs');
        app.use(express.urlencoded({ extended: true }));
        app.use(express.static(path.join(__dirname, 'public')));
        app.use(express.json());
        app.set('views', path.join(__dirname, 'views'));
        app.use('/css', express.static(path.join(__dirname, 'css')));

        app.get('/', (req, res) => {
            if (req.session.name) {
                return res.render('index', {
                    loggedInConfirmation: true,
                    name: req.session.name
                });
            }
            res.render('index', { loggedInConfirmation: false });
        });

        app.get('/signup', (req, res) => {
            res.render('signup');
        });

        app.post('/signupSubmit', async (req, res) => {
            const signupSchema = Joi.object({
                name: Joi.string().max(30).required(),
                email: Joi.string().email().required(),
                password: Joi.string().min(6).required()
            });

            try {
                const { error, value } = signupSchema.validate(req.body);
                if (error) {
                    return res.send(`<p>${error.message}</p><a href="/signup">Try again</a>`);
                }
                const { name, email, password } = value;
                const hashcode = await bcrypt.hash(password, 10);
                await client.db().collection('users')
                    .insertOne({ 
                        name, 
                        email, 
                        password: hashcode });
                req.session.name = name;
                res.redirect('/members');

            } catch (err) {
                console.error(err);
                res.status(500).send("An unexpected error occurred during registration. Please try again later.");
            }
        });

        app.get('/login', (req, res) => {
            res.render('login');
        });

        app.post('/loginSubmit', async (req, res) => {
            const loginSchema = Joi.object({
                email: Joi.string().email().required(),
                password: Joi.string().required()
            });

            const { error, value } = loginSchema.validate(req.body);
            if (error) {
                return res.send(`<p>${error.message}</p><a href="/login">Try again</a>`);
            }

            try {
                const user = await client.db().collection('users').findOne({ email: value.email });
                if (!user) {
                    return res.send('<p>Invalid email/password combination</p><a href="/login">Try again</a>');
                }

                const passwordMatch = await bcrypt.compare(value.password, user.password);
                if (!passwordMatch) {
                    return res.send('<p>Invalid email/password combination</p><a href="/login">Try again</a>');
                }

                req.session.name = user.name;
                res.redirect('/members');
            } catch (err) {
                console.error(err);
                res.status(500).send("An unexpected error occurred during login. Please try again later.");
            }
        });

        app.get('/members', (req, res) => {
            if (!req.session.name) {
                return res.redirect('/');
            }

            // Select one random image filename
            const images = ['beautiful_squidward.jpg', 'chicken_spongebob.webp', 'imagination.webp'];
            const randomImage = images[Math.floor(Math.random() * images.length)];

            // Render the members page with user name and random image
            res.render('members', {
                user: req.session.name,
                randomImage: randomImage
            });
        });

        app.get('/logout', (req, res) => {
            req.session.destroy(err => {
                if (err) {
                    console.log('Logout error:', err);
                    return res.status(500).send("An error has occurred. Couldn't log you out.");
                }
                res.redirect('/');
            });
        });

        app.use((req, res) => {
            res.status(404).send("Page not found - 404");
        });

        app.listen(port, () => {
            console.log(`Server running on http://localhost:${port}`);
        });
    }
    catch (err) {
        console.error('Failed to start', err);
    }
}

start();