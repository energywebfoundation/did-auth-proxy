require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');

const { passport, LOGIN_STRATEGY_NAME } = require('./lib/passport').getPassport();

const app = express();

app.use(passport.initialize({}));

app.use(bodyParser.json());

app.use((req, res, next) => {
    console.log(`incoming request: ${JSON.stringify({ url: req.url, headers: req.headers, method: req.method, body: req.body })}`);
    next();
});

app.post('/login', passport.authenticate(LOGIN_STRATEGY_NAME), (req, res) => {
    console.log(`user logged in successfully`);
    res.send({ accessToken: req.user });
});

app.get('/token-introspection', passport.authenticate('jwt'), (req, res) => {
    console.log(`successful token introspection`)
    console.log(`access token payload: ${JSON.stringify(req.user)}`);
    console.log(`did: ${JSON.stringify(req.user.did)}`);
    console.log(`did roles: ${JSON.stringify(req.user.verifiedRoles)}`);
    res.status(200).send();
});

const server = app.listen(80);

server.on('listening', () => {
    console.log(`authorization server listening`);
});


// below required for docker to not wait for container stopped
const signals = {
    'SIGHUP': 1,
    'SIGINT': 2,
    'SIGTERM': 15
};

Object.keys(signals).forEach((signal) => {
    process.on(signal, () => {
        console.log(`process received a ${signal} (${signals[signal]}) signal`);
        console.log(`exiting with signal ${signals[signal]}`);
        process.exit(128 + signals[signal]);
    });
});
