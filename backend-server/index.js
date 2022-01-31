const express = require('express');
const bodyParser = require('body-parser');

const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use((req, res, next) => {
    console.log(`incoming request: ${JSON.stringify({ url: req.url, headers: req.headers, method: req.method, body: req.body })}`);
    next();
});

app.use(((req, res) => {
    res.send({ message: 'backend response', timestamp: new Date().toISOString() });
}));

const server = app.listen(80);

server.on('listening', () => {
    console.log(`backend server listening`);
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
