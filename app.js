const express = require('express'); 

const morgan = require('morgan'); // work as middleware

const rateLimit = require('express-rate-limit'); // block ip when it reaches to limit

const helmet = require('helmet'); 

const mongoSanitize = require('express-mongo-sanitize');

const bodyParser = require('body-parser');

const xss = require('xss');

const cors = require('cors')

const app = express();

app.use(express.urlencoded({
    extended: true,
}));

app.use(mongoSanitize());

// app.use(xss());

app.use(cors({
    origin: '*',
    methods: ['GET', 'PATCH', 'POST', 'DELETE', 'PUT'],
    credentials: true,
}))

app.use(express.json({limit: '100kb'}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));

app.use(helmet());

if(process.env.NODE_ENV === 'development') {
    app.use(morgan('dev'));
}

const limiter = rateLimit({
    max: 3000,
    WindowMs: 60 * 60 * 1000, // in one hour
    message: 'Too many request from this IP, Please try again in one hour.'
});

app.use('/tawk', limiter);



module.exports = app;