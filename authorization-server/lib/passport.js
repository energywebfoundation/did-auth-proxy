const passport = require('passport');
const { LoginStrategy } = require('passport-did-auth');
const { ExtractJwt, Strategy } = require('passport-jwt');


const RPC_URL = process.env.RPC_URL || 'https://volta-rpc.energyweb.org/';
console.log(`RPC_URL=${RPC_URL}`);

const CACHE_SERVER_URL = process.env.CACHE_SERVER_URL || 'https://identitycache-dev.energyweb.org/v1';
console.log(`CACHE_SERVER_URL=${CACHE_SERVER_URL}`);

const LOGIN_STRATEGY_NAME = 'did-login';
const JWT_SECRET = process.env.JWT_SECRET;

if (JWT_SECRET === undefined) {
    console.log('undefined JWT_SECRET env variable, exiting');
    process.exit(1);
}

const ACCEPTED_ROLES = process.env.ACCEPTED_ROLES ?
    process.env.ACCEPTED_ROLES.split(',').map(r => r.trim())
    : [];

console.log(`ACCEPTED_ROLES=${JSON.stringify(ACCEPTED_ROLES)}`);

const didLoginStrategy = new LoginStrategy({
    rpcUrl: RPC_URL,
    cacheServerUrl: CACHE_SERVER_URL,
    // accepted account to log into the cache server:
    privateKey: 'eab5e5ccb983fad7bf7f5cb6b475a7aea95eff0c6523291b0c0ae38b5855459c',
    name: LOGIN_STRATEGY_NAME,
    jwtSecret: JWT_SECRET,
    acceptedRoles: ACCEPTED_ROLES
});

const jwtStrategy = new Strategy({
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: JWT_SECRET
}, (payload, done) => {
    done(null, payload);
});

module.exports = {
    getPassport() {
        passport.use(didLoginStrategy);
        passport.use(jwtStrategy);

        passport.serializeUser(function (user, done) {
            done(null, user);
        });

        passport.deserializeUser(function (user, done) {
            done(null, user);
        });

        return {
            passport,
            LOGIN_STRATEGY_NAME
        };
    }
};
