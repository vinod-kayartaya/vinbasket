const jsonServer = require('json-server');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const fs = require('fs');

const server = jsonServer.create();
const router = jsonServer.router('./db.json');
// const router = jsonServer.router(require('./db.js')())
const middlewares = jsonServer.defaults();
const port = process.env.PORT || 8080;
const fsp = fs.promises;

server.use(bodyParser.json());
const SECRET_KEY = 'ASD2738ASDASD';

router.render = (req, resp) => {
    const re = /customers/;
    const re1 = /orders/;
    if (re.test(req.url)) {
        if (req.method === 'POST') {
            let { id, name } = resp.locals.data;
            let token = jwt.sign({ id, name }, SECRET_KEY);
            resp.json({ id, name, token });
        } else if (req.method === 'GET' || req.method === 'PUT') {
            // REMOVE PASSWORD
            delete resp.locals.data['password'];
            resp.json(resp.locals.data);
        }
        return;
    } else if (re1.test(req.url) && req.method === 'GET') {
        if ('customerId' in resp.locals.data) {
            let { customerId } = resp.locals.data;
            if (customerId.toString() !== req.query['customerId']) {
                resp.status(403).end(
                    'Invalid order id for the given customer id'
                );
                return;
            }
        }
    }
    resp.json(resp.locals.data);
};
// middleware for all incoming requests to handle CORS
server.use((req, resp, next) => {
    resp.set('Access-Control-Allow-Origin', '*');
    resp.set('Access-Control-Allow-Methods', 'GET,POST,OPTIONS,PUT');
    resp.set(
        'Access-Control-Allow-Headers',
        'Content-Type,Accept,Authorization'
    );
    next();
});

// a handler function for POST requests for the url '/customers'
server.options('/*', (req, resp) => {
    resp.end();
});

const verifyUser = async (email, password) => {
    let data = await fsp.readFile('./db.json', 'utf-8');
    data = JSON.parse(data);
    let { customers } = data;
    return customers.find((c) => c.email === email && c.password === password);
};

server.post('/login', async (req, resp) => {
    let { email, password } = req.body;
    if (!email || !password) {
        resp.end('Missing email/password');
        return;
    }

    let user = await verifyUser(email, password);

    if (user) {
        let { id, name } = user;
        let token = jwt.sign({ id, name }, SECRET_KEY);
        resp.json({ id, name, token });
        return;
    }
    resp.status(401).json('Invalid email/password');
});

server.use('/customers', async (req, resp, next) => {
    if (req.method === 'GET' || req.method === 'PUT') {
        let auth = req.headers.authorization;
        if (!auth) {
            resp.status(401).json('Authorization header is missing');
            return;
        }

        let [bearer, token] = auth.split(' ');
        if (bearer && bearer === 'Bearer') {
            try {
                let user = jwt.verify(token, SECRET_KEY);
                req.url += '/' + user.id.toString();

                if (req.method === 'PUT') {
                    // get current password from db.json
                    let data = await fsp.readFile('./db.json', 'utf-8');
                    data = JSON.parse(data);
                    let { customers } = data;
                    let cust = customers.find((c) => c.id === user.id);
                    let { password } = cust;
                    req.body.password = password;
                }
            } catch (e) {
                resp.status(403).json('Authorization token is not valid');
                return;
            }
        } else {
            resp.status(403).json('Authorization token is not valid');
            return;
        }
    }
    next();
});

server.use('/orders', async (req, resp, next) => {
    if (req.method === 'GET' || req.method === 'POST') {
        let auth = req.headers.authorization;
        if (!auth) {
            resp.status(401).json('Authorization header is missing');
            return;
        }

        let [bearer, token] = auth.split(' ');
        if (bearer && bearer === 'Bearer') {
            try {
                let user = jwt.verify(token, SECRET_KEY);
                if (req.method === 'GET') {
                    req.query['customerId'] = user.id.toString();
                } else if (req.method === 'POST') {
                    req.body.customerId = user.id.toString();
                }
            } catch (e) {
                resp.status(403).json('Authorization token is not valid');
                return;
            }
        } else {
            resp.status(403).json('Authorization token is not valid');
            return;
        }
    }
    next();
});

server.use(middlewares);
server.use(router);

server.listen(port, function () {});
