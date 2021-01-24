const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const port = process.env.PORT || 3001;
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.listen(port);
console.log('Server started! At http://localhost:' + port);

app.post('/services/oauth2/token', (req, res) => {
    const token = parseJwt(req.body.assertion);
    console.log(`JWT: ${token.iss}, ${token.sub}, ${token.aud}`);
    dispatcher(token, req, res);
});

const parseJwt = (token) => {
    var base64Url = token.split('.')[1];
    var base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    var jsonPayload = decodeURIComponent(Buffer.from(base64, 'base64').toString()
        .split('').map(function(c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));

    return JSON.parse(jsonPayload);
};

const dispatcher = (token, req, res) => {
    switch (token.sub) {
        case 'user-error':
            handleError401(req, res);
            break;
        default:
            handleSuccess(req, res);
    }
};

const handleSuccess = (req, res) => {
    res.status(200).send({
        id: '1',
        issued_at: `${Date.now()}`,
        instance_url: 'https://my-org.salesforce.com',
        signature: 'signature',
        access_token: 'jhjhdjashdjashdjashdjashdjasdhsjadhasjdhj'
    });    
};

const handleError401 = (req, res) => {
    res.status(401).send({
        error: 'invalid_grant',
        error_description: 'an error description'
    });
};