const urlsafeBase64 = require('urlsafe-base64')
const mysql = require('mysql2/promise')

const conn = mysql.createPool({
  host: process.env.DATABASE_HOST,
  user: process.env.DATABASE_USER,
  password: process.env.DATABASE_PASSWORD,
  database: process.env.DATABASE_NAME,
  port: process.env.DATABASE_PORT,
  ssl: 'Amazon RDS'
})

exports.handler = (event, context, callback) => {
    const headerAuth = event.headers.Authorization;
    // this ensures immediate response as soon as callback was called,
    // without it then it waits for the connection to database to end
    // since it waits for empty event loop
    context.callbackWaitsForEmptyEventLoop = false;
    
    if (!headerAuth) {
        // if Authroization header was not present, reject
        console.log('Header not present')
        return callback(null, buildPolicy(event, '', 'Deny'))
    }

    if (!headerAuth.startsWith('Bearer')) {
        // Authorization header is too short
        console.log('too short')
        return callback(null, buildPolicy(event, '', 'Deny'))
    }

    const apikeyString = headerAuth.slice('Bearer'.length).trim()
    const apikey = urlsafeBase64.decode(apikeyString)

    // check if API key is valid
    conn.query('SELECT apikey_available(?) result', [apikey]).then(([result, _]) => {
        const apikey_available = result[0].result
        if (apikey_available === 1) {
            callback(null, buildPolicy(event, apikeyString, 'Allow'))
        } else {
            console.log('not available')
            callback(null, buildPolicy(event, apikeyString, 'Deny'))
        }
    }).catch((error) => {
        console.log(error);
        callback('Internal server error on authentication');
    });
};

function buildPolicy (event, apikey, type) {
    const policy = {
        principalId: 'apiuser_'+apikey,
        policyDocument: {
            Version: '2012-10-17',
                Statement: [
                {
                  Action: 'execute-api:Invoke',
                  Effect: type,
                  Resource: [event.methodArn]
                }
            ]
        }
    }
    
    return policy;
}