const crypto = require('crypto');
const sessionSecret = crypto.randomBytes(64).toString('hex');
console.log(sessionSecret);
