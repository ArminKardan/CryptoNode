const crypto = require('crypto');

function encrypt(input, password) {

    const salt = crypto.randomBytes(16);

    const key = crypto.pbkdf2Sync(password, salt, 1000, 32, 'sha1');

    const iv = crypto.randomBytes(16);

    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);

    let encrypted = cipher.update(input);

    encrypted = Buffer.concat([encrypted, cipher.final()]);

    return Buffer.concat([salt, iv, encrypted]); 
}

function decrypt(input, password) {

    const salt = input.slice(0, 16);

    const iv = input.slice(16, 32);

    const encryptedData = input.slice(32);

    const key = crypto.pbkdf2Sync(password, salt, 1000, 32, 'sha1');

    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);

    let decrypted = decipher.update(encryptedData);

    decrypted = Buffer.concat([decrypted, decipher.final()]);

    return decrypted;
}


// console.log(encrypt(Buffer.from("hiiiii"),"XXXX").toString('base64'))
console.log(decrypt(Buffer.from("2Yh3/VbzTj5ycG0C/kEuF44cQqdR4Y8W5T0gyBfmsv2QB0na8JlTIixbUizOlL6pX4BBZ9WuUMak114IEu/Uaw",'base64'),"XXXX").toString('utf8'))

