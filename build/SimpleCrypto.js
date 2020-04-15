"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var crypto_js_1 = require("crypto-js");
var SimpleCrypto = /** @class */ (function () {
    function SimpleCrypto(_a) {
        var secret = _a.secret, _b = _a.iterations, iterations = _b === void 0 ? 100 : _b, _c = _a.keySize, keySize = _c === void 0 ? 256 : _c, _d = _a.algorithm, algorithm = _d === void 0 ? "PBKDF2" : _d, _e = _a.randomLength, randomLength = _e === void 0 ? 128 : _e;
        this._keySize = 256;
        this._iterations = 100;
        this._randomLength = 128;
        this._algorithm = crypto_js_1.PBKDF2;
        if (secret === void 0) {
            throw new Error('SimpleCrypto object MUST BE initialised with a SECRET KEY.');
        }
        this._secret = secret;
        this._keySize = keySize;
        this._randomLength = randomLength;
        this._iterations = iterations;
        this._defaultEncoder = crypto_js_1.enc.Utf8;
        switch (algorithm) {
            case "PBKDF2":
                this._algorithm = crypto_js_1.PBKDF2;
                break;
            case "SHA3":
                this._algorithm = crypto_js_1.SHA3;
                break;
            case "SHA224":
                this._algorithm = crypto_js_1.SHA224;
                break;
            case "SHA256":
                this._algorithm = crypto_js_1.SHA256;
                break;
            case "SHA384":
                this._algorithm = crypto_js_1.SHA384;
                break;
            case "SHA512":
                this._algorithm = crypto_js_1.SHA512;
                break;
            case "RIPEMD160":
                this._algorithm = crypto_js_1.RIPEMD160;
                break;
        }
    }
    SimpleCrypto.generateRandom = function (length, expectsWordArray) {
        if (length === void 0) { length = 128; }
        if (expectsWordArray === void 0) { expectsWordArray = false; }
        var random = crypto_js_1.lib.WordArray.random(length / 8);
        //@ts-ignore
        return expectsWordArray ? random : random.toString();
    };
    SimpleCrypto.prototype.encrypt = function (data) {
        if (data == void 0) {
            throw new Error('No data was attached to be encrypted. Encryption halted.');
        }
        var string = typeof data == "object"
            ? JSON.stringify(data)
            : typeof data == "string" || typeof data == "number" || typeof data == 'boolean'
                ? data.toString()
                : null;
        if (null === string) {
            throw new Error('Only object, string, number and boolean data types that can be encrypted.');
        }
        var salt = SimpleCrypto.generateRandom(this._randomLength, true);
        var key = this._algorithm(this._secret, salt, {
            keySize: this._keySize / 32,
            iterations: this._iterations
        });
        var initialVector = SimpleCrypto.generateRandom(this._randomLength, true);
        var encrypted = crypto_js_1.AES.encrypt(string, key, {
            iv: initialVector,
            padding: crypto_js_1.pad.Pkcs7,
            mode: crypto_js_1.mode.CBC
        });
        return salt.toString() + initialVector.toString() + encrypted.toString();
    };
    SimpleCrypto.prototype.decrypt = function (ciphered, expectsObject, encoder) {
        if (expectsObject === void 0) { expectsObject = false; }
        if (encoder === void 0) { encoder = this._defaultEncoder; }
        if (ciphered == void 0) {
            throw new Error('No encrypted string was attached to be decrypted. Decryption halted.');
        }
        var salt = crypto_js_1.enc.Hex.parse(ciphered.substr(0, 32));
        var initialVector = crypto_js_1.enc.Hex.parse(ciphered.substr(32, 32));
        var encrypted = ciphered.substring(64);
        var key = crypto_js_1.PBKDF2(this._secret, salt, {
            keySize: this._keySize / 32,
            iterations: this._iterations
        });
        var decrypted = crypto_js_1.AES.decrypt(encrypted, key, {
            iv: initialVector,
            padding: crypto_js_1.pad.Pkcs7,
            mode: crypto_js_1.mode.CBC
        });
        return expectsObject ? JSON.parse(decrypted.toString(encoder)) : decrypted.toString(encoder);
    };
    SimpleCrypto.prototype.encryptObject = function (object) {
        return this.encrypt(object);
    };
    SimpleCrypto.prototype.decryptObject = function (string) {
        var decrypted = this.decrypt(string, true);
        return typeof decrypted == 'object' ? decrypted : JSON.parse(decrypted);
    };
    SimpleCrypto.prototype.setSecret = function (secret) {
        this._secret = secret;
    };
    return SimpleCrypto;
}());
exports.SimpleCrypto = SimpleCrypto;
exports.default = SimpleCrypto;
//# sourceMappingURL=SimpleCrypto.js.map