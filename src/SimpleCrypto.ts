import {
	lib,
	PBKDF2,
	SHA3,
	SHA224,
	SHA256,
	SHA384,
	SHA512,
	RIPEMD160,

	AES,
	pad,
	mode,
	enc,
	Hashes,
} from 'crypto-js';
import { WordArray, Encoder } from 'crypto-js';

type TAlgorithms = "SHA256" | "SHA224" | "SHA512" | "SHA384" | "SHA3" | "RIPEMD160" | "PBKDF2";

interface IConstructorParams {
	secret: string
	keySize?: 128 | 192 | 256
	randomLength?: number
	iterations?: number
	algorithm?: TAlgorithms
}

export class SimpleCrypto {

	private _secret: string;
	private _keySize: 128 | 192 | 256 = 256;
	private _iterations: number = 100;
	private _randomLength: number = 128;
	private _defaultEncoder: Encoder;
	private _algorithm: any = PBKDF2;

	public constructor({secret, iterations = 100, keySize = 256, algorithm = "PBKDF2", randomLength = 128}: IConstructorParams) {
		if (secret === void 0) {
			throw new Error('SimpleCrypto object MUST BE initialised with a SECRET KEY.');
		}
		this._secret = secret;
		this._keySize = keySize;
		this._randomLength = randomLength;
		this._iterations = iterations;
		this._defaultEncoder = enc.Utf8;
		switch(algorithm){
			case "PBKDF2":
				this._algorithm = PBKDF2;
				break
			case "SHA3":
				this._algorithm = SHA3;
				break;
			case "SHA224":
				this._algorithm = SHA224;
				break;
			case "SHA256":
				this._algorithm = SHA256;
				break;
			case "SHA384":
				this._algorithm = SHA384;
				break;
			case "SHA512":
				this._algorithm = SHA512;
				break;
			case "RIPEMD160":
				this._algorithm = RIPEMD160;
				break;
		}
	}

	public static generateRandom(
		length: number = 128,
		expectsWordArray: boolean = false
	): string | WordArray {
		const random = lib.WordArray.random(length/8);
		//@ts-ignore
		return expectsWordArray ? random : random.toString();
	}

	public encrypt(data: object | string | number | boolean): string {
		if (data == void 0) {
			throw new Error('No data was attached to be encrypted. Encryption halted.');
		}
		const string: string = typeof data == "object"
			? JSON.stringify(data)
			: typeof data == "string" || typeof data == "number" || typeof data == 'boolean'
				? data.toString()
				: null;
		if (null === string) {
			throw new Error('Only object, string, number and boolean data types that can be encrypted.');
		}
		const salt: string | WordArray = SimpleCrypto.generateRandom(this._randomLength, true);
		const key: WordArray = this._algorithm(this._secret, salt, {
			keySize: this._keySize / 32,
			iterations: this._iterations
		});
		const initialVector: string | WordArray = SimpleCrypto.generateRandom(this._randomLength, true);
		const encrypted: WordArray = AES.encrypt(string, key, {
			iv: initialVector as string,
			padding: pad.Pkcs7,
			mode: mode.CBC
		});
		return salt.toString() + initialVector.toString() + encrypted.toString();
	}

	public decrypt(
		ciphered: string,
		expectsObject: boolean = false,
		encoder: Encoder = this._defaultEncoder
	): string | object {
		if (ciphered == void 0) {
			throw new Error('No encrypted string was attached to be decrypted. Decryption halted.');
		}
		const salt: string = enc.Hex.parse(ciphered.substr(0, 32));
		const initialVector: string = enc.Hex.parse(ciphered.substr(32, 32));
		const encrypted: string = ciphered.substring(64);
		const key: string | WordArray = PBKDF2(this._secret, salt, {
			keySize: this._keySize / 32,
			iterations: this._iterations
		});
		const decrypted = AES.decrypt(encrypted, key, {
			iv: initialVector,
			padding: pad.Pkcs7,
			mode: mode.CBC
		});
		return expectsObject ? JSON.parse(decrypted.toString(encoder)) : decrypted.toString(encoder);
	}

	public encryptObject(object: object): string {
		return this.encrypt(object);
	}

	public decryptObject(string: string): object {
		const decrypted: string | object = this.decrypt(string, true);
		return typeof decrypted == 'object' ? decrypted : JSON.parse(decrypted);
	}

	public setSecret(secret: string): void {
		this._secret = secret;
	}

}

export default SimpleCrypto;
