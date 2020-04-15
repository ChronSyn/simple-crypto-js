import { WordArray, Encoder } from 'crypto-js';
declare type TAlgorithms = "SHA256" | "SHA224" | "SHA512" | "SHA384" | "SHA3" | "RIPEMD160" | "PBKDF2";
interface IConstructorParams {
    secret: string;
    keySize?: 128 | 192 | 256;
    randomLength?: number;
    iterations?: number;
    algorithm?: TAlgorithms;
}
export declare class SimpleCrypto {
    private _secret;
    private _keySize;
    private _iterations;
    private _randomLength;
    private _defaultEncoder;
    private _algorithm;
    constructor({ secret, iterations, keySize, algorithm, randomLength }: IConstructorParams);
    static generateRandom(length?: number, expectsWordArray?: boolean): string | WordArray;
    encrypt(data: object | string | number | boolean): string;
    decrypt(ciphered: string, expectsObject?: boolean, encoder?: Encoder): string | object;
    encryptObject(object: object): string;
    decryptObject(string: string): object;
    setSecret(secret: string): void;
}
export default SimpleCrypto;
