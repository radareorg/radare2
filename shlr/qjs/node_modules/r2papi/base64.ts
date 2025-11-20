export class Base64 {
    /**
     * Encode the given input string using base64
     *
     * @param {string} input string to encode
     * @returns {string} base64 encoded string
     */
    static encode(input: string): string {
        return b64(input);
    }
    /**
     * Decode the given base64 string into plain text
     *
     * @param {string} input string encoded in base64 format
     * @returns {string} base64 decoded string
     */
    static decode(input: string): string {
        return b64(input, true);
    }
}

export interface Base64Interface {
    (message: string, decode?: boolean): string;
}

export declare const b64: Base64Interface;
