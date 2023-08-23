const crypto = require("crypto");

class TuyaCipher {
    constructor(key, version, sessionKey = null) {
        this.sessionKey = sessionKey;
        this.key = key;
        this.version = version.toString();
        this.localNonce = "0123456789abcdef";
    }

    static encrypt_3_4(o) {
        /*
        Protocol notes are here: https://github.com/jasonacox/tinytuya/discussions/260
    */
        const { data, key } = { ...o };

        let payload = data;

        const cipher = crypto.createCipheriv("aes-128-ecb", key, null);
        cipher.setAutoPadding(false);
        const encrypted = cipher.update(payload);
        cipher.final();

        return encrypted;
    }

    static decrypt_3_4(o) {
        /*
        Protocol notes are here: https://github.com/jasonacox/tinytuya/discussions/260
    */

        const { data, key } = { ...o };

        let result;

        try {
            const decipher = crypto.createDecipheriv("aes-128-ecb", key, null);
            decipher.setAutoPadding(false);
            result = decipher.update(data);
            decipher.final();
            // Remove padding
            result = result.slice(0, result.length - result[result.length - 1]);
        } catch (_) {
            throw new Error("Decrypt failed");
        }

        // Try to parse data as JSON,
        // otherwise return as string.
        // 3.4 protocol
        // {"protocol":4,"t":1632405905,"data":{"dps":{"101":true},"cid":"00123456789abcde"}}
        try {
            if (result.indexOf(this.version) === 0) {
                result = result.slice(15);
            }

            const res = JSON.parse(result);
            if ("data" in res) {
                const resData = res.data;
                resData.t = res.t;
                return resData; // Or res.data // for compatibility with tuya-mqtt
            }

            return res;
        } catch (_) {
            return result;
        }
    }

    static hmac(data, key) {
        return crypto.createHmac("sha256", key).update(data, "utf8").digest(); // .digest('hex');
    }

    static hmacbuffer(data, key) {
        return crypto.createHmac("sha256", key).update(data).digest(); // .digest('hex');
    }

    static verifyHmac(data, key) {
        return false;
    }

    static getCRC32 = (buffer) => {
        let crc = 0xffffffff;
        for (let i = 0, len = buffer.length; i < len; i++)
            crc = crc32LookupTable[buffer[i] ^ (crc & 0xff)] ^ (crc >>> 8);
        return ~crc;
    };

    getKey() {
        return this.sessionKey === null ? this.key : this.sessionKey;
    }

    getLocalNonce() {
        return this.localNonce;
    }

    clearSessionKey() {
        this.sessionKey = null;
    }

    getSessionKey() {
        return this.sessionKey;
    }

    setSessionKey(o) {
        const { localNonce, remoteNonce, version, log } = { ...o };

        let success;

        if (version === "3.4") {
            let _sessionKey = Buffer.from(localNonce);

            for (let i = 0; i < localNonce.length; i++) {
                _sessionKey[i] = localNonce[i] ^ remoteNonce[i];
            }

            log.debug(
                "Unencrypted v3.4 session key: " + _sessionKey.toString("hex")
            );

            _sessionKey = TuyaCipher.encrypt_3_4({
                data: _sessionKey,
                key: this.key,
            });

            log.debug(
                "Encrypted v3.4 session key: " + _sessionKey.toString("hex")
            );

            this.sessionKey = _sessionKey;

            log.debug("Protocol 3.4: Initialization done");

            return (success = true);
        } else if (version === "3.5") {
            // TODO
        }
    }
}

const crc32LookupTable = [];
(() => {
    for (let i = 0; i < 256; i++) {
        let crc = i;
        for (let j = 8; j > 0; j--)
            crc = crc & 1 ? (crc >>> 1) ^ 3988292384 : crc >>> 1;
        crc32LookupTable.push(crc);
    }
})();

module.exports = TuyaCipher;
