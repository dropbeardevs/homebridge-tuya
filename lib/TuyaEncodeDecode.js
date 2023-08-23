const TuyaConst = require("./TuyaConst");
const TuyaCipher = require("./TuyaCipher");

class TuyaEncodeDecode {
    constructor() {}

    static encode_3_4(o) {
        const { cmd, data, key, counter, log } = { ...o };

        let payload = data;

        if (!payload) {
            payload = new String();
        }

        log.debug(
            "[Tuya DEBUG] v3.4 Unencrypted Payload: " + payload.toString("hex")
        );

        // Convert Objects to Strings, Strings to Buffers
        if (!(payload instanceof Buffer)) {
            if (typeof payload !== "string") {
                payload = JSON.stringify(payload);
            }

            payload = Buffer.from(payload);
        }

        if (
            cmd !== TuyaConst.CommandType.DP_QUERY &&
            cmd !== TuyaConst.CommandType.HEART_BEAT &&
            cmd !== TuyaConst.CommandType.DP_QUERY_NEW &&
            cmd !== TuyaConst.CommandType.SESS_KEY_NEG_START &&
            cmd !== TuyaConst.CommandType.SESS_KEY_NEG_FINISH &&
            cmd !== TuyaConst.CommandType.DP_REFRESH
        ) {
            // Add 3.4 header
            const buffer = Buffer.alloc(payloadLength + 15);
            Buffer.from("3.4").copy(buffer, 0);
            payload.copy(buffer, 15);
            payload = buffer;
        }

        const padding = 0x10 - (payload.length & 0xf);
        const buf34 = Buffer.alloc(payload.length + padding, padding);

        payload.copy(buf34);
        payload = buf34;

        payload = TuyaCipher.encrypt_3_4({
            data: payload,
            key: key,
        });

        log.debug(
            "[Tuya DEBUG] v3.4 Encrypted Payload: " + payload.toString("hex")
        );

        // Allocate buffer with room for payload + 52 bytes for
        // prefix, sequence, command, length, crc, and suffix
        const buffer = Buffer.alloc(payload.length + 52);

        // Add prefix, command, and length
        buffer.writeUInt32BE(0x000055aa, 0);
        buffer.writeUInt32BE(cmd, 8);
        buffer.writeUInt32BE(payload.length + 0x24, 12);
        buffer.writeUInt32BE(counter, 4);

        // Add payload, checksum, and suffix
        payload.copy(buffer, 16);

        log.debug(
            "[Tuya DEBUG] v3.4 unsliced buffer: " + buffer.toString("hex")
        );

        // Allocate buffer with room for payload + 32 bytes for
        // prefix, sequence, command, length, crc, and suffix
        const bufPayload = Buffer.alloc(payload.length + 16);
        buffer.copy(bufPayload);
        log.debug(
            "[Tuya DEBUG] v3.4 unencrypted buffer of payload: " +
                bufPayload.toString("hex")
        );

        // For 3.4 session key, calculate HMAC on Buffer payload
        const calculatedChecksum = TuyaCipher.hmac(bufPayload, key);
        log.debug(
            "[Tuya DEBUG] v3.4 checksum: " + calculatedChecksum.toString("hex")
        );

        calculatedChecksum.copy(buffer, payload.length + 16);

        buffer.writeUInt32BE(0x0000aa55, payload.length + 48);

        log.debug(
            "[Tuya DEBUG] v3.4 Unencoded Buffer: " + buffer.toString("hex")
        );

        return buffer;
    }

    static decode_3_4(o) {
        const { msg, key, log } = { ...o };

        log.debug(
            "[Tuya] v3.4 original message received: " + msg.toString("hex")
        );

        const msgLen = msg.length;
        const prefix = "0x0000" + msg.readUInt32BE(0).toString(16);
        const cmd = msg.readUInt32BE(8);
        const payloadSize = msg.readUInt32BE(12);
        const suffix = "0x0000" + msg.readUInt32BE(msgLen - 4).toString(16);

        log.debug("[Tuya] msgLen: " + msgLen.toString());
        log.debug("[Tuya] prefix: " + prefix);
        log.debug("[Tuya] cmd: " + cmd.toString(16));
        log.debug("[Tuya] payloadSize: " + payloadSize.toString(16));
        log.debug("[Tuya] suffix: " + suffix);

        let versionPos = msg.indexOf("3.4");
        const cleanMsg = msg.slice(
            versionPos === -1
                ? msgLen -
                      payloadSize +
                      (msg.readUInt32BE(16) & 0xffffff00 ? 0 : 4)
                : 15 + versionPos,
            msgLen - 36
        );

        log.debug(
            "[Tuya DEBUG] Cleaned Up Message: " + cleanMsg.toString("hex")
        );

        const decryptedPayload = TuyaCipher.decrypt_3_4({
            data: cleanMsg,
            key: key,
        });

        var decodedMsg = {
            msgLen: msgLen,
            prefix: prefix,
            cmd: cmd,
            payloadSize: payloadSize,
            decryptedPayload: decryptedPayload,
            suffix: suffix,
        };

        return decodedMsg;
    }
}

module.exports = TuyaEncodeDecode;
