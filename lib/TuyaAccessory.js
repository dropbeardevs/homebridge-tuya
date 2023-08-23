const net = require("net");
const async = require("async");
const crypto = require("crypto");
const EventEmitter = require("events");
const TuyaCipher = require("./TuyaCipher");
const TuyaEncodeDecode = require("./TuyaEncodeDecode");
const TuyaConst = require("./TuyaConst");

const isNonEmptyPlainObject = (o) => {
    if (!o) return false;
    for (let i in o) return true;
    return false;
};

class TuyaAccessory extends EventEmitter {
    constructor(props) {
        super();

        this.log = props.logger;

        if (!(props.id && props.key && props.ip) && !props.fake)
            return this.log.info(
                "[Tuya] Insufficient details to initialize:",
                props
            );

        this.context = { version: "3.1", port: 6668, ...props };

        this.state = {};
        this._cachedBuffer = Buffer.allocUnsafe(0);

        // Create a Cipher if we have a valid key
        this.tuyacipher = new TuyaCipher(props.key, props.version);

        // Create encoder class
        this.tuyaencodedecode = new TuyaEncodeDecode();

        this.sessionEstablished = false; // For v3.4 and above

        // Include test for version 3.4
        if (this.context.version === "3.4")
            this._msgQueue = async.queue(this["_msgHandler_3_4"].bind(this), 1);
        else if (
            this.context.version === "3.2" ||
            this.context.version === "3.3"
        )
            this._msgQueue = async.queue(this["_msgHandler_3_3"].bind(this), 1);
        else
            this._msgQueue = async.queue(this["_msgHandler_3_1"].bind(this), 1);

        if (this.context.version >= 3.2) {
            this.context.pingGap = Math.min(this.context.pingGap || 9, 9);
            this.log.info(
                `[Tuya] Changing ping gap for ${this.context.name} to ${this.context.pingGap}s`
            );
        }

        this.connected = false;
        if (props.connect !== false) this._connect();

        this._connectionAttempts = 0;
        this._sendCounter = 0;
        this._sessionKey = null;
    }

    _connect() {
        if (this.context.fake) {
            this.connected = true;
            return setTimeout(() => {
                this.emit("change", {}, this.state);
            }, 1000);
        }

        this._socket = net.Socket();

        this._incrementAttemptCounter();

        (this._socket.reconnect = () => {
            this.log.debug(
                `[Tuya DEBUG] reconnect called for ${this.context.name}`
            );
            if (this._socket._pinger) {
                clearTimeout(this._socket._pinger);
                this._socket._pinger = null;
            }

            if (this._socket._connTimeout) {
                clearTimeout(this._socket._connTimeout);
                this._socket._connTimeout = null;
            }

            if (this._socket._errorReconnect) {
                clearTimeout(this._socket._errorReconnect);
                this._socket._errorReconnect = null;
            }

            this._socket.setKeepAlive(true);
            this._socket.setNoDelay(true);

            this._socket._connTimeout = setTimeout(() => {
                this._socket.emit(
                    "error",
                    new Error("ERR_CONNECTION_TIMED_OUT")
                );
                //this._socket.destroy();
                //process.nextTick(this._connect.bind(this));
            }, (this.context.connectTimeout || 30) * 1000);

            this._incrementAttemptCounter();

            this._socket.connect(this.context.port, this.context.ip);
        })();

        this._socket._ping = () => {
            if (this._socket._pinger) clearTimeout(this._socket._pinger);
            this._socket._pinger = setTimeout(() => {
                //Retry ping
                this._socket._pinger = setTimeout(() => {
                    this._socket.emit("error", new Error("ERR_PING_TIMED_OUT"));
                }, 5000);

                this.log.debug("Ping");

                this._send({
                    cmd: 9,
                    data: "",
                });
            }, (this.context.pingTimeout || 30) * 1000);

            this._send({
                cmd: 9,
            });
        };

        this._socket.on("connect", () => {
            clearTimeout(this._socket._connTimeout);

            this.connected = true;
            this.emit("connect");
            if (this._socket._pinger) clearTimeout(this._socket._pinger);
            this._socket._pinger = setTimeout(() => this._socket._ping(), 1000);

            if (this.context.intro === false) {
                this.emit("change", {}, this.state);
                process.nextTick(this.update.bind(this));
            }

            this.log.debug("Socket connected.");
        });

        this._socket.on("ready", () => {
            if (this.context.intro === false) return;
            this.connected = true;

            if (this.context.version == "3.4") {
                try {
                    this._negotiate_session_key_part_1("3.4");
                } catch (error) {
                    this.log.debug(
                        "Error binding key for protocol 3.4: " + error
                    );
                }
            }

            //this.update();
        });

        this._socket.on("data", (msg) => {
            this._cachedBuffer = Buffer.concat([this._cachedBuffer, msg]);

            this.log.debug("[Tuya DEBUG] Data received");

            do {
                let startingIndex = this._cachedBuffer.indexOf(
                    "000055aa",
                    "hex"
                );
                if (startingIndex === -1) {
                    this._cachedBuffer = Buffer.allocUnsafe(0);
                    break;
                }
                if (startingIndex !== 0)
                    this._cachedBuffer =
                        this._cachedBuffer.slice(startingIndex);

                let endingIndex = this._cachedBuffer.indexOf("0000aa55", "hex");
                if (endingIndex === -1) break;

                endingIndex += 4;

                this._msgQueue.push({
                    msg: this._cachedBuffer.slice(0, endingIndex),
                });

                this._cachedBuffer = this._cachedBuffer.slice(endingIndex);
            } while (this._cachedBuffer.length);
        });

        this._socket.on("error", (err) => {
            this.connected = false;
            this.log.info(
                `[Tuya] Socket had a problem and will reconnect to ${
                    this.context.name
                } (${(err && err.code) || err})`
            );

            if (
                err &&
                (err.code === "ECONNRESET" || err.code === "EPIPE") &&
                this._connectionAttempts < 10
            ) {
                this.log.debug(
                    `[Tuya DEBUG] Reconnecting with connection attempts =  ${this._connectionAttempts}`
                );
                return process.nextTick(this._socket.reconnect.bind(this));
            }

            this._socket.destroy();

            let delay = 5000;
            if (err) {
                if (err.code === "ENOBUFS") {
                    this.log.warn();
                    ("[Tuya] Operating system complained of resource exhaustion; did I open too many sockets?");
                    this.log.info(
                        "[Tuya] Slowing down retry attempts; if you see this happening often, it could mean some sort of incompatibility."
                    );
                    delay = 60000;
                } else if (this._connectionAttempts > 10) {
                    this.log.info(
                        "[Tuya] Slowing down retry attempts; if you see this happening often, it could mean some sort of incompatibility."
                    );
                    delay = 60000;
                }
            }

            if (!this._socket._errorReconnect) {
                this.log.debug(
                    `[Tuya DEBUG] after error setting _connect in ${delay}ms`
                );
                this._socket._errorReconnect = setTimeout(() => {
                    this.log.debug(
                        `[Tuya DEBUG] executing _connect after ${delay}ms delay`
                    );
                    process.nextTick(this._connect.bind(this));
                }, delay);
            }
        });

        this._socket.on("close", (err) => {
            this._disconnect(); // Disconnect gracefully
            //this.log.info('[Tuya] Closed connection with', this.context.name);
        });

        this._socket.on("end", () => {
            this.connected = false;
            this.log.info("[Tuya] Disconnected from", this.context.name);
        });
    }

    _incrementAttemptCounter() {
        this._connectionAttempts++;
        setTimeout(() => {
            this.log.debug(
                `[Tuya DEBUG] decrementing this._connectionAttempts, currently ${this._connectionAttempts}`
            );
            this._connectionAttempts--;
        }, 10000);
    }

    _msgHandler_3_1(task, callback) {
        if (!(task.msg instanceof Buffer)) return callback();

        const len = task.msg.length;
        if (
            len < 16 ||
            task.msg.readUInt32BE(0) !== 0x000055aa ||
            task.msg.readUInt32BE(len - 4) !== 0x0000aa55
        )
            return callback();

        const size = task.msg.readUInt32BE(12);
        if (len - 8 < size) return callback();

        const cmd = task.msg.readUInt32BE(8);
        let data = task.msg
            .slice(len - size, len - 8)
            .toString("utf8")
            .trim()
            .replace(/\0/g, "");

        if (this.context.intro === false && cmd !== 9)
            this.log.info("[Tuya] Message from", this.context.name + ":", data);

        switch (cmd) {
            case 7:
                // ignoring
                break;

            case 9:
                if (this._socket._pinger) clearTimeout(this._socket._pinger);
                this._socket._pinger = setTimeout(() => {
                    this._socket._ping();
                }, (this.context.pingGap || 20) * 1000);
                break;

            case 8:
                let decryptedMsg;
                try {
                    const decipher = crypto.createDecipheriv(
                        "aes-128-ecb",
                        this.context.key,
                        ""
                    );
                    decryptedMsg = decipher.update(
                        data.substr(19),
                        "base64",
                        "utf8"
                    );
                    decryptedMsg += decipher.final("utf8");
                } catch (ex) {
                    decryptedMsg = data.substr(19).toString("utf8");
                }

                try {
                    data = JSON.parse(decryptedMsg);
                } catch (ex) {
                    data = decryptedMsg;
                    this.log.info(
                        `[Tuya] Odd message from ${this.context.name} with command ${cmd}:`,
                        data
                    );
                    this.log.info(
                        `[Tuya] Raw message from ${this.context.name} (${this.context.version}) with command ${cmd}:`,
                        task.msg.toString("hex")
                    );
                    break;
                }

                if (data && data.dps) {
                    //this.log.info('[Tuya] Update from', this.context.name, 'with command', cmd + ':', data.dps);
                    this._change(data.dps);
                }
                break;

            case 10:
                if (data) {
                    if (data === "json obj data unvalid") {
                        this.log.info(
                            `[Tuya] ${this.context.name} (${this.context.version}) didn't respond with its current state.`
                        );
                        this.emit("change", {}, this.state);
                        break;
                    }

                    try {
                        data = JSON.parse(data);
                    } catch (ex) {
                        this.log.info(
                            `[Tuya] Malformed update from ${this.context.name} with command ${cmd}:`,
                            data
                        );
                        this.log.info(
                            `[Tuya] Raw update from ${this.context.name} (${this.context.version}) with command ${cmd}:`,
                            task.msg.toString("hex")
                        );
                        break;
                    }

                    if (data && data.dps) this._change(data.dps);
                }
                break;

            default:
                this.log.info(
                    `[Tuya] Odd message from ${this.context.name} with command ${cmd}:`,
                    data
                );
                this.log.info(
                    `[Tuya] Raw message from ${this.context.name} (${this.context.version}) with command ${cmd}:`,
                    task.msg.toString("hex")
                );
        }

        callback();
    }

    _msgHandler_3_3(task, callback) {
        if (!(task.msg instanceof Buffer)) return callback;

        const len = task.msg.length;
        if (
            len < 16 ||
            task.msg.readUInt32BE(0) !== 0x000055aa ||
            task.msg.readUInt32BE(len - 4) !== 0x0000aa55
        )
            return callback();

        const size = task.msg.readUInt32BE(12);
        if (len - 8 < size) return callback();

        const cmd = task.msg.readUInt32BE(8);

        if (cmd === 7) return callback(); // ignoring
        if (cmd === 9) {
            if (this._socket._pinger) clearTimeout(this._socket._pinger);
            this._socket._pinger = setTimeout(() => {
                this._socket._ping();
            }, (this.context.pingGap || 20) * 1000);

            return callback();
        }

        let versionPos = task.msg.indexOf("3.3");
        if (versionPos === -1) versionPos = task.msg.indexOf("3.2");
        const cleanMsg = task.msg.slice(
            versionPos === -1
                ? len - size + (task.msg.readUInt32BE(16) & 0xffffff00 ? 0 : 4)
                : 15 + versionPos,
            len - 8
        );

        let decryptedMsg;
        try {
            const decipher = crypto.createDecipheriv(
                "aes-128-ecb",
                this.context.key,
                ""
            );
            decryptedMsg = decipher.update(cleanMsg, "buffer", "utf8");
            decryptedMsg += decipher.final("utf8");
        } catch (ex) {
            decryptedMsg = cleanMsg.toString("utf8");
        }

        if (cmd === 10 && decryptedMsg === "json obj data unvalid") {
            this.log.info(
                `[Tuya] ${this.context.name} (${this.context.version}) didn't respond with its current state.`
            );
            this.emit("change", {}, this.state);
            return callback();
        }

        let data;
        try {
            data = JSON.parse(decryptedMsg);
        } catch (ex) {
            this.log.info(
                `[Tuya] Odd message from ${this.context.name} with command ${cmd}:`,
                decryptedMsg
            );
            this.log.info(
                `[Tuya] Raw message from ${this.context.name} (${this.context.version}) with command ${cmd}:`,
                task.msg.toString("hex")
            );
            return callback();
        }

        switch (cmd) {
            case 8:
            case 10:
                if (data) {
                    if (data.dps) {
                        this.log.info(
                            `[Tuya] Heard back from ${this.context.name} with command ${cmd}`
                        );
                        this._change(data.dps);
                    } else {
                        this.log.info(
                            `[Tuya] Malformed message from ${this.context.name} with command ${cmd}:`,
                            decryptedMsg
                        );
                        this.log.info(
                            `[Tuya] Raw message from ${this.context.name} (${this.context.version}) with command ${cmd}:`,
                            task.msg.toString("hex")
                        );
                    }
                }
                break;

            default:
                this.log.info(
                    `[Tuya] Odd message from ${this.context.name} with command ${cmd}:`,
                    decryptedMsg
                );
                this.log.info(
                    `[Tuya] Raw message from ${this.context.name} (${this.context.version}) with command ${cmd}:`,
                    task.msg.toString("hex")
                );
        }

        callback();
    }

    _msgHandler_3_4(task, callback) {
        if (!(task.msg instanceof Buffer)) return callback;

        //Get decoded message
        const decodedMsg = TuyaEncodeDecode.decode_3_4({
            msg: task.msg,
            key: this.tuyacipher.getKey(),
            log: this.log,
        });

        if (
            decodedMsg.msgLen < 16 ||
            decodedMsg.prefix !== TuyaConst.ProtocolValues.PROTOCOL_34_PREFIX ||
            decodedMsg.suffix !== TuyaConst.ProtocolValues.PROTOCOL_34_SUFFIX
        ) {
            return callback();
        }

        if (decodedMsg.msgLen - 8 < decodedMsg.payloadSize) return callback();

        if (decodedMsg.cmd === TuyaConst.CommandType.SESS_KEY_NEG_RES) {
            // Negotiate Part 3

            if (this.sessionEstablished) {
                this.log.debug(
                    "Do nothing because session is already established"
                );
                return callback;
            }

            this._negotiate_session_key_part_3({
                msg: decodedMsg.decryptedPayload,
                version: "3.4",
            });

            return callback;
        }

        if (decodedMsg.cmd === TuyaConst.CommandType.CONTROL) return callback(); // ignoring
        if (decodedMsg.cmd === TuyaConst.CommandType.HEART_BEAT) {
            if (this.sessionEstablished) {
                // Don't ping until session established
                if (this._socket._pinger) clearTimeout(this._socket._pinger);
                this._socket._pinger = setTimeout(() => {
                    this._socket._ping();
                }, (this.context.pingGap || 20) * 1000);
            }

            return callback();
        }

        if (
            decodedMsg.cmd === 10 &&
            decodedMsg.decryptedPayload === "json obj data unvalid"
        ) {
            this.log.info(
                `[Tuya] ${this.context.name} (${this.context.version}) didn't respond with its current state.`
            );
            this.emit("change", {}, this.state);
            return callback();
        }

        let data;

        try {
            data = JSON.parse(decryptedMsg);
        } catch (ex) {
            this.log.info(
                `[Tuya] Odd message from ${this.context.name} with command ${cmd}:`,
                decryptedMsg
            );
            this.log.info(
                `[Tuya] Raw message from ${this.context.name} (${this.context.version}) with command ${cmd}:`,
                task.msg.toString("hex")
            );
            return callback();
        }

        switch (decodedMsg.cmd) {
            case TuyaConst.CommandType.STATUS:
            case TuyaConst.CommandType.DP_QUERY:
                if (data) {
                    if (data.dps) {
                        this.log.info(
                            `[Tuya] Heard back from ${this.context.name} with command ${cmd}`
                        );
                        this._change(data.dps);
                    } else {
                        this.log.info(
                            `[Tuya] Malformed message from ${this.context.name} with command ${cmd}:`,
                            decryptedMsg
                        );
                        this.log.info(
                            `[Tuya] Raw message from ${this.context.name} (${this.context.version}) with command ${cmd}:`,
                            task.msg.toString("hex")
                        );
                    }
                }
                break;

            default:
                this.log.info(
                    `[Tuya] Odd message from ${this.context.name} with command ${cmd}:`,
                    decryptedMsg
                );
                this.log.info(
                    `[Tuya] Raw message from ${this.context.name} (${this.context.version}) with command ${cmd}:`,
                    task.msg.toString("hex")
                );
        }

        callback();
    }

    update(o) {
        const dps = {};
        let hasDataPoint = false;
        o &&
            Object.keys(o).forEach((key) => {
                if (!isNaN(key)) {
                    dps["" + key] = o[key];
                    hasDataPoint = true;
                }
            });

        if (this.context.fake) {
            if (hasDataPoint) this._fakeUpdate(dps);
            return true;
        }

        let result = false;
        if (hasDataPoint) {
            this.log.info(
                "[Tuya] Sending",
                this.context.name,
                JSON.stringify(dps)
            );
            result = this._send({
                data: {
                    devId: this.context.id,
                    uid: "",
                    t: (Date.now() / 1000).toFixed(0),
                    dps: dps,
                },
                cmd: 7,
            });
            if (result !== true) this.log.info("[Tuya] Result", result);
            if (this.context.sendEmptyUpdate) {
                this.log.info(
                    "[Tuya] Sending",
                    this.context.name,
                    "empty signature"
                );
                this._send({ cmd: 7 });
            }
        } else {
            this.log.info(
                `[Tuya] Sending first query to ${this.context.name} (${this.context.version})`
            );
            result = this._send({
                data: {
                    gwId: this.context.id,
                    devId: this.context.id,
                },
                cmd: 10,
            });
        }

        return result;
    }

    _change(data) {
        if (!isNonEmptyPlainObject(data)) return;

        const changes = {};
        Object.keys(data).forEach((key) => {
            if (data[key] !== this.state[key]) {
                changes[key] = data[key];
            }
        });

        if (isNonEmptyPlainObject(changes)) {
            this.state = { ...this.state, ...data };
            this.emit("change", changes, this.state);
        }
    }

    _send(o) {
        if (this.context.fake) return;
        if (!this.connected) return false;

        if (this.context.version === "3.4") return this._send_3_4(o);
        else if (
            this.context.version === "3.2" ||
            this.context.version === "3.3"
        )
            return this._send_3_3(o);
        else return this._send_3_1(o);
    }

    _send_3_1(o) {
        const { cmd, data } = { ...o };

        let msg = "";

        //data
        if (data) {
            switch (cmd) {
                case 7:
                    const cipher = crypto.createCipheriv(
                        "aes-128-ecb",
                        this.context.key,
                        ""
                    );
                    let encrypted = cipher.update(
                        JSON.stringify(data),
                        "utf8",
                        "base64"
                    );
                    encrypted += cipher.final("base64");

                    const hash = crypto
                        .createHash("md5")
                        .update(
                            `data=${encrypted}||lpv=${this.context.version}||${this.context.key}`,
                            "utf8"
                        )
                        .digest("hex")
                        .substr(8, 16);

                    msg = this.context.version + hash + encrypted;
                    break;

                case 10:
                    msg = JSON.stringify(data);
                    break;
            }
        }

        const payload = Buffer.from(msg);
        const prefix = Buffer.from(
            "000055aa00000000000000" + cmd.toString(16).padStart(2, "0"),
            "hex"
        );
        const suffix = Buffer.concat([
            payload,
            Buffer.from("000000000000aa55", "hex"),
        ]);

        const len = Buffer.allocUnsafe(4);
        len.writeInt32BE(suffix.length, 0);

        return this._socket.write(Buffer.concat([prefix, len, suffix]));
    }

    _send_3_3(o) {
        const { cmd, data } = { ...o };

        // If sending empty dp-update command, we should not increment the sequence
        if (cmd !== 7 || data) this._sendCounter++;

        const hex = [
            "000055aa", //header
            this._sendCounter.toString(16).padStart(8, "0"), //sequence
            cmd.toString(16).padStart(8, "0"), //command
            "00000000", //size
        ];
        //version
        if (cmd === 7 && !data) hex.push("00000000");
        else if (cmd !== 9 && cmd !== 10)
            hex.push("332e33000000000000000000000000");
        //data
        if (data) {
            const cipher = crypto.createCipheriv(
                "aes-128-ecb",
                this.context.key,
                ""
            );
            let encrypted = cipher.update(
                Buffer.from(JSON.stringify(data)),
                "utf8",
                "hex"
            );
            encrypted += cipher.final("hex");
            hex.push(encrypted);
        }
        //crc32
        hex.push("00000000");
        //tail
        hex.push("0000aa55");

        const payload = Buffer.from(hex.join(""), "hex");
        //length
        payload.writeUInt32BE(payload.length - 16, 12);
        //crc
        payload.writeInt32BE(
            TuyaCipher.getCRC32(payload.slice(0, payload.length - 8)),
            payload.length - 8
        );

        return this._socket.write(payload);
    }

    _negotiate_session_key_part_1(version) {
        /*
            For v3.4, using the following sequence:
            https://github.com/codetheweb/tuyapi/issues/481#issuecomment-921756711

            ---

            in 3.4 there are session_key generated runtime:
            local_key is well known from devices.json.

            SESSION_KEY negotiation
            client send frame_id: 0x03
            16 bytes random

            gw responds with frame_id: 0x04
            16 bytes random
            32 bytes hmacSHA256(client_random, local_key)

            client send frame_id: 0x05
            32 bytes hmacSHA256(gw_random, local_key)

            all frames are aes_ecb_128 encrypted with local_key and have checksum hmacSHA256(data,local_key)

            SESSION_KEY generation
            aes_ecb_128( XOR_by_byte(client_random,gw_random) , local_key))
        */

        this._version = version;
        this._sendCounter++;

        if (this._version === "3.4") {
            this.log.debug("[Tuya DEBUG] v3.4 Negotiate Session Key Part 1");

            const payload = TuyaEncodeDecode.encode_3_4({
                cmd: TuyaConst.CommandType.SESS_KEY_NEG_START,
                data: this.tuyacipher.getLocalNonce(),
                key: this.tuyacipher.getKey(),
                counter: this._sendCounter,
                log: this.log,
            });

            return this._socket.write(payload);
        }

        return;
    }

    _negotiate_session_key_part_3(o) {
        const { version, msg } = { ...o };

        this.log.debug("[Tuya DEBUG] v3.4 Negotiate Session Key Part 3");

        const _localNonce = this.tuyacipher.getLocalNonce();

        if (version === "3.4") {
            // 16 bytes _remoteNonce and hmac on _localNonce
            const _remoteNonce = msg.subarray(0, 16);

            this.log.debug(
                "[Tuya DEBUG] Protocol 3.4: Remote Nonce: " +
                    _remoteNonce.toString("hex")
            );

            // Calculate HMAC of local nonce to compare against returned data
            const _calcLocalHmac = TuyaCipher.hmac(
                _localNonce,
                this.tuyacipher.getKey()
            ).toString("hex");

            const _returnedLocalHmac = msg.slice(16, 16 + 32).toString("hex");

            if (_returnedLocalHmac !== _calcLocalHmac) {
                this.log.error(
                    `HMAC mismatch(keys): expected ${expLocalHmac}, was ${calcLocalHmac}. ${msg.toString(
                        "hex"
                    )}`
                );

                return;
            }

            // Calculate payload for response 0x05
            const payload = TuyaEncodeDecode.encode_3_4({
                cmd: TuyaConst.CommandType.SESS_KEY_NEG_FINISH,
                data: _remoteNonce,
                key: this.tuyacipher.getKey(),
                counter: this._sendCounter,
                log: this.log,
            });

            // Calculate session key
            let sessionSuccess = this.tuyacipher.setSessionKey({
                localNonce: _localNonce,
                remoteNonce: _remoteNonce,
                version: "3.4",
                log: this.log,
            });

            if (sessionSuccess) {
                this.sessionEstablished = true;
            }

            return this._socket.write(payload);
        }
    }

    _send_3_4(o) {
        const { cmd, data } = { ...o };

        // Do not send anything if session hasn't been established.
        // Allow sending if establishing session key
        if (
            !this.sessionEstablished &&
            cmd !== TuyaConst.CommandType.SESS_KEY_NEG_START &&
            cmd !== TuyaConst.CommandType.SESS_KEY_NEG_RES
        )
            return false;

        // If sending empty dp-update command, we should not increment the sequence
        if (cmd !== 7 || data) this._sendCounter++;

        const payload = TuyaEncodeDecode.encode_3_4({
            cmd: cmd,
            data: data,
            key: this.tuyacipher.getKey(),
            counter: this._sendCounter,
            log: this.log,
        });

        this.log.debug("[Tuya DEBUG] v3.4 payload: " + payload.toString("hex"));

        return this._socket.write(payload);
    }

    _fakeUpdate(dps) {
        this.log.info("[Tuya] Fake update:", JSON.stringify(dps));
        Object.keys(dps).forEach((dp) => {
            this.state[dp] = dps[dp];
        });
        setTimeout(() => {
            this.emit("change", dps, this.state);
        }, 1000);
    }

    _disconnect() {
        this.log.debug("Disconnecting");
        this.connected = false;
        this.tuyacipher.clearSessionKey();
        this.sessionEstablished = false;
        this.log.info("Disconnected");
    }
}

module.exports = TuyaAccessory;
