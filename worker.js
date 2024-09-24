addEventListener("fetch", (event) => {
    event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
    const requestClone = request.clone();

    if (request.method === "POST") {
        try {
            const requestBody = await request.json();
            const sealedResult = requestBody.fingerprintData.sealedResult;
            // TODO: Handle missing Fingerprint data, probably meaning malicious party trying to tamper with the request

            // Replace this with your actual base64-encoded decryption key in the env variables; ref: https://dev.fingerprint.com/docs/sealed-client-results
            const base64Key = ENCRYPTION_KEY;

            // Decrypt the sealed result
            const unsealedData = await unsealEventsResponse(sealedResult, base64Key);
            // TODO: handle spoofed data that cannot be decrypted by the key

            const fingerprintData = JSON.parse(unsealedData);

            // TODO: Check against the replay attacks; ref: https://dev.fingerprint.com/docs/protecting-from-client-side-tampering


            // TODO: Come up with your own rules based on the data provided by Fingerprint
            // TODO: Come up with your own actions based on the data provided by Fingerprint
            const rules = [
                {
                    check: (data) => {
                        const timestamp = data.products.identification.data.timestamp;
                        const currentTime = Date.now();
                        const timestampDate = new Date(timestamp);
                        return (currentTime - timestampDate.getTime()) > 1000;
                    },
                    message: "Timestamp is older than 1 second!",
                    status: 403,
                },
                {
                    check: (data) => data.products.botd.data.bot.result !== "notDetected",
                    message: "Bots are forbidden!",
                    status: 403,
                },
                {
                    check: (data) => data.products.suspectScore.data.result > 10,
                    message: "Suspect score!",
                    status: 403,
                },
                {
                    check: (data) => data.products.ipBlocklist.data.result === true,
                    message: "IP Blocklist!",
                    status: 403,
                },
                {
                    check: (data) => data.products.tampering.data.result === true,
                    message: "Tampering is forbidden!",
                    status: 403,
                }
            ];


            // Apply rules
            for (const rule of rules) {
                if (rule.check(fingerprintData)) {
                    // TODO: Properly handle challenges, logging, etc based on business needs
                    return new Response(rule.message, { status: rule.status });
                }
            }

        } catch (error) {
            console.error("Failed to unseal data:", error);
            return new Response("Malformed unexpected request", { status: 403 });
        }

        // Forward the cloned request to the origin server if no rule was violated
        return fetch(requestClone).then((oldResponse) => new Response(oldResponse.body, oldResponse));
    }

    return new Response("Malformed unexpected request", { status: 403 });
}

// Bellow is just the unsealemnet logic, quickly hacked, not tested thoroughly; ref: https://dev.fingerprint.com/docs/sealed-client-results
async function unsealEventsResponse(sealedDataBase64, base64Key) {
    // Convert base64 to Uint8Array
    const key = base64ToUint8Array(base64Key);
    const data = base64ToUint8Array(sealedDataBase64);

    // Define the header and lengths
    const sealedHeaderHex = '9E85DCED';
    const sealedHeader = hexToUint8Array(sealedHeaderHex);
    const nonceLength = 12;
    const authTagLength = 16;

    // Verify header
    const header = data.slice(0, sealedHeader.length);
    if (uint8ArrayToHex(header).toUpperCase() !== sealedHeaderHex) {
        throw new Error("Wrong header");
    }

    // Extract nonce, ciphertext, and authTag
    const nonce = data.slice(sealedHeader.length, sealedHeader.length + nonceLength);
    const ciphertext = data.slice(sealedHeader.length + nonceLength, -authTagLength);
    const authTag = data.slice(-authTagLength);

    // Import the key
    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        key,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
    );

    try {
        // Decrypt the data
        const decrypted = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: nonce },
            cryptoKey,
            new Uint8Array([...ciphertext, ...authTag])
        );

        // Convert the decrypted data from ArrayBuffer to Uint8Array
        const decryptedArray = new Uint8Array(decrypted);

        return await decompress(decryptedArray)
    } catch (error) {
        console.error("Decryption error details:", error);
        throw new Error("Decryption failed: " + error.message);
    }
}

function base64ToUint8Array(base64) {
    const binaryString = atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}

function hexToUint8Array(hex) {
    const length = hex.length / 2;
    const bytes = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
}

function uint8ArrayToHex(uint8Array) {
    return Array.from(uint8Array)
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');
}


/**
 * Decompress bytes into a UTF-8 string.
 *
 * @param {Uint8Array} compressedBytes
 * @returns {Promise<string>}
 */
async function decompress(compressedBytes) {
    // Convert the bytes to a stream.
    const stream = new Blob([compressedBytes]).stream();

    // Create a decompressed stream.
    const decompressedStream = stream.pipeThrough(
        new DecompressionStream("deflate-raw")
    );

    // Read all the bytes from this stream.
    const chunks = [];
    for await (const chunk of decompressedStream) {
        chunks.push(chunk);
    }
    const stringBytes = await concatUint8Arrays(chunks);

    // Convert the bytes to a string.
    return new TextDecoder().decode(stringBytes);
}

/**
 * Combine multiple Uint8Arrays into one.
 *
 * @param {ReadonlyArray<Uint8Array>} uint8arrays
 * @returns {Promise<Uint8Array>}
 */
async function concatUint8Arrays(uint8arrays) {
    const blob = new Blob(uint8arrays);
    const buffer = await blob.arrayBuffer();
    return new Uint8Array(buffer);
}