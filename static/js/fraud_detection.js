// static/js/fraud_detection.js

document.addEventListener("DOMContentLoaded", function () {
    const form = document.getElementById("loanForm");
    const publicKey = window.fingerprintjsPublicKey;

    if (!publicKey || publicKey.trim() === "" || publicKey.includes("{{")) {
        console.error('FingerprintJS public key is missing or not properly set.');
        return;
    }

    form.addEventListener("submit", async function (event) {
        event.preventDefault(); // Prevent default form submission

        try {
            const FingerprintJS = await import(`https://fpjscdn.net/v3/${publicKey}`);
            const fp = await FingerprintJS.load();
            const result = await fp.get({ extendedResult: true });

            // Collect metadata
            const extendedData = {
                requestId: result.requestId,
                visitorId: result.visitorId,
                firstSeenAt: result.firstSeenAt.global,
                lastSeenAt: result.lastSeenAt.global,
                browserDetails: {
                    browser: result.browserName,
                    version: result.browserVersion
                },
                osDetails: {
                    os: result.os,
                    version: result.osVersion,
                },
                device: result.device,
                publicIpAddress: result.ip,  // Store IP from FingerprintJS
                incognito: result.incognito, // Add incognito mode detection
                confidence: result.confidence?.score || 0
            };

            // Append metadata to form
            document.getElementById("extended_metadata").value = JSON.stringify(extendedData);

            // Submit form using Fetch API
            const formData = new FormData(form);
            const response = await fetch(form.action, {
                method: "POST",
                body: formData
            });

            const data = await response.json();

            // Handle response and update UI
            if (response.ok) {
                form.innerHTML = `<div class="alert alert-success text-center">${data.message || "Application submitted successfully!"}</div>`;
            } else {
                form.innerHTML = `<div class="alert alert-danger text-center">Something went wrong. Please try again later.</div>`;
                console.error("Server Error:", data.error || "Unknown error");
            }
        } catch (error) {
            console.error("Error retrieving visitor metadata:", error);
            form.innerHTML = `<div class="alert alert-danger text-center">An unexpected error occurred. Please try again.</div>`;
        }
    });
});
