// static/js/fraud_detection.js

document.addEventListener("DOMContentLoaded", function () {
    const form = document.getElementById("loanForm");
    if (!form) return;

    // Get the public key from the global variable set in the HTML template
    const publicKey = window.fingerprintjsPublicKey;
    
    if (!publicKey) {
        console.error("FingerprintJS public key is missing.");
        return;
    }

    form.addEventListener("submit", async function (event) {
        event.preventDefault();
        try {
            const fp = await import(`https://fpjscdn.net/v3/${publicKey}`);
            const result = await fp.load().then(FingerprintJS => FingerprintJS.get());

            // Store visitor ID in hidden input
            const visitorInput = document.getElementById("visitor_id");
            if (visitorInput) {
                visitorInput.value = result.visitorId;

                // Ensure device fingerprint is captured
                const deviceFingerprintInput = document.createElement("input");
                deviceFingerprintInput.type = "hidden";
                deviceFingerprintInput.name = "device_fingerprint";
                deviceFingerprintInput.value = JSON.stringify(result.components);
                form.appendChild(deviceFingerprintInput);

                // Now submit the form
                form.submit();
            } else {
                console.error("Visitor ID input element not found");
                throw new Error("Visitor ID input element not found");
            }
        } catch (error) {
            console.error("Error getting visitor ID:", error);
            // Log the error but still allow form submission
            form.submit();
        }
    });
});
