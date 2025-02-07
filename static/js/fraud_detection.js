// static/js/fraud_detection.js

document.addEventListener("DOMContentLoaded", function () {
    const form = document.getElementById("loanForm");
    const publicKey = window.fingerprintjsPublicKey;
    
    form.addEventListener("submit", async function (event) {
        event.preventDefault(); // Prevent form submission until data is collected

        try {
            // Load FingerprintJS library dynamically
            const FingerprintJS = await import(`https://fpjscdn.net/v3/${publicKey}`);
            const fp = await FingerprintJS.load();

            // Get visitor data with extended metadata
            const result = await fp.get({ extendedResult: true });

            // Log full response for debugging
            console.log("FingerprintJS Extended Metadata Response:", result);

            // Store visitor ID in form
            document.getElementById("visitor_id").value = result.visitorId;

            // Extract extended metadata
            const extendedData = {
                requestId: result.requestId,
                confidence: result.confidence.score,
                ip: result.ip,
                browserInfo: {
                    browserName: result.browserName,
                    browserVersion: result.browserVersion,
                    os: result.os,
                    osVersion: result.osVersion,
                    device: result.device,
                    incognito: result.incognito
                },
                location: result.ipLocation ? {
                    accuracyRadius: result.ipLocation.accuracyRadius,
                    latitude: result.ipLocation.latitude,
                    longitude: result.ipLocation.longitude,
                    postalCode: result.ipLocation.postalCode,
                    timezone: result.ipLocation.timezone,
                    city: result.ipLocation.city.name,
                    country: result.ipLocation.country.name,
                    continent: result.ipLocation.continent.name,
                    subdivisions: result.ipLocation.subdivisions.map(sub => sub.name)
                } : null,
                firstSeenAt: result.firstSeenAt.global,
                lastSeenAt: result.lastSeenAt.global
            };

            // Log extended metadata for debugging
            console.log("Extracted Extended Metadata:", extendedData);

            // Store metadata in hidden form field
            document.getElementById("extended_metadata").value = JSON.stringify(extendedData);

            // Submit form after data collection
            form.submit();
        } catch (error) {
            console.error("Error retrieving visitor metadata:", error);
            form.submit(); // Allow form submission even if FingerprintJS fails
        }
    });
});
