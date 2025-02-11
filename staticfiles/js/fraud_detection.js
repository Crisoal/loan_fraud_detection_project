// static/js/fraud_detection.js

document.addEventListener("DOMContentLoaded", async function () {
    const form = document.getElementById("loanForm");
    const publicKey = window.fingerprintjsPublicKey;

    // Get CSRF token from cookie
    function getCookie(name) {
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.substring(0, name.length + 1) === (name + '=')) {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    }

    form.addEventListener("submit", async function (event) {
        event.preventDefault();

        try {
            const csrftoken = getCookie('csrftoken');

            // Load FingerprintJS
            const FingerprintJS = await import(`https://fpjscdn.net/v3/${publicKey}`);
            const fp = await FingerprintJS.load();
            const result = await fp.get({ extendedResult: true });

            // Send requestId to Django backend with CSRF token
            const smartSignalsResponse = await fetch("/get-smart-signals/", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRFToken": csrftoken  // Add CSRF token here
                },
                body: JSON.stringify({ requestId: result.requestId })
            });

            if (!smartSignalsResponse.ok) {
                throw new Error(`Failed to fetch smart signals: ${smartSignalsResponse.statusText}`);
            }

            const smartSignalsData = await smartSignalsResponse.json();

            // Collect metadata including smart signals
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
                publicIpAddress: result.ip,
                incognito: result.incognito,
                confidence: result.confidence?.score || 0,
                smartSignals: {
                    botDetection: smartSignalsData.products.botd?.data?.bot?.result === 'detected',
                    ipBlocklist: smartSignalsData.products.ipBlocklist?.data?.result,
                    tor: smartSignalsData.products.tor?.data?.result,
                    vpn: smartSignalsData.products.vpn?.data?.result,
                    proxy: smartSignalsData.products.proxy?.data?.result,
                    tampering: smartSignalsData.products.tampering?.data?.result,
                    velocity: smartSignalsData.products.velocity?.data,
                    ipInfo: smartSignalsData.products.ipInfo?.data?.v4
                }
                
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
