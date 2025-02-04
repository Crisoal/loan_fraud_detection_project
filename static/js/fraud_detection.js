document.addEventListener("DOMContentLoaded", function () {
    // Fetch Visitor ID from backend
    fetch("/api/visitor-id/")

        .then(response => response.json())
        .then(data => {
            document.getElementById("visitor_id").value = data.visitor_id;
        })
        .catch(error => console.error("Error fetching Visitor ID:", error));
});

