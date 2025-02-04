document.addEventListener("DOMContentLoaded", function () {
    // Fetch Visitor ID from backend
    fetch("/api/visitor-id/")
        .then(response => response.json())
        .then(data => {
            document.getElementById("visitor_id").value = data.visitor_id;
        })
        .catch(error => console.error("Error fetching Visitor ID:", error));
});


document.addEventListener("DOMContentLoaded", function() {
    fetch("{% url 'get_visitor_id' %}")
    .then(response => response.json())
    .then(data => {
        document.getElementById("visitor_id").value = data.visitor_id;
    });
});

document.getElementById("loanForm").addEventListener("submit", function (event) {
    event.preventDefault();
    let formData = new FormData(this);
    fetch("{% url 'apply_for_loan' %}", {
        method: "POST",
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        alert(data.message);
    })
    .catch(error => console.error("Error submitting loan application:", error));
});
