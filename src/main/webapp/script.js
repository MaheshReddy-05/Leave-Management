document.getElementById('loginForm').addEventListener('submit', function(event) {
    event.preventDefault();

    let email = document.getElementById('email').value.trim().toLowerCase();
    let password = document.getElementById('password').value.trim();

    fetch('http://localhost:8080/LeaveManagement/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email: email, password: password })
    })
    .then(response => {
        return response.json().then(data => {
            if (response.ok && data === "Valid") {
                window.location.href = "http://localhost:8080/LeaveManagement/employee/employee.html";
            } else {
                document.getElementById('errorMessage').textContent = 'Laugh out loud 😂, you\'re not.';
            }
        });
    })
    .catch(error => {
        console.error('Error:', error);
        document.getElementById('errorMessage').textContent = 'An error occurred. Please try again later.';
    });
});