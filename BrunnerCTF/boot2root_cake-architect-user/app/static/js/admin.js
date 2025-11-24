document.addEventListener('DOMContentLoaded', function () {
    const nutritionForm = document.getElementById('nutritionForm');
    const nutritionResult = document.getElementById('nutritionResult');

    nutritionForm.addEventListener('submit', function (e) {
        e.preventDefault();
        const cakeId = document.getElementById('cakeId').value.trim();

        fetch('/admin/calculate-nutrition', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ cake_id: cakeId })
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                nutritionResult.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
            } else {
                nutritionResult.innerHTML = `
                    <div class="alert alert-success">
                        <strong>Nutrition Data:</strong>
                        <pre>${data.result}</pre>
                    </div>`;
            }
        })
        .catch(error => {
            nutritionResult.innerHTML = `<div class="alert alert-danger">Error: ${error.message}</div>`;
        });
    });
});
