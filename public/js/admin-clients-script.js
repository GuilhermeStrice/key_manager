document.addEventListener('DOMContentLoaded', function() {
    const rejectButtons = document.querySelectorAll('button.reject');
    rejectButtons.forEach(button => {
        button.addEventListener('click', function(event) {
            if (!confirm('Are you sure you want to reject this client?')) {
                event.preventDefault();
            }
        });
    });

    const revokeButtons = document.querySelectorAll('button.delete'); // 'delete' is the class for revoke
    revokeButtons.forEach(button => {
        button.addEventListener('click', function(event) {
            if (!confirm('Are you sure you want to revoke this client? This will delete the client and its token.')) {
                event.preventDefault();
            }
        });
    });
});
