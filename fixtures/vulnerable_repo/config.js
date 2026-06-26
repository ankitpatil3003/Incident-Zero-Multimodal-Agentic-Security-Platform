// Intentionally vulnerable JS file for CodeScan testing.

const API_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz1234";

function getUser(userId) {
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    return query;
}

// Safe code — should NOT trigger
function add(a, b) {
    return a + b;
}
