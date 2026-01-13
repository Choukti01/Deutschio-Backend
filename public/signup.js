const signupForm = document.getElementById('signupForm');
const errorDiv = document.getElementById('signupError');

signupForm.addEventListener('submit', async (e) => {
  e.preventDefault();

  const email = document.getElementById('signupEmail').value.trim();
  const password = document.getElementById('signupPassword').value;

  errorDiv.style.display = 'none';

  try {
    const res = await fetch(`${API_URL}/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });

    const data = await res.json();

    if (!res.ok) {
      errorDiv.style.display = 'block';
      errorDiv.textContent = data.message;
      return;
    }

    alert(data.message);
    window.location.href = 'login.html';

  } catch {
    errorDiv.style.display = 'block';
    errorDiv.textContent = 'Cannot connect to server';
  }
});
