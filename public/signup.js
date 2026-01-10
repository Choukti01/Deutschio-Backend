const signupForm = document.getElementById('signupForm');
const errorDiv = document.getElementById('signupError');

signupForm.addEventListener('submit', async (e) => {
  e.preventDefault();

  const email = document.getElementById('signupEmail').value.trim();
  const password = document.getElementById('signupPassword').value;

  errorDiv.style.display = 'none';
  errorDiv.textContent = '';

  try {
    const res = await fetch(`${deutschio.up.railway.app}/signup`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ email, password })
    });

    const isJson = res.headers
      .get('content-type')
      ?.includes('application/json');

    const data = isJson ? await res.json() : {};

    if (!res.ok) {
      errorDiv.style.display = 'block';
      errorDiv.textContent =
        data.message || `Signup failed (status ${res.status})`;
      return;
    }

    alert('Signup successful! You can now login.');
    window.location.href = 'login.html';

  } catch (err) {
    console.error('Network error:', err);
    errorDiv.style.display = 'block';
    errorDiv.textContent = 'Cannot connect to server';
  }
});
