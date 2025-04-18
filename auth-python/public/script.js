document.getElementById('loginForm').addEventListener('submit', async function (e) {
  e.preventDefault();

  const username = document.getElementById('loginUsername').value;
  const password = document.getElementById('loginPassword').value;

  const response = await fetch('/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });

  const data = await response.json();
  const message = document.getElementById('loginMessage');

  message.style.color = data.success ? 'green' : 'red';
  message.textContent = data.message;
});

document.getElementById('registerForm').addEventListener('submit', async function (e) {
  e.preventDefault();

  const username = document.getElementById('registerUsername').value;
  const password = document.getElementById('registerPassword').value;

  const response = await fetch('/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });

  const data = await response.json();
  const message = document.getElementById('registerMessage');

  message.style.color = data.success ? 'green' : 'red';
  message.textContent = data.message;
});
