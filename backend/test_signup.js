const http = require('http');

const data = JSON.stringify({
  nom: 'Test User Agent',
  email: `test${Date.now()}@example.com`,
  password: 'password123',
  metier: 'Tester',
  localisation: 'Internet',
  skills: 'testing,debugging'
});

const options = {
  hostname: 'localhost',
  port: 5000,
  path: '/api/auth/signup',
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Content-Length': data.length
  }
};

const req = http.request(options, (res) => {
  console.log(`StatusCode: ${res.statusCode}`);
  let responseBody = '';

  res.on('data', (chunk) => {
    responseBody += chunk;
  });

  res.on('end', () => {
    console.log('Response:', responseBody);
  });
});

req.on('error', (error) => {
  console.error('Error connecting to server:', error.message);
  console.log('Ensure the server is running on port 5000');
});

req.write(data);
req.end();