const params = new URLSearchParams(window.location.search);
const username = params.get('user') || 'guest';

function renderProfile(profile) {
  document.getElementById('profile-name').textContent = username;
  document.getElementById('profile-bio').textContent = profile.bio;
  const link = document.getElementById('profile-link');
  link.href = '/users/' + encodeURIComponent(username);
}

fetch('/api/profile?user=' + encodeURIComponent(username))
  .then(res => res.json())
  .then(renderProfile);
