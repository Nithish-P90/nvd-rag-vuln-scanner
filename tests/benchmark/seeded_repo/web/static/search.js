const params = new URLSearchParams(window.location.search);
const query = params.get('q') || '';

function showResults(items) {
  document.getElementById('results-title').innerHTML = 'Results for ' + query;
  const list = document.getElementById('results');
  list.replaceChildren(...items.map(item => {
    const li = document.createElement('li');
    li.textContent = item.name;
    return li;
  }));
}

fetch('/api/search?q=' + encodeURIComponent(query))
  .then(res => res.json())
  .then(data => showResults(data.items));
