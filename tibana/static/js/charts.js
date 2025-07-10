async function loadAlerts() {
  try {
    const resp = await fetch('/api/alerts');
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return await resp.json();
  } catch (err) {
    console.error('Failed to load alerts:', err);
    return [];
  }
}

function renderTable(alerts) {
  const tbody = document.getElementById('alertsTable');
  tbody.innerHTML = '';
  alerts.slice(0, 50).forEach(a => {
    const row = `
      <tr>
        <td class="px-6 py-4">${a.alert_type}</td>
        <td class="px-6 py-4 font-mono">${a.src_ip}</td>
        <td class="px-6 py-4">${a.sensor}</td>
        <td class="px-6 py-4">${new Date(a.attack_time).toLocaleString()}</td>
      </tr>`;
    tbody.insertAdjacentHTML('beforeend', row);
  });
}

function renderChart(alerts) {
  const ctx = document.getElementById('timeChart').getContext('2d');

  // If you ever re-run, destroy old chart
  if (window.alertChart) {
    window.alertChart.destroy();
  }

  // Group by hour
  const counts = alerts.reduce((acc, a) => {
    const hour = new Date(a.attack_time).toISOString().slice(0, 13) + ':00';
    acc[hour] = (acc[hour] || 0) + 1;
    return acc;
  }, {});

  const labels = Object.keys(counts).sort();
  const data   = labels.map(l => counts[l]);

  // Dynamic gradient height based on canvas size
  const height = ctx.canvas.clientHeight;
  const gradient = ctx.createLinearGradient(0, 0, 0, height);
  gradient.addColorStop(0, 'rgba(59,130,246,0.5)');
  gradient.addColorStop(1, 'rgba(59,130,246,0)');

  window.alertChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label: 'Alerts per Hour',
        data,
        fill: true,
        backgroundColor: gradient,
        borderColor: 'rgba(59,130,246,1)',
        tension: 0.35,
        pointRadius: 0
      }]
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { title: { display: true, text: 'Time' }, grid: { display: false } },
        y: { title: { display: true, text: 'Count' }, beginAtZero: true }
      }
    }
  });

  document.getElementById('chartLoader').style.display = 'none';
}

(async () => {
  const alerts = await loadAlerts();
  renderTable(alerts);
  renderChart(alerts);
})();
