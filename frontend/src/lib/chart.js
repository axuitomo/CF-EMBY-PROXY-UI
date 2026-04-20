let activeChart = null;

export async function renderTrendChart(canvas, points = [], options = {}) {
  if (!canvas) return null;

  const { default: Chart } = await import('chart.js/auto');
  const label = String(options.label || '趋势').trim() || '趋势';
  const borderColor = String(options.borderColor || '#fb923c').trim() || '#fb923c';
  const backgroundColor = String(options.backgroundColor || 'rgba(251, 146, 60, 0.18)').trim() || 'rgba(251, 146, 60, 0.18)';

  if (activeChart) {
    activeChart.destroy();
    activeChart = null;
  }

  activeChart = new Chart(canvas, {
    type: 'line',
    data: {
      labels: points.map((point) => point.label),
      datasets: [
        {
          label,
          data: points.map((point) => point.value),
          borderColor,
          backgroundColor,
          tension: 0.35,
          fill: true,
          borderWidth: 2.5,
          pointRadius: 3.5,
          pointHoverRadius: 5
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: {
        intersect: false,
        mode: 'index'
      },
      plugins: {
        legend: {
          display: false
        },
        tooltip: {
          displayColors: false,
          backgroundColor: '#08111f',
          borderColor: 'rgba(255,255,255,0.12)',
          borderWidth: 1
        }
      },
      scales: {
        x: {
          grid: {
            color: 'rgba(255,255,255,0.06)'
          },
          ticks: {
            color: '#cbd5e1'
          }
        },
        y: {
          beginAtZero: true,
          grid: {
            color: 'rgba(255,255,255,0.06)'
          },
          ticks: {
            color: '#cbd5e1',
            precision: 0
          }
        }
      }
    }
  });

  return activeChart;
}

export function destroyTrendChart() {
  if (!activeChart) return;
  activeChart.destroy();
  activeChart = null;
}

export async function renderReleaseChart(canvas, points = []) {
  return renderTrendChart(canvas, points, {
    label: '模块改动热度',
    borderColor: '#fb923c',
    backgroundColor: 'rgba(251, 146, 60, 0.18)'
  });
}

export function destroyReleaseChart() {
  destroyTrendChart();
}
