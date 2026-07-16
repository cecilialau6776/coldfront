// SPDX-FileCopyrightText: (C) ColdFront Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { getCSSVariable } from './data';
import Chart from 'chart.js/auto';

export function initGaugeChart(): void {
  const gauges = document.querySelectorAll<HTMLCanvasElement>(
    'div.chart-container > canvas.gauge-chart'
  );
  for (const element of gauges) {
    if (element !== null) {
      const used = Number(element?.getAttribute('data-used') || 0);
      let available = Number(element?.getAttribute('data-total') || 0) - used;
      const title = String(element?.getAttribute('data-title') || '');

      if (available < 0) {
        available = 0;
      }

      createGaugeChart(element, title, used, available);
    }
  }
}

function createGaugeChart(
  canvas: HTMLCanvasElement,
  title: string,
  used: number,
  available: number
): void {
  const total = used + available;
  const used_percentage = (used / total) * 100;
  const available_percentage = (available / total) * 100;
  new Chart(canvas, {
    type: 'doughnut',
    data: {
      labels: [
        `Used (${used_percentage.toFixed(2)}%)`,
        `Available (${available_percentage.toFixed(2)}%)`,
      ],
      datasets: [
        {
          data: [used, available],
          // This uses bootstraps colors
          backgroundColor: [
            getCSSVariable('--bs-success'),
            getCSSVariable('--bs-secondary'),
          ],
          borderColor: [
            getCSSVariable('--bs-success'),
            getCSSVariable('--bs-secondary'),
          ],
          borderWidth: 1,
        },
      ],
    },
    options: {
      radius: '70%',
      aspectRatio: 2,
      rotation: 270,
      circumference: 180,
      responsive: true,
      plugins: {
        legend: {
          display: true,
          position: 'bottom',
        },
        title: {
          display: true,
          text: title,
          position: 'bottom',
        },
      },
    },
  });
}
