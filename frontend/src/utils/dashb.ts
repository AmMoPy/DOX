import type { ActivityData, ActivityFilter, TimePeriod } from '~/api/types';

const morningGreetings = [
  'The day hasn\'t ruined you yet?',
  'Coffee hasn\'t kicked in? Me neither',
  'Early bird or just bad at time management?',
  'You\'re up early... or late. Either way, concerning',
  'Hustle culture says you\'re behind schedule',
  'SERIOUSLY? THE SUN ISN\'T EVEN UP YET. WHY ARE YOU?',
  'The day looms menacingly before us',
  'Up already? Overachiever',
  'The day is young and full of errors'
];

const afternoonGreetings = [
  'Hope lunch was better than your morning',
  'Productivity window closing rapidly, panic is optional',
  'Hope your lunch was better than your decisions',
  'Evening encroaches, did you accomplish... anything?',
  'The day is half over, so is your motivation',
  'Peak procrastination hours'
];

const eveningGreetings = [
  'Winding down or spiraling?',
  'The witching hour for productivity',
  'NIGHT FALLS, ALL HOPE IS NOT LOST. YET',
  'Should you be working right now?',
  'Bed is calling, Ignore it'
];

const nightGreetings = [
  'Shouldn\'t you be in bed? Quite irregular',
  'Late night thoughts: why am I like this?',
  'Night owl or procrastinator? Yes',
  'Prime time for existential dread',
  'I\'ll be here when you wake up. Creepy, right?',
  'Seriously? Go to bed!'
];

// Helpers
const getHoursFromPeriod = (period: TimePeriod): number => {
  const hours = { '24h': 24, '7d': 168, '30d': 720 };
  return hours[period];
};

// Format activity type for display
const formatActivityType = (type: string): string => {
  const typeMap: Record<string, string> = {
    'search_query': 'Search',
    'ai_query': 'AI Query',
    'upload_success': 'Document Upload',
    'login_success': 'Login',
    'password_changed': 'Password Changed',
  };
  return typeMap[type] || type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
};
 
// Format timestamp
const formatTime = (timestamp: string): string => {
  try {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;

    const diffDays = Math.floor(diffHours / 24);
    if (diffDays < 7) return `${diffDays}d ago`;
    
    return date.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  } catch {
    return timestamp;
  }
};
 
// Get time-based greeting
const getGreeting = (): string => {
  const hour = new Date().getHours();
  const greetings = hour < 12 ? morningGreetings :
                    hour < 18 ? afternoonGreetings :
                    hour < 22 ? eveningGreetings :
                    nightGreetings;
  
  return greetings[Math.floor(Math.random() * greetings.length)];
};

// Charts
const buildLineDatasets = (data: ActivityData[], filter: ActivityFilter) => {
  const datasets = [];
  
  if (filter === 'all' || filter === 'searches') {
    datasets.push({
      label: 'Searches',
      data: data.map(d => d.searches),
      borderColor: '#3B82F6',
      backgroundColor: 'rgba(59, 130, 246, 0.1)',
      tension: 0.4,
      fill: true,
      pointRadius: 4,
      pointHoverRadius: 6,
      pointBackgroundColor: '#3B82F6',
      pointBorderColor: '#fff',
      pointBorderWidth: 2,
    });
  }
  
  if (filter === 'all' || filter === 'ai') {
    datasets.push({
      label: 'AI Queries',
      data: data.map(d => d.aiQueries),
      borderColor: '#10B981',
      backgroundColor: 'rgba(16, 185, 129, 0.1)',
      tension: 0.4,
      fill: true,
      pointRadius: 4,
      pointHoverRadius: 6,
      pointBackgroundColor: '#10B981',
      pointBorderColor: '#fff',
      pointBorderWidth: 2,
    });
  }
  
  if (filter === 'all' || filter === 'uploads') {
    datasets.push({
      label: 'Uploads',
      data: data.map(d => d.uploads),
      borderColor: '#8B5CF6',
      backgroundColor: 'rgba(139, 92, 246, 0.1)',
      tension: 0.4,
      fill: true,
      pointRadius: 4,
      pointHoverRadius: 6,
      pointBackgroundColor: '#8B5CF6',
      pointBorderColor: '#fff',
      pointBorderWidth: 2,
    });
  }
  
  return datasets;
};

const buildBarDatasets = (data: ActivityData[], filter: ActivityFilter) => {
  const datasets = [];
  
  if (filter === 'all' || filter === 'searches') {
    datasets.push({
      label: 'Searches',
      data: data.map(d => d.searches),
      backgroundColor: '#3B82F6',
      borderRadius: 8,
      borderSkipped: false,
    });
  }
  
  if (filter === 'all' || filter === 'ai') {
    datasets.push({
      label: 'AI Queries',
      data: data.map(d => d.aiQueries),
      backgroundColor: '#10B981',
      borderRadius: 8,
      borderSkipped: false,
    });
  }
  
  if (filter === 'all' || filter === 'uploads') {
    datasets.push({
      label: 'Uploads',
      data: data.map(d => d.uploads),
      backgroundColor: '#8B5CF6',
      borderRadius: 8,
      borderSkipped: false,
    });
  }
  
  return datasets;
};

const lineChartOptions = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: {
      position: 'bottom' as const,
      labels: {
        color: '#9CA3AF',
        usePointStyle: true,
        padding: 15,
        font: { size: 12 }
      }
    },
    tooltip: {
      mode: 'index' as const,
      intersect: false,
      backgroundColor: 'rgba(0, 0, 0, 0.8)',
      titleColor: '#fff',
      bodyColor: '#fff',
      borderColor: '#374151',
      borderWidth: 1,
      padding: 12,
      displayColors: true,
      callbacks: {
        label: function(context: any) {
          let label = context.dataset.label || '';
          if (label) label += ': ';
          if (context.parsed.y !== null) label += context.parsed.y;
          return label;
        }
      }
    }
  },
  scales: {
    y: {
      beginAtZero: true,
      ticks: {
        color: '#9CA3AF',
        stepSize: 1,
        font: { size: 11 }
      },
      grid: {
        color: 'rgba(55, 65, 81, 0.2)',
        drawBorder: false
      }
    },
    x: {
      ticks: {
        color: '#9CA3AF',
        font: { size: 11 },
        maxTicksLimit: 7,
        maxRotation: 45,
        minRotation: 0
      },
      grid: { display: false }
    }
  },
  interaction: {
    mode: 'nearest' as const,
    axis: 'x' as const,
    intersect: false
  }
};

const barChartOptions = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: {
      position: 'bottom' as const,
      labels: {
        color: '#9CA3AF',
        usePointStyle: true,
        padding: 15,
        font: { size: 12 }
      }
    },
    tooltip: {
      mode: 'index' as const,
      intersect: false,
      backgroundColor: 'rgba(0, 0, 0, 0.8)',
      titleColor: '#fff',
      bodyColor: '#fff',
      borderColor: '#374151',
      borderWidth: 1,
      padding: 12,
      displayColors: true,
      callbacks: {
        label: function(context: any) {
          let label = context.dataset.label || '';
          if (label) label += ': ';
          if (context.parsed.y !== null) label += context.parsed.y;
          return label;
        }
      }
    }
  },
  scales: {
    y: {
      beginAtZero: true,
      ticks: {
        color: '#9CA3AF',
        stepSize: 1,
        font: { size: 11 }
      },
      grid: {
        color: 'rgba(55, 65, 81, 0.2)',
        drawBorder: false
      }
    },
    x: {
      ticks: {
        color: '#9CA3AF',
        font: { size: 11 },
        maxTicksLimit: 10
      },
      grid: { display: false }
    }
  }
};

export {formatActivityType, formatTime, getGreeting, getHoursFromPeriod, buildLineDatasets, buildBarDatasets, lineChartOptions, barChartOptions }