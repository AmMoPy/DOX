/**
 * Application Entry Point
 */

import { render } from 'solid-js/web';
import App from './app';
import './index.css';

const root = document.getElementById('root');

if (!root) {
  throw new Error('Root element not found');
}

// Render main app
render(() => <App />, root);