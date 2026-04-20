import { createApp } from 'vue';

import App from './App.vue';
import { useTheme } from './composables/useTheme';
import './style.css';

useTheme().initializeTheme();

createApp(App).mount('#app');
