// ForgeRepo management portal.
// Author: Tim Rice
// plain vanilla js, no build step, no regrets (mostly). textContent everywhere so user input never becomes markup.
// hiding controls is just tidiness, the server is the one that says no.
// one module per page under js/, this file only gets it going

import { boot, route } from './js/routing.js';

window.addEventListener('hashchange', route);
boot();
