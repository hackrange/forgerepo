// ForgeRepo portal: shared state.
// Author: Tim Rice

var state = { me: null, csrf: null, perms: [], view: null };
var root = document.getElementById('app');

export { root, state };
