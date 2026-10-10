const fs = require('fs');

let appJs = fs.readFileSync('js/app.js', 'utf8');

// Find the bad replacement and remove the old body
// It starts with `// dummy for replace logic:` up to the end of that object or next method
appJs = appJs.replace(
  /\/\/ dummy for replace logic: resetAdminLock_legacy\(\) \{[\s\S]*?return \{ cleared: true, removedKeys: removedKeys, storageKey: STORAGE_KEYS\.admin \};\n  \},/m,
  ''
);

fs.writeFileSync('js/app.js', appJs);
console.log('Fixed app.js');
