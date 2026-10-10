const fs = require('fs');
let appJs = fs.readFileSync('js/app.js', 'utf8');

// The problematic code is:
//     return { cleared: true };
//   }
//   enablePinUI(enabled) {
// I just need to replace "return { cleared: true };\n  }\n  enablePinUI" with "return { cleared: true };\n  },\n  enablePinUI"

appJs = appJs.replace(
  /return \{ cleared: true \};\s*\}\s*enablePinUI\(enabled\) \{/,
  "return { cleared: true };\n  },\n  enablePinUI(enabled) {"
);

fs.writeFileSync('js/app.js', appJs);
console.log('Fixed comma in app.js');
