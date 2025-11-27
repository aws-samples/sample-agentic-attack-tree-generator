// ThreatForest Custom JavaScript

// Table sorting
document$.subscribe(function() {
  var tables = document.querySelectorAll("article table:not([class])")
  tables.forEach(function(table) {
    new Tablesort(table)
  })
})

// Smooth scroll for anchor links
document.addEventListener('DOMContentLoaded', function() {
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
      e.preventDefault();
      const target = document.querySelector(this.getAttribute('href'));
      if (target) {
        target.scrollIntoView({
          behavior: 'smooth',
          block: 'start'
        });
      }
    });
  });
});

// Enhanced code block interactions
document$.subscribe(function() {
  // Add language labels to code blocks
  document.querySelectorAll('.highlight').forEach(function(block) {
    const code = block.querySelector('code');
    if (code && code.className) {
      const lang = code.className.match(/language-(\w+)/);
      if (lang && lang[1]) {
        const label = document.createElement('div');
        label.className = 'code-label';
        label.textContent = lang[1].toUpperCase();
        label.style.cssText = 'position: absolute; top: 0.5rem; right: 3rem; background: rgba(0,0,0,0.3); color: white; padding: 0.25rem 0.75rem; border-radius: 0.25rem; font-size: 0.75rem; font-weight: 600;';
        block.style.position = 'relative';
        block.appendChild(label);
      }
    }
  });
});

// Console output for documentation
console.log('%c🌳 ThreatForest Documentation', 'color: #15803d; font-size: 20px; font-weight: bold;');
console.log('%cVersion: 1.0.0', 'color: #6b7280; font-size: 12px;');
console.log('%cLearn more: https://threatforest.dev', 'color: #6b7280; font-size: 12px;');
