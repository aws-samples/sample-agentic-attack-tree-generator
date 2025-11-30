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

// Resize sidebar to be thinner
function resizeSidebar() {
  const sidebars = document.querySelectorAll('.wy-nav-side, nav[role="navigation"], .md-sidebar--primary, aside.md-sidebar, [data-md-component="navigation"]');
  sidebars.forEach(sidebar => {
    if (sidebar) {
      sidebar.style.width = '180px';
      sidebar.style.minWidth = '180px';
      sidebar.style.maxWidth = '180px';
      sidebar.style.flex = '0 0 180px';
    }
  });
  
  // Also resize search and menu containers
  const sidebarContainers = document.querySelectorAll('.wy-side-nav-search, .wy-menu, .md-sidebar__scrollwrap');
  sidebarContainers.forEach(container => {
    if (container) {
      container.style.width = '180px';
    }
  });
}

// Run on page load and after content updates
document.addEventListener('DOMContentLoaded', resizeSidebar);
if (typeof document$ !== 'undefined') {
  document$.subscribe(resizeSidebar);
}
// Run immediately in case DOM is already loaded
resizeSidebar();
// Run again after a short delay to catch late-loading elements
setTimeout(resizeSidebar, 100);
setTimeout(resizeSidebar, 500);

// Initialize Mermaid for diagram rendering
document.addEventListener('DOMContentLoaded', function() {
  if (typeof mermaid !== 'undefined') {
    mermaid.initialize({ 
      startOnLoad: true,
      theme: 'default',
      securityLevel: 'loose',
      fontFamily: 'var(--font-family)',
      flowchart: {
        useMaxWidth: true,
        htmlLabels: true,
        curve: 'basis'
      }
    });
  }
});

// Console output for documentation
console.log('%c🌳 ThreatForest Documentation', 'color: #15803d; font-size: 20px; font-weight: bold;');
console.log('%cVersion: 1.0.0', 'color: #6b7280; font-size: 12px;');
console.log('%cLearn more: https://threatforest.dev', 'color: #6b7280; font-size: 12px;');
