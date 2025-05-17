$(document).ready(function() {
    const $sidebarToggler = $('#sidebar-toggler');
    const $sidebar = $('#sidebar');
    const $body = $('body');
    
    // Check if there's a saved state
    const sidebarCollapsed = localStorage.getItem('sidebarCollapsed') === 'true';
    
    // Apply initial state
    if (sidebarCollapsed) {
        $sidebar.addClass('collapsed');
        $body.addClass('sidebar-collapsed');
    }
    
    // Add titles to menu items for tooltips
    $('.has-sub').each(function() {
        const navText = $(this).find('.nav-text').text();
        $(this).attr('data-title', navText);
    });
    
    $sidebarToggler.on('click', function(e) {
        e.preventDefault();
        $sidebar.toggleClass('collapsed');
        $body.toggleClass('sidebar-collapsed');
        
        // Save state
        localStorage.setItem('sidebarCollapsed', $sidebar.hasClass('collapsed'));
        
        // Trigger window resize to adjust any charts or responsive elements
        $(window).trigger('resize');
    });
    
    // Add hover effect for collapsed menu items
    $('.nav.sidebar-inner > li').hover(
        function() {
            if ($sidebar.hasClass('collapsed')) {
                $(this).addClass('show-tooltip');
            }
        },
        function() {
            $(this).removeClass('show-tooltip');
        }
    );
});
