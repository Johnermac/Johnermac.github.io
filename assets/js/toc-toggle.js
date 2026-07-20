/* TOC toggle — chapters tree starts collapsed, header click expands/collapses. */
(function($){
  $(function(){
    var $toc = $('nav.toc');
    if (!$toc.length) return;

    var $menu = $toc.find('.toc__menu');
    if (!$menu.length) return;

    var $heading = $toc.find('.nav__title').first();
    if (!$heading.length) {
      $heading = $toc.find('.toc__heading, h2, h3').first();
    }

    var $btn = $('<button class="toc__toggle" aria-expanded="false" aria-label="Toggle table of contents">▾</button>');

    if ($heading.length) {
      $heading.append($btn);
    } else {
      $toc.prepend($btn);
    }

    // Start collapsed
    $toc.addClass('is--collapsed');

    function toggle(){
      var expanded = $btn.attr('aria-expanded') === 'true';
      $btn.attr('aria-expanded', String(!expanded));
      $toc.toggleClass('is--collapsed');
    }

    $btn.on('click', function(e){
      e.stopPropagation();
      toggle();
    });

    // Whole header bar is a click target
    if ($heading.length) {
      $heading.css('cursor', 'pointer').on('click', toggle);
    }
  });
})(jQuery);
