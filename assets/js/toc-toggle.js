/* Small TOC toggle so pages can collapse/expand the table of contents. */
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

    // Single icon button
    var $btn = $('<button class="toc__toggle" aria-expanded="true" aria-label="Toggle table of contents">▾</button>');

    if ($heading.length) {
      $heading.append($btn);
    } else {
      $toc.prepend($btn);
    }

    $btn.on('click', function(){
      var expanded = $(this).attr('aria-expanded') === 'true';
      $(this).attr('aria-expanded', !expanded);
      $toc.toggleClass('is--collapsed');
    });
  });
})(jQuery);
