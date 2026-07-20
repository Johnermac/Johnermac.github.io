---
layout: none
---

var idx = lunr(function () {
  this.field('title')
  this.field('excerpt')
  this.field('categories')
  this.field('tags')
  this.ref('id')

  this.pipeline.remove(lunr.trimmer)

  for (var item in store) {
    this.add({
      title: store[item].title,
      excerpt: store[item].excerpt,
      categories: store[item].categories,
      tags: store[item].tags,
      id: item
    })
  }
});

function escapeHtml(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Build a snippet of `text` centred on the first matched term, with all
// matched terms highlighted. Falls back to the start of the text.
function buildSnippet(text, terms) {
  var CTX = 220; // chars of context on each side
  var lower = text.toLowerCase();
  var pos = -1;
  terms.forEach(function (t) {
    if (!t) return;
    var p = lower.indexOf(t);
    if (p !== -1 && (pos === -1 || p < pos)) pos = p;
  });

  var start, end, lead, trail;
  if (pos === -1) {
    start = 0; end = Math.min(text.length, CTX * 2);
    lead = ""; trail = end < text.length ? "…" : "";
  } else {
    start = Math.max(0, pos - CTX);
    end = Math.min(text.length, pos + CTX);
    lead = start > 0 ? "…" : "";
    trail = end < text.length ? "…" : "";
  }

  var snippet = escapeHtml(text.slice(start, end));
  terms.forEach(function (t) {
    if (!t) return;
    var re = new RegExp("(" + escapeRegExp(escapeHtml(t)) + ")", "ig");
    snippet = snippet.replace(re, "<mark>$1</mark>");
  });
  return lead + snippet + trail;
}

$(document).ready(function() {
  $('input#search').on('keyup', function () {
    var resultdiv = $('#results');
    var query = $(this).val().toLowerCase();
    var terms = query.split(lunr.tokenizer.separator).filter(function (t) { return t; });
    var result =
      idx.query(function (q) {
        query.split(lunr.tokenizer.separator).forEach(function (term) {
          q.term(term, { boost: 100 })
          if(query.lastIndexOf(" ") != query.length-1){
            q.term(term, {  usePipeline: false, wildcard: lunr.Query.wildcard.TRAILING, boost: 10 })
          }
          if (term != ""){
            q.term(term, {  usePipeline: false, editDistance: 1, boost: 1 })
          }
        })
      });
    resultdiv.empty();
    resultdiv.prepend('<p class="results__found">'+result.length+' {{ site.data.ui-text[site.locale].results_found | default: "Result(s) found" }}</p>');
    for (var item in result) {
      var ref = result[item].ref;
      var snippet = buildSnippet(store[ref].excerpt, terms);
      var teaser = store[ref].teaser
        ? '<div class="archive__item-teaser"><img src="'+store[ref].teaser+'" alt=""></div>'
        : '';
      var searchitem =
        '<div class="list__item">'+
          '<article class="archive__item" itemscope itemtype="https://schema.org/CreativeWork">'+
            teaser +
            '<div class="archive__item-body">'+
              '<h2 class="archive__item-title" itemprop="headline">'+
                '<a href="'+store[ref].url+'" rel="permalink">'+store[ref].title+'</a>'+
              '</h2>'+
              '<p class="archive__item-excerpt" itemprop="description">'+snippet+'</p>'+
            '</div>'+
          '</article>'+
        '</div>';
      resultdiv.append(searchitem);
    }
  });
});
