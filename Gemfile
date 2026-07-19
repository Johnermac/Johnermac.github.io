source "https://rubygems.org"

gem "jekyll", "~> 4.3"

# Plugins enabled in _config.yml
group :jekyll_plugins do
  gem "jekyll-paginate"
  gem "jekyll-sitemap"
  gem "jekyll-gist"
  gem "jekyll-feed"
  gem "jekyll-include-cache"
end

# Required for `jekyll serve` on Ruby >= 3.0
gem "webrick"

# Faster file watching on Windows
install_if -> { Gem.win_platform? } do
  gem "wdm", ">= 0.1.0"
end
