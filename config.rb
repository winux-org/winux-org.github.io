activate :autoprefixer do |prefix|
  prefix.browsers = "last 2 versions"
end

# https://github.com/middleman/middleman-syntax
# activate :syntax, :line_numbers => true

# Per-page layout changes
page '/CNAME', layout: false
page '/*.xml', layout: false
page '/*.json', layout: false
page '/*.txt', layout: false

# define specific layout
# page "/about/*", :layout => "layout-about"

set :markdown_engine, :redcarpet
set :markdown, :fenced_code_blocks => true, :smartypants => true

ignore 'partials/*'

set :build_dir, 'docs'
