activate :autoprefixer do |prefix|
  prefix.browsers = "last 2 versions"
end

# Per-page layout changes
page '/CNAME', layout: false
page '/*.xml', layout: false
page '/*.json', layout: false
page '/*.txt', layout: false

set :markdown_engine, :redcarpet
set :markdown, :fenced_code_blocks => true, :smartypants => true

set :build_dir, 'docs'
