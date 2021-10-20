

# Note
All things discussed here has to work on Debian

# Building the website
    apt install ruby-dev ruby-full build-essential npm
    bundle config set --local path '/home/winux/.gem'
    bundle exec middleman build

# Running server
    bundle exec middleman serve
