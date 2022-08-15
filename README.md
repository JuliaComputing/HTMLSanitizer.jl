# HTMLSanitizer

[![CI](https://github.com/JuliaComputing/HTMLSanitizer.jl/actions/workflows/CI.yml/badge.svg)](https://github.com/JuliaComputing/HTMLSanitizer.jl/actions/workflows/CI.yml)

Whitelist-based HTML sanitizer inspired by [sanitize](https://github.com/rgrove/sanitize/) and [html-pipeline](https://github.com/jch/html-pipeline/blob/13057c4dcde5e769dd116682f1bed7e65e920b40/lib/html/pipeline/sanitization_filter.rb).

HTMLSanitizer.jl parses your source HTML with [Gumbo.jl](https://github.com/JuliaWeb/Gumbo.jl) and then filters tags and attributes according to a whitelist. The default whitelists are fairly close to GitHubs pipeline for rendering markdown to HTML.

## Usage

```
julia> sanitize("<a onclick='javascript:alert(0)'>YO DAWG</a>")
"<a>YO DAWG</a>"
```
```
julia> sanitize("""<img src="./foo.jpg" longdesc="javascript:alert(1)"></img>""")
"<img src=\"./foo.jpg\"></img>"
```
```
julia> whitelist = deepcopy(HTMLSanitizer.WHITELIST)
Dict{Symbol,Any} with 4 entries:
  :protocols       => Dict("del"=>Dict("cite"=>["http", "https", :relative]),"ins"=>D…
  :attributes      => Dict{Any,Array{String,1}}("del"=>["cite"],"ins"=>["cite"],:ALL=…
  :elements        => ["h1", "h2", "h3", "h4", "h5", "h6", "h7", "h8", "br", "b"  …  …
  :remove_contents => ["script"]

julia> append!(whitelist[:elements], ["body", "head"]); # body and head are not allowed by default

julia> HTMLSanitizer.sanitize("""
        <html><head></head><body onload!#\$%&()*~+-_.,:;?@[/|\\]^`=alert("XSS")></body></html>
       """, isfragment = false, whitelist = whitelist)
"<HTML><head></head><body></body></HTML>"
```

## Whitelists

Two whitelists are provided: `HTMLSanitizer.WHITELIST` and `HTMLSanitizer.LIMITED`. Check out the
implementation if you want to know what exactly is whitelisted.
