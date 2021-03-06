using HTMLSanitizer
using Test

@testset "HTMLSanitizer.jl" begin
  # https://github.com/jch/html-pipeline/blob/master/test/html/pipeline/sanitization_filter_test.rb
  @testset "test_removing_script_tags" begin
    orig = """<p><img src="http://github.com/img.png" /><script></script></p>"""
    html = HTMLSanitizer.sanitize(orig)
    @test !occursin("script", html)
  end

  @testset "test_removing_style_tags" begin
    orig = """<p><style>hey now</style></p>"""
    html = HTMLSanitizer.sanitize(orig)
    @test !occursin("style", html)
  end

  @testset "test_removing_style_attributes" begin
    orig = """<p style='font-size:1000%'>YO DAWG</p>"""
    html = HTMLSanitizer.sanitize(orig)
    @test !occursin("font-size", html)
    @test !occursin("style", html)
  end

  @testset "test_removing_script_event_handler_attributes" begin
    orig = """<a onclick='javascript:alert(0)'>YO DAWG</a>"""
    html = HTMLSanitizer.sanitize(orig)
    @test !occursin("javscript", html)
    @test !occursin("onclick", html)
  end

  # @testset "test_sanitizes_li_elements_not_contained_in_ul_or_ol" begin
  #   orig = "a\n<li>b</li>\nc"
  #   html  = HTMLSanitizer.sanitize(orig)
  #   @test """a\nb\nc""" == html
  # end

  @testset "test_does_not_sanitize_li_elements_contained_in_ul_or_ol" begin
    stuff = "a\n<ul><li>b</li></ul>\nc"
    @test stuff == HTMLSanitizer.sanitize(stuff)
  end

  @testset "test_unknown_schemes_are_removed" begin
    stuff = """<a href="something-weird://heyyy">Wat</a> is this"""
    html  = HTMLSanitizer.sanitize(stuff)
    @test """<a>Wat</a> is this""" == html
  end

  @testset "test_whitelisted_longdesc_schemes_are_allowed" begin
    stuff = """<img longdesc="http://longdesc.com" src="./foo.jpg"/>"""
    html  = HTMLSanitizer.sanitize(stuff)
    @test stuff == html
  end

  @testset "test_weird_longdesc_schemes_are_removed" begin
    stuff = """<img src="./foo.jpg" longdesc="javascript:alert(1)"/>"""
    html  = HTMLSanitizer.sanitize(stuff)
    @test """<img src="./foo.jpg"/>""" == html
  end

  @testset "test_standard_schemes_are_removed_if_not_specified_in_anchor_schemes" begin
    stuff  = """<a href="http://www.example.com/">No href for you</a>"""
    nohrefwhitelist = merge(HTMLSanitizer.WHITELIST, Dict(:protocols => Dict("a" => Dict("href" => []))))
    html  = HTMLSanitizer.sanitize(stuff, whitelist = nohrefwhitelist)
    @test """<a>No href for you</a>""" == html
  end

  @testset "test_custom_anchor_schemes_are_not_removed" begin
    stuff  = """<a href="something-weird://heyyy">Wat</a> is this"""
    weirdwhitelist = merge(HTMLSanitizer.WHITELIST, Dict(:protocols => Dict("a" => Dict("href" => ["something-weird"]))))
    html  = HTMLSanitizer.sanitize(stuff, whitelist = weirdwhitelist)
    @test stuff == html
  end

  @testset "test_script_contents_are_removed1" begin
    orig = """<div><script>JavaScript!</script></div>"""
    @test "<div></div>" == HTMLSanitizer.sanitize(orig)
  end

  @testset "test_script_contents_are_removed2" begin
    orig = """<script>JavaScript!</script>"""
    @test "" == HTMLSanitizer.sanitize(orig)
  end

  # @testset "test_table_rows_and_cells_removed_if_not_in_table" begin
  #   orig = """<tr><td>Foo</td></tr><td>Bar</td>"""
  #   assert_equal 'FooBar', SanitizationFilter.call(orig).to_s
  # end

  # @testset "test_table_sections_removed_if_not_in_table" begin
  #   orig = """<thead><tr><td>Foo</td></tr></thead>"""
  #   assert_equal 'Foo', SanitizationFilter.call(orig).to_s
  # end

  @testset "test_table_sections_are_not_removed" begin
    orig = """
      <table>
      <thead><tr><th>Column 1</th></tr></thead>
      <tfoot><tr><td>Sum</td></tr></tfoot>
      <tbody><tr><td>1</td></tr></tbody>
      </table>"""
    @test replace(orig, "\n" => "") == replace(HTMLSanitizer.sanitize(orig), "\n" => "")
  end

  @testset "test_summary_tag_are_not_removed" begin
    orig = """<summary>Foo</summary>"""
    @test orig == HTMLSanitizer.sanitize(orig)
  end

  @testset "test_details_tag_and_open_attribute_are_not_removed" begin
    orig = """<details open>Foo</details>"""
    @test """<details open="">Foo</details>""" == HTMLSanitizer.sanitize(orig)
  end

  @testset "test_nested_details_tag_are_not_removed" begin
    orig = """
      <details>
        <summary>Foo</summary>
        <details>
          Bar
          <summary>Baz</summary>
        </details>
        Qux
      </details>"""
    @test replace(orig, "\n" => "") == replace(HTMLSanitizer.sanitize(orig), "\n" => "")
  end
end

@testset "preserve relevant whitespace" begin
  orig = """
  <!DOCTYPE html>
  <html>
    <head>
      <meta description="test page"></meta>
    </head>
    <body>
      <p>A simple test page.</p>
      <a></a>
      <a></a>
      <pre>
          <code>
  foo
  bar
  baz
          </code>
      </pre>
    </body>
  </html>
  """
  expected = "<HTML>\n    \n  \n  \n    <p>A simple test page.</p>\n    <a></a>\n    <a></a>\n    <pre>        <code>\nfoo\nbar\nbaz\n        </code>\n    </pre>\n  \n\n</HTML>"
  @test sanitize(orig, isfragment=false) == expected
end

@testset "urls" begin
  @testset "relative" begin
    orig = """<img src="foo/bar.html"/>"""
    @test sanitize(orig) == orig

    orig = """<img src="/foo/bar.html"/>"""
    @test sanitize(orig) == orig

    orig = """<img src="//foo/bar.html"/>"""
    @test sanitize(orig) == orig

    orig = """<img src="./foo/bar.html"/>"""
    @test sanitize(orig) == orig

    orig = """<img src="/asd://foo/bar.html"/>"""
    @test sanitize(orig) == orig
  end

  @testset "protocols" begin
    orig = """<img src="asd://foo/bar.html"/>"""
    @test sanitize(orig) == "<img/>"

    orig = """<img src="http://foo/bar.html"/>"""
    @test sanitize(orig) == orig

    orig = """<img src="https://foo/bar.html"/>"""
    @test sanitize(orig) == orig
  end
end

@testset "edge case" begin
  html = read(joinpath(@__DIR__, "testhtml.html"), String)
  sanitize(html) == read(joinpath(@__DIR__, "testhtml_out.html"), String)
end

@testset "relative urls" begin
  @test HTMLSanitizer.is_relative_url("/foo")
  @test HTMLSanitizer.is_relative_url("//foo")
  @test HTMLSanitizer.is_relative_url("./foo")
  @test HTMLSanitizer.is_relative_url("../foo")
  @test HTMLSanitizer.is_relative_url("foo")
  @test !HTMLSanitizer.is_relative_url("https://foo")
  @test !HTMLSanitizer.is_relative_url("http://foo")
  @test !HTMLSanitizer.is_relative_url("bar://foo")
end

include("malicious_html.jl")
