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
    stuff = """<img longdesc="http://longdesc.com"src="./foo.jpg"></img>"""
    html  = HTMLSanitizer.sanitize(stuff)
    @test stuff == html
  end

  @testset "test_weird_longdesc_schemes_are_removed" begin
    stuff = """<img src="./foo.jpg" longdesc="javascript:alert(1)"></img>"""
    html  = HTMLSanitizer.sanitize(stuff)
    @test """<img src="./foo.jpg"></img>""" == html
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

  @testset "test_script_contents_are_removed" begin
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
    @test replace(orig, '\n' => "") == HTMLSanitizer.sanitize(orig)
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
      </details>
    """
    @test replace(orig, r"[\s\n]" => "") == replace(HTMLSanitizer.sanitize(orig), r"[\s\n]" => "")
  end
end

include("malicious_html.jl")
