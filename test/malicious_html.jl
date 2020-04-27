@testset "malicious html" begin
    # https://github.com/rgrove/sanitize/blob/master/test/test_malicious_html.rb

  @testset "comments" begin
    @testset "should not allow script injection via conditional comments" begin
      @test "" == HTMLSanitizer.sanitize("""<!--[if gte IE 4]>\n<script>alert('XSS');</script>\n<![endif]-->""")
    end
  end

  @testset "<body>" begin
    @testset "should not be possible to inject JS via a malformed event attribute" begin
      whitelist = deepcopy(HTMLSanitizer.WHITELIST)
      append!(whitelist[:elements], ["body", "head"])
      @test """<HTML><head></head><body></body></HTML>""" == HTMLSanitizer.sanitize("""<html><head></head><body onload!#\$%&()*~+-_.,:;?@[/|\\]^`=alert("XSS")></body></html>""", isfragment = false, whitelist = whitelist)
    end
  end

  @testset "<iframe>" begin
    @testset "should not be possible to inject an iframe using an improperly closed tag" begin
      @test "" == HTMLSanitizer.sanitize("""<iframe src=http://ha.ckers.org/scriptlet.html <""")
    end
  end

  @testset "<img>" begin
    @testset "should not be possible to inject JS via an unquoted <img> src attribute" begin
      @test "<img></img>" == HTMLSanitizer.sanitize("""<img src=javascript:alert('XSS')>""")
    end

    @testset "should not be possible to inject JS using grave accents as <img> src delimiters" begin
      @test "<img></img>" == HTMLSanitizer.sanitize("""<img src=`javascript:alert('XSS')`>""")
    end

    @testset "should not be possible to inject <script> via a malformed <img> tag" begin
      @test """<img></img>&quot;&gt;""" == HTMLSanitizer.sanitize("""<img \"\"\"><script>alert("XSS")</script>">""")
    end

    @testset "should not be possible to inject protocol-based JS" begin
      @test "<img></img>" == HTMLSanitizer.sanitize("""<img src=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>""")

      @test "<img></img>" == HTMLSanitizer.sanitize("""<img src=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>""")

      @test "<img></img>" == HTMLSanitizer.sanitize("""<img src=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>""")

      # Encoded tab character.
      @test "<img></img>" == HTMLSanitizer.sanitize("""<img src="jav&#x09;ascript:alert('XSS');">""")

      # Encoded newline.
      @test "<img></img>" == HTMLSanitizer.sanitize("""<img src="jav&#x0A;ascript:alert('XSS');">""")

      # Encoded carriage return.
      @test "<img></img>" == HTMLSanitizer.sanitize("""<img src="jav&#x0D;ascript:alert('XSS');">""")

      # Spaces plus meta char.
      @test "<img></img>" == HTMLSanitizer.sanitize("""<img src=" &#14;  javascript:alert('XSS');">""")

      # Mixed spaces and tabs.
      @test "<img></img>" == HTMLSanitizer.sanitize("""<img src="j\na v\tascript://alert('XSS');">""")
    end

    @testset "should not be possible to inject protocol-based JS via whitespace" begin
      @test "<img></img>" == HTMLSanitizer.sanitize("""<img src="jav\tascript:alert('XSS');">""")
    end

    @testset "should not be possible to inject JS using a half-open <img> tag" begin
      @test """""" == HTMLSanitizer.sanitize("""<img src="javascript:alert('XSS')" """)
    end
  end
end
