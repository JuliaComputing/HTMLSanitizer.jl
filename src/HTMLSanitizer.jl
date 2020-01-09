module HTMLSanitizer

using Gumbo

export sanitize

"""
    sanitize(input::AbstractString; isfragment = true, whitelist = WHITELIST, prettyprint = false)

Sanitizes the HTML input according to `whitelist`.

- `isfragment`: If true, removes enclosing `<HTML>` tags from the output.
- `whitelist`: Whitelist for allowed elements and attributes.
- `prettyprint`: Returns a prettier multiline string instead of a somewhat minified version.
"""
function sanitize(input::AbstractString; isfragment = true, whitelist = WHITELIST, prettyprint = false)
    input_preserve_ws = replace(input, r"(\s+)"s => s" 🐑\1🐑 ")
    doc = parsehtml(input_preserve_ws)

    sanitize_bfs(doc.root, whitelist)

    out = IOBuffer()
    print(out, doc.root, pretty = prettyprint)

    out = String(take!(out))
    out = replace(out, r"\s?🐑(\s+)🐑\s?"s => s"\1")

    if isfragment
        out = replace(out, r"^<HTML>" => "")
        out = replace(out, r"</HTML>$" => "")
    else
        return out
    end
end

reparent!(_, _) = nothing

reparent!(node::HTMLElement, parent) = node.parent = parent

# HTMLText isn't mutable, so this does nothing. Will lead to inconsistencies, but ¯\_(ツ)_/¯.
reparent!(node::HTMLText, parent) = nothing

function sanitize_bfs(tree, whitelist)
    i = 1
    while i <= length(tree.children)
        el = tree.children[i]

        sanitized = sanitize_element(el, whitelist)
        if sanitized isa Vector
            # reparent all nodes
            reparent!.(sanitized, Ref(tree))
            splice!(tree.children, i, sanitized)
            i += length(sanitized)
        else
            # reparent node
            reparent!(sanitized, tree)
            tree.children[i] = sanitized
            i += 1
        end
    end
    sanitize_bfs.(tree.children, Ref(whitelist))
end

sanitize_bfs(tree::HTMLText, whitelist) = nothing

function sanitize_element(el::HTMLElement{TAG}, whitelist) where TAG
    tag = string(TAG)

    @debug("Sanitizing `$(tag)`.")

    if !(tag in get(whitelist, :elements, []))
        @debug("Element `$(tag)` not in whitelist.")
        if tag in get(whitelist, :remove_contents, [])
            @debug("Removing contents for `$(tag)`.")
            return Gumbo.HTMLText("")
        end
        @debug("Replacing `$(tag)` with its contents.")
        out = sanitize_element.(el.children, Ref(whitelist))
        return isempty(out) ? Gumbo.HTMLText("") : out
    end

    el = sanitize_attributes(el, whitelist)

    return el
end

sanitize_element(el::HTMLElement{:HTML}, whitelist) = el

sanitize_element(el::HTMLText, whitelist) = el

const REGEX_PROTOCOL = r"\A\s*([^\/#]*?)(?:\:|&#0*58|&#x0*3a)"i

function sanitize_attributes(el::HTMLElement{TAG}, whitelist) where TAG
    tag = string(TAG)
    attributes = attrs(el)
    protocols = get(get(whitelist, :protocols, Dict()), tag, Dict())

    attributes_for_tag = get(get(whitelist, :attributes, Dict()), tag, [])
    attributes_for_all = get(get(whitelist, :attributes, Dict()), :ALL, [])

    for (attr, val) in attributes
        if !(attr in attributes_for_tag) && !(attr in attributes_for_all)
            # not in whitelist, so remove the attribute altogether
            @debug("Deleting attribute `$(attr)` in element `$(tag)` (not in whitelist).")
            delete!(attributes, attr)
        elseif haskey(protocols, attr)
            # allowed, but only specific values are ok
            is_acceptable = false

            if occursin(REGEX_PROTOCOL, val)
                # looks like a protocol is specified
                if any(startswith.(Ref(lowercase(val)), string.(protocols[attr])))
                    is_acceptable = true
                end
            else
                if :relative in protocols[attr] && is_relative_url(val)
                    is_acceptable = true
                end
            end

            if !is_acceptable
                @debug("Deleting attribute `$(attr)` in element `$(tag)` (does not conform to protocol).")
                delete!(attributes, attr)
            end
        end
    end

    return el
end

function is_relative_url(url)
    startswith(url, "./")
end

"""
Default whitelist. Allows many elements and attributes, but crucially removes `<script>` elements
as well as `style` attributes.
"""
const WHITELIST = Dict(
    :elements => [
        "h1","h2","h3","h4","h5","h6","h7","h8","br","b","i","strong","em","a","pre","code","img","tt",
        "div","ins","del","sup","sub","p","ol","ul","table","thead","tbody","tfoot","blockquote",
        "dl","dt","dd","kbd","q","samp","var","hr","ruby","rt","rp","li","tr","td","th","s","strike",
        "summary","details","caption","figure","figcaption","abbr","bdo","cite","dfn","mark",
        "small","span","time","wbr"
    ],
    :remove_contents => ["script"],
    :attributes => Dict(
        "a"          => ["href"],
        "img"        => ["src", "longdesc"],
        "div"        => ["itemscope", "itemtype"],
        "blockquote" => ["cite"],
        "del"        => ["cite"],
        "ins"        => ["cite"],
        "q"          => ["cite"],
        :ALL         => [
            "abbr", "accept", "accept-charset",
            "accesskey", "action", "align", "alt",
            "aria-describedby", "aria-hidden", "aria-label", "aria-labelledby",
            "axis", "border", "cellpadding", "cellspacing", "char",
            "charoff", "charset", "checked",
            "clear", "cols", "colspan", "color",
            "compact", "coords", "datetime", "dir",
            "disabled", "enctype", "for", "frame",
            "headers", "height", "hreflang",
            "hspace", "ismap", "label", "lang",
            "maxlength", "media", "method",
            "multiple", "name", "nohref", "noshade",
            "nowrap", "open", "prompt", "readonly", "rel", "rev",
            "rows", "rowspan", "rules", "scope",
            "selected", "shape", "size", "span",
            "start", "summary", "tabindex", "target",
            "title", "type", "usemap", "valign", "value",
            "vspace", "width", "itemprop"
        ]
    ),
    :protocols => Dict(
        "a"          => Dict("href" => ["http", "https", "mailto", :relative]),
        "img"        => Dict(
            "src"      => ["http", "https", :relative],
            "longdesc" => ["http", "https", :relative]),
        "blockquote" => Dict("cite" => ["http", "https", :relative]),
        "del"        => Dict("cite" => ["http", "https", :relative]),
        "ins"        => Dict("cite" => ["http", "https", :relative]),
        "q"          => Dict("cite" => ["http", "https", :relative]),
    )
)

"""
Similar to the default whitelist, but only allows very few elements types.
"""
const LIMITED = merge(WHITELIST, Dict(
    :elements => ["b", "i", "strong", "em", "a", "pre", "code", "img", "ins", "del", "sup", "sub", "mark", "abbr", "p", "ol", "ul", "li"]
))

end # module
