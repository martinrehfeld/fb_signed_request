-module(fb_signed_request).

-export([parse/2, generate/2]).

-define( PADDING, re:compile("(=|%3d)+$", [caseless]) ).


parse( Request, Secret ) ->
    try
        [Signature, Payload] = extract_signature_and_payload(Request),
        Data                 = decode_body(Payload),
        validate_signature(Signature, Payload, Secret),
        {ok, Data}
    catch
        {fb_signed_request, Message} -> {error, Message}
    end.


generate( Payload, Secret ) ->
    EncodedPayload = url_safe(
        strip_padding(
            base64:encode_to_string(
                jiffy:encode(Payload)
            )
        )
    ),

    EncodedSignature = create_signature(EncodedPayload, Secret),
    lists:flatten([EncodedSignature, ".", EncodedPayload]).


extract_signature_and_payload(Request) ->
    try
        re:split(Request, "\\.", [{return, list}])
    catch
        _:_ -> throw({fb_signed_request, <<"Invalid format of signed request">>})
    end.


decode_body( Payload ) ->
    try
        jiffy:decode(
            base64:decode_to_string(
                base64_pad(Payload)
            )
        )
    catch
        _:_ -> throw({fb_signed_request, <<"Invalid Payload">>})
    end.


validate_signature( Signature, Payload, Secret ) ->
    try
        ComputedSignature = create_signature(Payload, Secret),
        ComputedSignature = Signature
    catch
        error:{badmatch,_} -> throw({fb_signed_request, <<"Invalid Signature">>})
    end.


create_signature(Payload, Secret) ->
    strip_padding(
        url_safe(
            base64:encode_to_string(
                hmac:hmac256(Secret, Payload)
            )
        )
    ).


%% @doc Transforms the given signature into a URL-safe format.
url_safe(Signature) ->
    lists:map(fun(Element) ->
        case Element of
            43 -> 45;
            47 -> 95;
            _  -> Element
        end
    end,
    Signature
  ).


strip_padding( Signature ) ->
    {ok, Regex} = ?PADDING,
    case re:replace(Signature, Regex, "", [global, {return, list}]) of
        [Result|[]] -> Result;
        Result      -> Result
    end.


base64_pad(String) ->
    Length = length(String),
    Remainder = Length rem 4,
    ToPad = case Remainder of
        0 -> 0;
        N -> 4 - N
    end,
    string:left(String, Length + ToPad, $=).