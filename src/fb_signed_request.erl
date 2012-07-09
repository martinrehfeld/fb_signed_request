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
                jiffy:encode(
                    pack(Payload)
                )
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
        unpack(
            jiffy:decode(
                base64:decode_to_string(
                    base64_pad(Payload)
                )
            )
        )
    catch
        _:_ -> throw({fb_signed_request, <<"Invalid Payload">>})
    end.


%% @doc does what it says
validate_signature( Signature, Payload, Secret ) ->
    try
        ComputedSignature = create_signature(Payload, Secret),
        ComputedSignature = Signature
    catch
        error:{badmatch,_} -> throw({fb_signed_request, <<"Invalid Signature">>})
    end.


%% @doc Calculate signature from Json and FB App Secret
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


%% @doc Strip trailing '=' from base64 because that is how facebook rolls
strip_padding( Signature ) ->
    {ok, Regex} = ?PADDING,
    case re:replace(Signature, Regex, "", [global, {return, list}]) of
        [Result|[]] -> Result;
        Result      -> Result
    end.


%% @doc Add trailing '=' from base64 string
base64_pad(String) ->
    Length = length(String),
    Remainder = Length rem 4,
    ToPad = case Remainder of
        0 -> 0;
        N -> 4 - N
    end,
    string:left(String, Length + ToPad, $=).


% JSON is encoded from and decoded to recursive JSON-structures as used by
% jiffy, see https://github.com/davisp/jiffy for more information.
% Thus any structure obtained via jiffy:decode needs to be unpacked first.
% That is stripped of extra tuples and list constructors.

%% @doc Attempts to extract a orddict from the given jiffy-JSON.
unpack(Json) when is_list(Json) orelse is_tuple(Json) ->
  unpack(Json, orddict:new());


%% Only tuples and list require deeper unpacking, return simple structs.
unpack(Json) -> Json.


%% @doc Recursively unpacks a nested jiffy-JSON object.
unpack({Proplist}, Dict) when is_list(Proplist) ->
  lists:foldl(
    fun({Key, Value}, Acc) ->
      orddict:store(Key, unpack(Value), Acc)
    end,
    Dict,
    Proplist
  );


% List of jiffy-JSON => list of unpacked structs.
unpack(List, _) when is_list(List) ->
  [unpack(Elem) || Elem <- List].


%% @doc Recursively builds a jiffy-JSON struct from the given orddict.
% Single orddict => jiffy-JSON object.
pack(Orddict = [Head|_]) when is_list(Orddict) andalso is_tuple(Head) ->
  {orddict:fold(
    fun(Key, Value, Acc) ->
      Acc ++ [{Key, pack(Value)}]
    end,
    [],
    Orddict
  )};


% Treat the empty list as an empty object.
pack([]) -> [];


% List of orddicts => list of jiffy-JSON objects.
pack(List) when is_list(List) ->
  [pack(Elem) || Elem <- List];


pack(undefined) -> null;


% Simple term => same simple term.
pack(Value) -> Value.
