-module(fb_signed_request_test).

-compile(export_all).

% Include etest's assertion macros.
-include_lib("etest/include/etest.hrl").

-define(FB_SECRET, "897z956a2z7zzzzz5783z458zz3z7556").
-define(VALID_REQ, "53umfudisP7mKhsi9nZboBg15yMZKhfQAARL9UoZtSE.eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsImV4cGlyZXMiOjEzMDg5ODg4MDAsImlzc3VlZF9hdCI6MTMwODk4NTAxOCwib2F1dGhfdG9rZW4iOiIxMTExMTExMTExMTExMTF8Mi5BUUJBdHRSbExWbndxTlBaLjM2MDAuMTExMTExMTExMS4xLTExMTExMTExMTExMTExMXxUNDl3M0Jxb1pVZWd5cHJ1NTFHcmE3MGhFRDgiLCJ1c2VyIjp7ImNvdW50cnkiOiJkZSIsImxvY2FsZSI6ImVuX1VTIiwiYWdlIjp7Im1pbiI6MjF9fSwidXNlcl9pZCI6IjExMTExMTExMTExMTExMSJ9").
-define(INVALID_REQ_1, "umfudisP7mKhsi9nZboBg15yMZKhfQAARL9UoZtSE.eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsImV4cGlyZXMiOjEzMDg5ODg4MDAsImlzc3VlZF9hdCI6MTMwODk4NTAxOCwib2F1dGhfdG9rZW4iOiIxMTExMTExMTExMTExMTF8Mi5BUUJBdHRSbExWbndxTlBaLjM2MDAuMTExMTExMTExMS4xLTExMTExMTExMTExMTExMXxUNDl3M0Jxb1pVZWd5cHJ1NTFHcmE3MGhFRDgiLCJ1c2VyIjp7ImNvdW50cnkiOiJkZSIsImxvY2FsZSI6ImVuX1VTIiwiYWdlIjp7Im1pbiI6MjF9fSwidXNlcl9pZCI6IjExMTExMTExMTExMTExMSJ9").
-define(INVALID_REQ_2, "53umfudisP7mKhsi9nZboBg15yMZKhfQAARL9UoZtSE.eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsImV4cGlyZXMiOjEzMDg5ODg4MDAsImlzc3VlZF9hdCI6MTMwODk4NTAxOCwib2F1dGhfdG9rZW4iOiIxMTExMTExMTExMTExMTF8Mi5BUUJBdHRSbExWbndxTlBaLjM2MDAuMTExMTExMTExMS4xLTExMTExMTExMTExMTExMXxUNDl3M0Jxb1pVZWd5cHJ1NTFHcmE3MGhFRDgiLCJ1c2VyIjp7ImNvdW50cnkiOiJkZSIsImxvY2FsZSI6ImVuX1VTIiwiYWdlIjp7Im1pbiI6MjF9fSwidXNlcl9pZCI6IjExMTExMTExMTExMTExMSJ").
-define(EXPECTED_VALID_DATA, {[
    {<<"algorithm">>,<<"HMAC-SHA256">>},
    {<<"expires">>,1308988800},
    {<<"issued_at">>,1308985018},
    {<<"oauth_token">>,<<"111111111111111|2.AQBAttRlLVnwqNPZ.3600.1111111111.1-111111111111111|T49w3BqoZUegypru51Gra70hED8">>},
    {<<"user">>,{[
        {<<"country">>,<<"de">>},
        {<<"locale">>,<<"en_US">>},
        {<<"age">>,{[
            {<<"min">>,21}
        ]}}
    ]}},
    {<<"user_id">>,<<"111111111111111">>}
]}).


test_parsing_a_valid_request() ->
    Result = fb_signed_request:parse(?VALID_REQ, ?FB_SECRET),
    ?assert_equal({ok, ?EXPECTED_VALID_DATA}, Result).


test_parsing_a_invalid_request() ->
    Result = fb_signed_request:parse(?INVALID_REQ_1, ?FB_SECRET),
    ?assert_equal({error, <<"Invalid Signature">>}, Result).


test_parsing_another_invalid_request() ->
    Result = fb_signed_request:parse(?INVALID_REQ_2, ?FB_SECRET),
    ?assert_equal({error, <<"Invalid Payload">>}, Result).


test_generating_and_parsing_and_validating_a_request() ->
    SignedRequest       = fb_signed_request:generate(?EXPECTED_VALID_DATA, ?FB_SECRET),
    ?assert_equal(?VALID_REQ, SignedRequest),
    {ok, ParsedRequest} = fb_signed_request:parse(SignedRequest, ?FB_SECRET),
    ?assert_equal(ParsedRequest, ?EXPECTED_VALID_DATA).
