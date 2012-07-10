# Facebook Signed Request

This is a small library to parse, validate and generate signed requests from /
for facebook. It depends on etest for testing and jiffy for json parsing.

[![Build Status](https://secure.travis-ci.org/wooga/fb_signed_request.png?branch=master)](http://travis-ci.org/wooga/fb_signed_request)

## Usage


```erlang

% Parsing a signed request from Facebook
% Input can be list or bitstring
% Payload data will be returned as bitstring
Req = "Z9Xn16Pdo5ac9YWDh5HD70aujhsZ9eCoyPMcpd2aaiM.eyJhbGdvcml0aG0iOiJITUFDLVN"
      "IQTI1NiIsImV4cGlyZXMiOjEzMDg5ODg4MDAsImlzc3VlZF9hdCI6MTMwODk4NTAxOCwib2"
      "F1dGhfdG9rZW4iOiIxMTExMTExMTExMTExMTF8Mi5BUUJBdHRSbExWbndxTlBaLjM2MDAuM"
      "TExMTExMTExMS4xLTExMTExMTExMTExMTExMXxUNDl3M0Jxb1pVZWd5cHJ1NTFHcmE3MGhF"
      "RDgiLCJ1c2VyIjp7ImFnZSI6eyJtaW4iOjIxfSwiY291bnRyeSI6ImRlIiwibG9jYWxlIjo"
      "iZW5fVVMifSwidXNlcl9pZCI6IjExMTExMTExMTExMTExMSJ9",

{ok, Data} = fb_signed_request:parse(Req, FacebookAppSecret).


% If the request is invalid the following return values are expected:
{error, invalid_format}
{error, invalid_signature}
{error, invalid_payload}
{error, unsupported_algorithm}


% Generate a signed request (useful for testing)
Json = <<"{\"algorithm\":\"HMAC-SHA256\",\"expires\":1308988800,"
         "\"issued_at\":1308985018,\"oauth_token\":\"11|2.SOMETOKEN\","
         "\"user\":{\"age\":{\"min\":21},\"country\":\"de\","
         "\"locale\":\"en_US\"},\"user_id\":\"111111111111111\"}">>

SignedRequest = fb_signed_request:generate(Json, FacebookAppSecret).

% If you want generate to return a bitstring you can call:
fb_signed_request:generate(Json, FacebookAppSecret, [{return,binary}]).
```

## Installation

Add the following line to your rebar.config

```erlang
{fb_signed_request, ".*", {git, "git://github.com/wooga/fb_signed_request.git"}}
```
