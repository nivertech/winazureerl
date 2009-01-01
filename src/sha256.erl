%%% File    : sha256.erl
%%% Author  : Steve Vinoski <vinoski@ieee.org>
%%% Description : SHA 256 algorithm implemented by adapting the pseudocode provided by this Wikipedia article:
%%%                   <http://en.wikipedia.org/wiki/SHA1>
%%%               The code uses binaries rather than arrays or lists where possible.
%%% Created : 31 Dec 2008 by Steve Vinoski <vinoski@ieee.org>
%%%
%%% Copyright (c) 2008 Stephen B. Vinoski
%%% All rights reserved.
%%%
%%% Redistribution and use in source and binary forms, with or without
%%% modification, are permitted provided that the following conditions
%%% are met:
%%% 1. Redistributions of source code must retain the above copyright
%%%    notice, this list of conditions and the following disclaimer.
%%% 2. Redistributions in binary form must reproduce the above copyright
%%%    notice, this list of conditions and the following disclaimer in the
%%%    documentation and/or other materials provided with the distribution.
%%% 3. Neither the name of the copyright holder nor the names of contributors
%%%    may be used to endorse or promote products derived from this software
%%%    without specific prior written permission.
%%% 
%%% THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTOR(S) ``AS IS'' AND
%%% ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
%%% IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
%%% ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTOR(S) BE LIABLE
%%% FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
%%% DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
%%% OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
%%% HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
%%% LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
%%% OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
%%% SUCH DAMAGE.

-module(sha256).
-export([hexdigest/1, digest/1, test/0]).
-version(1.0).

-define(H, [16#6A09E667, 16#BB67AE85, 16#3C6EF372, 16#A54FF53A,
            16#510E527F, 16#9B05688C, 16#1F83D9AB, 16#5BE0CD19]).

-define(K, <<16#428A2F98:32/big-unsigned, 16#71374491:32/big-unsigned, 16#B5C0FBCF:32/big-unsigned,
            16#E9B5DBA5:32/big-unsigned, 16#3956C25B:32/big-unsigned, 16#59F111F1:32/big-unsigned,
            16#923F82A4:32/big-unsigned, 16#AB1C5ED5:32/big-unsigned, 16#D807AA98:32/big-unsigned,
            16#12835B01:32/big-unsigned, 16#243185BE:32/big-unsigned, 16#550C7DC3:32/big-unsigned,
            16#72BE5D74:32/big-unsigned, 16#80DEB1FE:32/big-unsigned, 16#9BDC06A7:32/big-unsigned,
            16#C19BF174:32/big-unsigned, 16#E49B69C1:32/big-unsigned, 16#EFBE4786:32/big-unsigned,
            16#0FC19DC6:32/big-unsigned, 16#240CA1CC:32/big-unsigned, 16#2DE92C6F:32/big-unsigned,
            16#4A7484AA:32/big-unsigned, 16#5CB0A9DC:32/big-unsigned, 16#76F988DA:32/big-unsigned,
            16#983E5152:32/big-unsigned, 16#A831C66D:32/big-unsigned, 16#B00327C8:32/big-unsigned,

            16#06CA6351:32/big-unsigned, 16#14292967:32/big-unsigned, 16#27B70A85:32/big-unsigned,
            16#2E1B2138:32/big-unsigned, 16#4D2C6DFC:32/big-unsigned, 16#53380D13:32/big-unsigned,
            16#650A7354:32/big-unsigned, 16#766A0ABB:32/big-unsigned, 16#81C2C92E:32/big-unsigned,
            16#92722C85:32/big-unsigned, 16#A2BFE8A1:32/big-unsigned, 16#A81A664B:32/big-unsigned,
            16#C24B8B70:32/big-unsigned, 16#C76C51A3:32/big-unsigned, 16#D192E819:32/big-unsigned,
            16#D6990624:32/big-unsigned, 16#F40E3585:32/big-unsigned, 16#106AA070:32/big-unsigned,
            16#19A4C116:32/big-unsigned, 16#1E376C08:32/big-unsigned, 16#2748774C:32/big-unsigned,
            16#34B0BCB5:32/big-unsigned, 16#391C0CB3:32/big-unsigned, 16#4ED8AA4A:32/big-unsigned,
            16#5B9CCA4F:32/big-unsigned, 16#682E6FF3:32/big-unsigned, 16#748F82EE:32/big-unsigned,
            16#78A5636F:32/big-unsigned, 16#84C87814:32/big-unsigned, 16#8CC70208:32/big-unsigned,
            16#90BEFFFA:32/big-unsigned, 16#A4506CEB:32/big-unsigned, 16#BEF9A3F7:32/big-unsigned,
            16#C67178F2:32/big-unsigned>>).

-define(ADD32(X, Y), (X + Y) band 16#FFFFFFFF).


hexdigest(M) when is_binary(M) ->
    lists:flatten([io_lib:format("~8.16.0b", [V]) || V <- local_sha256(split_binary(sha256_pad(M), 64), ?H)]);

hexdigest(Str) ->
    hexdigest(list_to_binary(Str)).
   
digest(M) when is_binary(M) ->
     unhex(hexdigest(M),[]);
   
digest(Str) ->
    digest(list_to_binary(Str)).

rotate(V, Count) ->
    Rest = 32 - Count,
    <<Top:Rest/unsigned, Bottom:Count/unsigned>> = <<V:32/big-unsigned>>,
    <<New:32/big-unsigned>> = <<Bottom:Count/unsigned, Top:Rest/unsigned>>,
    New.

sha256_pad(M) ->
    Len = size(M),
    Len_bits = Len*8,
    Pad_bits = (Len + 8 + 1) rem 64,
    Pad = case Pad_bits of
              0 -> 0;
              _ -> (64 - Pad_bits) * 8
          end,
    list_to_binary([M, <<16#80:8, 0:Pad, Len_bits:64/big-unsigned>>]).

local_sha256_extend(W, 64) ->
    W;
local_sha256_extend(W, Count) ->
    Off1 = (Count - 15) * 4,
    Off2 = (Count - 2) * 4 - Off1 - 4,
    <<_:Off1/binary, Word1:32/big-unsigned, _:Off2/binary, Word2:32/big-unsigned, _/binary>> = <<W/binary>>,
    S0 = rotate(Word1, 7) bxor rotate(Word1, 18) bxor (Word1 bsr 3),
    S1 = rotate(Word2, 17) bxor rotate(Word2, 19) bxor (Word2 bsr 10),
    Off3 = (Count - 16) * 4,
    Off4 = (Count - 7) * 4 - Off3 - 4,
    <<_:Off3/binary, W16:32/big-unsigned, _:Off4/binary, W7:32/big-unsigned, _/binary>> = <<W/binary>>,
    Next = (W16 + S0 + W7 + S1) band 16#FFFFFFFF,
    local_sha256_extend(<<W/binary, Next:32/big-unsigned>>, Count+1).

local_sha256_loop(_W, Hashes, Next, 64) ->
    lists:map(fun({X, Y}) -> ?ADD32(X, Y) end, lists:zip(Hashes, Next));
local_sha256_loop(W, Hashes, [A, B, C, D, E, F, G, H], Count) ->
    S0 = rotate(A, 2) bxor rotate(A, 13) bxor rotate(A, 22),
    Maj = (A band B) bxor (A band C) bxor (B band C),
    T2 = ?ADD32(S0, Maj),
    S1 = rotate(E, 6) bxor rotate(E, 11) bxor rotate(E, 25),
    Ch = (E band F) bxor (((bnot E) + 1 + 16#FFFFFFFF) band G),
    Offset = Count * 4,
    <<_:Offset/binary, K:32/big-unsigned, _/binary>> = ?K,
    <<_:Offset/binary, Wval:32/big-unsigned, _/binary>> = <<W/binary>>,
    T1 = (H + S1 + Ch + K + Wval) band 16#FFFFFFFF,
    local_sha256_loop(W, Hashes, [?ADD32(T1, T2), A, B, C, ?ADD32(D, T1), E, F, G], Count+1).

local_sha256(M, Hashes) when is_binary(M) ->
    Words64 = local_sha256_extend(M, 16),
    local_sha256_loop(Words64, Hashes, Hashes, 0);
local_sha256({M, <<>>}, Hashes) ->
    local_sha256(M, Hashes);
local_sha256({M, T}, Hashes) ->
    local_sha256(split_binary(T, 64), local_sha256(M, Hashes)).

%%% These are adapted from ssl_debug module and covered by the Erlang Public License

is_hex_digit(C) when C >= $0, C =< $9 -> true;
is_hex_digit(C) when C >= $A, C =< $F -> true;
is_hex_digit(C) when C >= $a, C =< $f -> true;
is_hex_digit(_) -> false.

unhex([], Acc) ->
    lists:reverse(Acc);
unhex([_], Acc) ->
    unhex([], Acc);
unhex([$  | Tl], Acc) ->
    unhex(Tl, Acc);
unhex([D1, D2 | Tl], Acc) ->
    case {is_hex_digit(D1), is_hex_digit(D2)} of
        {true, true} ->
            unhex(Tl, [erlang:list_to_integer([D1, D2], 16) | Acc]);
        _ ->
            unhex([], Acc)
    end.

%%% These tests come from <http://www.aarongifford.com/computers/sha.html>. The "Base" variable in test1/3
%%% below is expected to be the basename of the test vectors from that website, as set in test/0. The tests
%%% read the test data from those files and compare against the expected results. Download this file to get
%%% the test data: <http://www.aarongifford.com/computers/sha2-1.0.tar.gz>. The test data in the "Expected"
%%% list in test/0 below is copied from that file and is thus subject to the following license:
%%%
%%% Copyright (c) 2000-2001, Aaron D. Gifford
%%% All rights reserved.
%%%
%%% Redistribution and use in source and binary forms, with or without
%%% modification, are permitted provided that the following conditions
%%% are met:
%%% 1. Redistributions of source code must retain the above copyright
%%%    notice, this list of conditions and the following disclaimer.
%%% 2. Redistributions in binary form must reproduce the above copyright
%%%    notice, this list of conditions and the following disclaimer in the
%%%    documentation and/or other materials provided with the distribution.
%%% 3. Neither the name of the copyright holder nor the names of contributors
%%%    may be used to endorse or promote products derived from this software
%%%    without specific prior written permission.
%%% 
%%% THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTOR(S) ``AS IS'' AND
%%% ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
%%% IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
%%% ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTOR(S) BE LIABLE
%%% FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
%%% DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
%%% OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
%%% HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
%%% LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
%%% OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
%%% SUCH DAMAGE.

test() ->
    Base = "/usr/local/src/sha2-1.0/testvectors/vector0",
    Expected = ["ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
                "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
                "4d25fccf8752ce470a58cd21d90939b7eb25f3fa418dd2da4c38288ea561e600",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "ab64eff7e88e2e46165e29f2bce41826bd4c7b3552f6b382a9e7d3af47c245f8",
                "f08a78cbbaee082b052ae0708f32fa1e50c5c421aa772ba5dbb406a2ea6be342",
                "0ab803344830f92089494fb635ad00d76164ad6e57012b237722df0d7ad26896",
                "e4326d0459653d7d3514674d713e74dc3df11ed4d30b4013fd327fdb9e394c26",
                "a7f001d996dd25af402d03b5f61aef950565949c1a6ad5004efa730328d2dbf3",
                "6dcd63a07b0922cc3a9b3315b158478681cc32543b0a4180abe58a73c5e14cc2",
                "af6ebfde7d93d5badb6cde6287ecc2061c1cafc5b1c1217cd984fbcdb9c61aaa",
                "8ff59c6d33c5a991088bc44dd38f037eb5ad5630c91071a221ad6943e872ac29",
                "1818e87564e0c50974ecaabbb2eb4ca2f6cc820234b51861e2590be625f1f703",
                "5e3dfe0cc98fd1c2de2a9d2fd893446da43d290f2512200c515416313cdf3192",
                "80fced5a97176a5009207cd119551b42c5b51ceb445230d02ecc2663bbfb483a",
                "88ee6ada861083094f4c64b373657e178d88ef0a4674fce6e4e1d84e3b176afb",
                "5a2e925a7f8399fa63a20a1524ae83a7e3c48452f9af4df493c8c51311b04520"],
    test1(Expected, Base, 1).

test1(_, _, 19) ->
    ok;
test1([Expect|T], Base, Count) ->
    {ok, Vector} = file:read_file(lists:flatten(io_lib:format("~s~2.10.0b.dat", [Base, Count]))),
    Result = digest(Vector),
    try
        Result = Expect,
        io:format("test ~p passed~n", [Count]),
        test1(T, Base, Count+1)
    catch _:_ ->
            io:format("error: expected ~s, got ~s~n", [Expect, Result]),
            error
    end.
