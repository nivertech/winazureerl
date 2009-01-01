%%%-------------------------------------------------------------------
%%% File    : hmac256.erl
%%% Author  :  Sriram Krishnan<mail@sriramkrishnan.com>
%%% Description : HMAC-SHA256 implementation. Implementation based on Wikipedia's
%% pseudocode description of HMAC.  Relies on Steve Vinoski's SHA256 implementation
%%% from http://steve.vinoski.net/code/sha256.erl
%%%
%%% Created : 30 Dec 2008
%%%-------------------------------------------------------------------

-module(hmac256).
-export([hexdigest/2,digest/2,test/0]).
-version(1.0).

hexdigest(Key, Data)->
    digest(Key, Data, true).

digest(Key, Data) ->
    digest(Key, Data, false).

digest(Key, Data, Hex) -> 
    BlockSize = 64,
    
    %% Initialize OPad and IPad arrays filled with magic 0x5c and 0x36 values
    %% respectively. The arrays need to be of the same size as the block length 
    OPad = array:new( [{size,BlockSize},{fixed,true},{default,92}]),
    IPad = array:new ( [{size,BlockSize},{fixed,true},{default,54}]),

    
    
    %% If key is longer than block size, hash it to bring it below block size
    if
	length(Key)>BlockSize -> ShortHashKey = array:from_list(sha256:digest(Key));
	true-> ShortHashKey = array:from_list(Key) 
    end,
    

    HashKey = array:resize(BlockSize, ShortHashKey), %% Zero-pad array


    PadUpdateFunc =  fun (Index, Term) ->
		      
		       KeyTerm =  array:get(Index, HashKey),
		       if 
			   KeyTerm=:= undefined -> Term bxor 0;
			   true -> Term bxor KeyTerm
		       end
	       end, 

    OPadUpdated = array:map(PadUpdateFunc, OPad),
    IPadUpdated = array:map(PadUpdateFunc, IPad),
    
    FinalTransform = OPadUpdated:to_list() ++ sha256:digest( IPadUpdated:to_list() ++ Data),
    
    if
	Hex =:= true -> sha256:hexdigest(FinalTransform);
	Hex=:= false -> sha256:digest( FinalTransform)
    end.




test() ->  
    %% Test cases taken from Python's HMAC 256 test cases

    test(lists:duplicate(20, 11), "Hi There", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
    
    test("Jefe","what do ya want for nothing?","5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),

    test(lists:duplicate(20,170), lists:duplicate(50, 221), "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),

    test(lists:duplicate(131, 170), "Test Using Larger Than Block-Size Key - Hash Key First", "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),

    test(lists:duplicate(131, 170), "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.", "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"),

    ok.
    
test(Key, Data, Expect) ->
    Result = hexdigest(Key, Data),
    try
	Result = Expect,
	io:format("Passed!\n")
    catch _:_ ->
	    io:format("error: expected ~s , got ~s~n", [Expect, Result]),
	    error
    end.
