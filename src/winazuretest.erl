-module(winazuretest).

-export([test/0]).


test() ->
    winazure:start({"devstoreaccount1", "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==",true}),
    winazure:create_container("test",true),
    winazure:put_blob("test","blob1","Hello!","text/plain"),
    "Hello!" = winazure:get_blob("test","blob1"),
    winazure:delete_blob("test","blob1"),
    winazure:delete_container("test").
