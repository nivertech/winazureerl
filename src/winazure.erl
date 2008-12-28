%%%-------------------------------------------------------------------
%%% File    : winazure.erl
%%% Author  :  Sriram Krishnan<mail@sriramkrishnan.com>
%%%-------------------------------------------------------------------
-module(winazure).
-behaviour(gen_server).

%% API
-export([start/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-record(state, {}).

%%====================================================================
%% API
%%====================================================================
start() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

create_container(ContainerName, IsPublic) ->
     gen_server:call(?MODULE, {put, container, ContainerName, IsPublic}).

delete_container(ContainerName) ->
    gen_server:call(?MODULE, {delete, container, ContainerName}).

put_blob(ContainerName, Key, Data, ContentType)->
    gen_server:call(?MODULE, { put, blob, ContainerName, Key, Data, ContentType}).

get_blob(ContainerName, Key) ->
    gen_server:call(?MODULE, {get, blob, ContainerName, Key}).


%%====================================================================
%% gen_server callbacks
%%====================================================================

init([]) ->
    crypto:start(),
    inets:start(),
    {ok}.

handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------

blobStorageUrl (Local) ->
    case Local of
	true ->
	    "127.0.0.1:10000";
	false ->
	    "blob.core.windows.net"	    
    end.
    
