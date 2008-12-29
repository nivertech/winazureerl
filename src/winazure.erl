%%%-------------------------------------------------------------------
%%% File    : winazure.erl
%%% Author  :  Sriram Krishnan<mail@sriramkrishnan.com>
%%%-------------------------------------------------------------------
-module(winazure).
-behaviour(gen_server).

%% API
-export([start/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).



%%====================================================================
%% API
%%====================================================================
start({Account, Key, IsLocal}) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, {Account, Key, IsLocal}, []).

create_container(ContainerName, IsPublic) ->
     gen_server:call(?MODULE, {put, container, ContainerName, IsPublic}).

delete_container(ContainerName) ->
    gen_server:call(?MODULE, {delete, container,  ContainerName}).

put_blob(ContainerName, Data, ContentType)->
    gen_server:call(?MODULE, { put, blob, ContainerName,   Data, ContentType}).

get_blob(ContainerName) ->
    gen_server:call(?MODULE, {get, blob, ContainerName}).


%%====================================================================
%% gen_server callbacks
%%====================================================================

init({Account, Key, IsLocal}) ->
    crypto:start(),
    inets:start(),
    {ok, {Account, Key, IsLocal}}.

handle_call({put, container, ContainerName, IsPublic}, _From, {Account, Key, IsLocal}) ->

    %% If public container, add right HTTP header
    CustomHeaders = case IsPublic of
			true -> [{"x-ms-prop-publicaccess", "true"}];
			_-> []
		    end,
	  
    Reply = do_request(Account, Key, IsLocal, ContainerName, "","PUT", CustomHeaders, "", ""),

    {reply, Reply, {Account, Key, IsLocal}}.

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

do_request(Account, Key, IsLocal, ContainerName, ResourcePath, HttpMethod, CustomHeaders, ContentType, Data)->
    %% Generate the correct headers
    %% Content-Type is required even if blank
    %% Date should be in RFC 1123 format

    Date = httpd_util:rfc1123_date(),

    HeadersToSign =[      
		     {"x-ms-date", Date},
		     {"Content-Type", ContentType}
			 | CustomHeaders],

    Path = "/" ++ Account ++ "/" ++ ContainerName ++ "/" ++ ResourcePath,
    
    Authorization = get_auth_header( Path, HttpMethod, HeadersToSign, Key, Data, ContentType),
    

    Headers = [ 
		{"Authorization", "SharedKey" ++ Account ++ ":" ++ Authorization},
		{ "Content-Length", integer_to_list(size(Data))}
		| HeadersToSign],

    Options = [ {sync, true}, {headers_as_is, true}],
    
    Url = construct_url(Account, ContainerName, IsLocal) ++ ResourcePath,

    Request =  { Url, Headers, ContentType, Data},

    Reply = http:request( HttpMethod, Request, [], Options),
    
    case Reply of
	{ ok, {{_HttpVersion, Code, _ReasonPhrase}, ResponseHeaders, ResponseBody}}
	when Code=:= 200 
	     ->
	    ResponseBody;
	{ok, {{_HttpVersion, Code, _ReasonPhrase}, ResponseHeaders, ResponseBody}}
	->
	    throw( ResponseBody)
    end.


get_auth_header (Path, HttpMethod, HeadersToSign, Key, Data, ContentType) ->
    %% Generate string to sign. Algorithm from http://msdn.microsoft.com/en-us/library/dd179428.aspx    
    %%     StringToSign = VERB + "\n" + 
    %%                       Content-MD5 + "\n" + 
    %%                       Content-Type + "\n" +
    %%                       Date + "\n" +
    %%                       CanonicalizedHeaders + "\n" +
    %%                       CanonicalizedResource

    %% Get all the headers that start with x-ms- prefix
    MS_Header_Keys = [HeaderKey || {HeaderKey, HeaderValue} <- HeadersToSign, lists:prefix("x-ms", HeaderKey)],

    Sorted_MS_Header_Keys = lists:sort(MS_Header_Keys),
    
    %% Using sorted headers, construct CanonicalizedHeaders element. This is basically all the custom headers
    %% sorted lexicographically and output one after another in the form header:value\n.  Note that this doesn't
    %% implement the spec fully in things like collapsing multiple values and so on
    
    
    CanonicalHeaderFun = fun( HeaderKey, AccIn) ->
				 %% Find matching value for sorted header key
				 {value, {HeaderKey, HeaderValue}} = lists:keysearch(HeaderKey, 1, MS_Header_Keys), 
				 %% Add to incoming accumulator and return
				 AccIn ++ HeaderKey ++ ":" ++ HeaderValue ++ "\n" end,

    CanonicalHeaders = lists:foldl(CanonicalHeaderFun , "", Sorted_MS_Header_Keys),

    CanonicalResource = Path,
    
    %% Construct string to sign with blank Content-MD5 since it is optional. Date can be left blank since we specify with x-ms-date
    StringToSign = HttpMethod ++ "\n\n" ++ ContentType++ "\n\n" ++ CanonicalHeaders ++ "\n" ++ CanonicalResource ,
    
    %% INCORRECT! Erlang doesn't support sha256 out of the box - this code is left as placeholder
    binary_to_list( base64:encode( crypto:sha_mac(Key, StringToSign))).

    			    
construct_url(Account, ContainerName, IsLocal) ->
    case IsLocal of
	true ->
	    "http://127.0.0.1:10000/" ++ Account ++ "/" ++ ContainerName ++ "/"; 
	false ->
	    "http://" ++ Account ++ ".blob.core.windows.net/" ++ ContainerName ++ "/"
    end.

    
