%%% File    : winazure.erl
%%% Author  : Sriram Krishnan <mail@sriramkrishnan.com>
%%% Description : Storage client library for Windows Azure storage



-module(winazure).
-behaviour(gen_server).

%% API
-export([start/1, create_container/2, put_blob/4, get_blob/2, delete_blob/2, delete_container/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(LOGGING, false).


%%====================================================================
%% API
%%====================================================================
start({Account, Key, IsLocal}) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, {Account, Key, IsLocal}, []).

create_container(ContainerName, IsPublic) ->
     gen_server:call(?MODULE, {put, container, ContainerName, IsPublic}).

delete_container(ContainerName) ->
    gen_server:call(?MODULE, {delete, container,  ContainerName}).

put_blob(ContainerName, BlobName, Data, ContentType)->
    gen_server:call(?MODULE, { put, blob, ContainerName,   BlobName, Data, ContentType}).

get_blob(ContainerName, BlobName) ->
    gen_server:call(?MODULE, {get, blob, ContainerName, BlobName}).

delete_blob(ContainerName, BlobName) ->
    gen_server:call(?MODULE, {delete, blob, ContainerName, BlobName}).

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

    {reply, Reply, {Account, Key, IsLocal}};


handle_call({delete, container, ContainerName}, _From, {Account, Key, IsLocal}) ->
	  
    Reply = do_request(Account, Key, IsLocal, ContainerName, "","DELETE", [], "", ""),

    {reply, Reply, {Account, Key, IsLocal}};

handle_call({put, blob, ContainerName, BlobName, Data, ContentType}, _From, {Account, Key, IsLocal}) ->
    
    Reply = do_request(Account, Key, IsLocal, ContainerName, BlobName, "PUT", [], ContentType, Data), 
    
    {reply, Reply, {Account, Key, IsLocal}};

handle_call({get,blob, ContainerName, BlobName}, _From, {Account, Key, IsLocal}) ->
    Reply = do_request(Account, Key, IsLocal, ContainerName, BlobName, "GET", [], "",""), 
    {reply, Reply, {Account, Key, IsLocal}};

handle_call({delete,blob, ContainerName, BlobName}, _From, {Account, Key, IsLocal}) ->
    Reply = do_request(Account, Key, IsLocal, ContainerName, BlobName, "DELETE", [], "",""), 
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

    case ResourcePath of 
	[] -> ResourcePathToConcat = "";
	_-> ResourcePathToConcat = "/" ++ ResourcePath      
    end,

    %% Storage is finicky about trailing slashes so do the right thing
    case IsLocal of
	true ->  Path = "/" ++ Account ++ "/" ++Account ++ "/" ++ ContainerName ++  ResourcePathToConcat;
        _ ->  Path = "/" ++ Account ++ "/" ++ ContainerName ++   ResourcePathToConcat
    end,
   
    Authorization = get_auth_header( Path, HttpMethod, HeadersToSign, Key,  ContentType),
   
    case Data of
	"" -> ContentLength = 0;
	[] -> ContentLength = 0;
	_ ->  ContentLength = length(Data)
    end,
  
    Headers = [ 
		{"Authorization", "SharedKey " ++ Account ++ ":" ++ Authorization},
		{ "Content-Length", integer_to_list(ContentLength)}
		| HeadersToSign],

    Options = [ {sync, true}, {headers_as_is, true}],
    
  
    Url = construct_url(Account, ContainerName, IsLocal) ++   ResourcePathToConcat,
    
    Method = list_to_atom(string:to_lower(HttpMethod)),

    case Method of
	put -> Request =  { Url, Headers, ContentType, Data};
	get -> Request = { Url, Headers};
	delete -> Request = { Url, Headers}
    end,
   
    %% Fiddler
    %%http:set_options([{ proxy, {{"localhost", 8888}, []}}]),
    
    %% Though there's a warning that this is an invalid option, the doc supports this
    %% and this seems to be the only way to force it to speak HTTP 1.0. Suppress the
    %% warning
    error_logger:tty(false),
    Reply =  http:request( Method, Request, [{version,"HTTP/1.0"}], Options),
    error_logger:tty(true),

    case Reply of
	{ ok, {{_, Code, _}, _, ResponseBody}}
	when Code=:= 200 ; Code =:= 201; Code =:= 202
	     ->
	    if
		ResponseBody =:= [] ->
		    ok; %% Why doesn't Erlang like an empty list returned? Grr.
		true ->
		    ResponseBody
	    end;
	 
		    

	{ok, {{_, _, _}, _, ResponseBody}}
	->
	
	    io:format("~p~n", [Reply]),
	    io:format("~p~n", [construct_url(Account, ContainerName, IsLocal)]),
	    io:format("~p~n", [Request]),
	
	    throw( ResponseBody)
    end.


get_auth_header (Path, HttpMethod, HeadersToSign, Key,  ContentType) ->
    %% Generate string to sign. Algorithm from http://msdn.microsoft.com/en-us/library/dd179428.aspx    
    %%     StringToSign = VERB + "\n" + 
    %%                       Content-MD5 + "\n" + 
    %%                       Content-Type + "\n" +
    %%                       Date + "\n" +
    %%                       CanonicalizedHeaders + "\n" +
    %%                       CanonicalizedResource

    %% Get all the headers that start with x-ms- prefix
    MS_Header_Keys = [HeaderKey || {HeaderKey, _} <- HeadersToSign, lists:prefix("x-ms", HeaderKey)],

    Sorted_MS_Header_Keys = lists:sort(MS_Header_Keys),
    
    %% Using sorted headers, construct CanonicalizedHeaders element. This is basically all the custom headers
    %% sorted lexicographically and output one after another in the form header:value\n.  Note that this doesn't
    %% implement the spec fully in things like collapsing multiple values and so on
    
    
    
    CanonicalHeaderFun = fun( HeaderKey, AccIn) ->
				 %% Find matching value for sorted header key
				 {value, {HeaderKey, HeaderValue}} = lists:keysearch(HeaderKey, 1, HeadersToSign), 
				 %% Add to incoming accumulator and return
				 AccIn ++ HeaderKey ++ ":" ++ HeaderValue ++ "\n" end,

    CanonicalHeaders = lists:foldl(CanonicalHeaderFun , "", Sorted_MS_Header_Keys),

    CanonicalResource = Path,
    
    %% Construct string to sign with blank Content-MD5 since it is optional. Date can be left blank since we specify with x-ms-date
    StringToSign = HttpMethod ++ "\n\n" ++ ContentType++ "\n\n" ++ CanonicalHeaders ++  CanonicalResource ,
    
    
    if 
	?LOGGING =:= true ->
	    io:format("String to sign: ~p \n\n",[StringToSign]),
	    io:format("digest: ~p ~n", [hmac256:digest(Key, StringToSign)]);
	true -> ok
    end,
    
    
%% Sign using home grown HMAC 256 implementation
    DecodedKey = base64:decode(Key),
    binary_to_list( base64:encode( hmac256:digest(binary_to_list(DecodedKey), StringToSign))).

    			    
construct_url(Account, ContainerName, IsLocal) ->
    case IsLocal of
	true ->
	    "http://127.0.0.1:10000/" ++ Account ++ "/" ++ ContainerName; 
	false ->
	    "http://" ++ Account ++ ".blob.core.windows.net/" ++ ContainerName
    end.

    
