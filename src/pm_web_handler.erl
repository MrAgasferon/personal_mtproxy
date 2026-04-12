%%%-------------------------------------------------------------------
%% @doc Cowboy handler for JSON API endpoints
%% POST   /api/proxies                  → register new proxy, return JSON
%% DELETE /api/proxies?subdomain=<sub>  → revoke proxy
%% GET    /api/proxies                  → list all proxies
%% GET    /api/config                   → proxy config (secret, port, domain)
%% PATCH  /api/proxies?subdomain=<sub>  → update active/expires_at
%% GET    /api/connections              → active connections per subdomain
%% GET    /api/metrics                  → Prometheus metrics as JSON
%% @end
%%%-------------------------------------------------------------------
-module(pm_web_handler).
-export([init/2]).
-include_lib("kernel/include/logger.hrl").

init(Req, State) ->
    {Code, Body, Req1} = handle(Req),
    Reply = cowboy_req:reply(Code, #{<<"content-type">> => <<"application/json">>}, jsx:encode(Body), Req1),
    {ok, Reply, State}.

handle(Req = #{method := <<"POST">>, path := <<"/api/proxies">>}) ->
    {ok, Body, Req1} = cowboy_req:read_body(Req),
    Params = uri_string:dissect_query(Body),
    Email = proplists:get_value(<<"email">>, Params, <<>>),
    ExpiresAt = case proplists:get_value(<<"expires_at">>, Params) of
        undefined -> 0;
        V -> try binary_to_integer(V) catch _:_ -> 0 end
    end,
    {ok, BaseDomain} = application:get_env(personal_mtproxy, base_domain),
    case pm_registry:register(Email, list_to_binary(BaseDomain), ExpiresAt) of
        {ok, Subdomain, Port, BaseSecret} ->
            Secret = iolist_to_binary([<<"ee">>,
                           string:lowercase(BaseSecret),
                           string:lowercase(binary:encode_hex(Subdomain))]),
            Query = uri_string:compose_query([
              {<<"server">>, list_to_binary(BaseDomain)},
              {<<"port">>,   integer_to_binary(Port)},
              {<<"secret">>, Secret}
            ]),
            TmeLink = iolist_to_binary(uri_string:recompose(
              #{scheme => <<"https">>, host => <<"t.me">>, path => <<"/proxy">>, query => Query})),
            TgLink = iolist_to_binary(uri_string:recompose(
              #{scheme => <<"tg">>, host => <<"proxy">>, path => <<>>, query => Query})),
            {200, #{subdomain => Subdomain, link => TmeLink, tg_link => TgLink}, Req1};
        {error, Reason} ->
            ErrMsg = iolist_to_binary(io_lib:format("~p", [Reason])),
            {500, #{error => ErrMsg}, Req1}
    end;

handle(Req = #{method := <<"PATCH">>, path := <<"/api/proxies">>}) ->
    Params = cowboy_req:parse_qs(Req),
    case proplists:get_value(<<"subdomain">>, Params) of
        undefined ->
            {400, #{error => <<"missing subdomain parameter">>}, Req};
        Subdomain ->
            {ok, Body, Req1} = cowboy_req:read_body(Req),
            BodyParams = uri_string:dissect_query(Body),
            Results = lists:filtermap(
                fun({<<"active">>, Val}) ->
                    Active = Val =:= <<"true">>,
                    case pm_registry:set_active(Subdomain, Active) of
                        ok -> {true, {active, Active}};
                        {error, R} -> {true, {error, R}}
                    end;
                   ({<<"expires_at">>, Val}) ->
                    ExpiresAt = try binary_to_integer(Val) catch _:_ -> 0 end,
                    case pm_registry:set_expires(Subdomain, ExpiresAt) of
                        ok -> {true, {expires_at, ExpiresAt}};
                        {error, R} -> {true, {error, R}}
                    end;
                   (_) -> false
                end, BodyParams),
            case lists:keyfind(error, 1, Results) of
                {error, not_found} -> {404, #{error => <<"subdomain not found">>}, Req1};
                _ -> {200, #{ok => true}, Req1}
            end
    end;

handle(Req = #{method := <<"DELETE">>, path := <<"/api/proxies">>}) ->
    Params = cowboy_req:parse_qs(Req),
    case proplists:get_value(<<"subdomain">>, Params) of
        undefined ->
            {400, #{error => <<"missing subdomain parameter">>}, Req};
        Subdomain ->
            case pm_registry:revoke(Subdomain) of
                ok ->
                    {200, #{ok => true}, Req};
                {error, not_found} ->
                    {404, #{error => <<"subdomain not found">>}, Req}
            end
    end;

handle(Req = #{method := <<"GET">>, path := <<"/api/config">>}) ->
    {ok, [#{port := Port, secret := Secret} | _]} = application:get_env(mtproto_proxy, ports),
    {ok, BaseDomain} = application:get_env(personal_mtproxy, base_domain),
    Salt = case application:get_env(mtproto_proxy, per_sni_secret_salt) of
        {ok, S} -> S;
        undefined -> null
    end,
    {200, #{port => Port,
            secret => string:lowercase(Secret),
            base_domain => list_to_binary(BaseDomain),
            per_sni_secret_salt => Salt}, Req};

handle(Req = #{method := <<"GET">>, path := <<"/api/proxies">>}) ->
    Entries = pm_registry:list(),
    Now = erlang:system_time(second),
    List = [#{subdomain => Sub,
              email => Email,
              registered_at => Ts,
              expires_at => ExpiresAt,
              active => Active,
              expired => (ExpiresAt > 0 andalso ExpiresAt < Now)}
            || {Sub, Email, Ts, ExpiresAt, Active} <- Entries],
    {200, List, Req};

handle(Req = #{method := <<"GET">>, path := <<"/api/connections">>}) ->
    Entries = ets:tab2list(mtp_policy_counter),
    List = [#{subdomain => iolist_to_binary(Sub), connections => Count}
            || {[Sub], Count} <- Entries],
    {200, List, Req};

handle(Req = #{method := <<"GET">>, path := <<"/api/metrics">>}) ->
    case httpc:request(get, {"http://127.0.0.1:9091/metrics", []}, [], []) of
        {ok, {{_, 200, _}, _, Body}} ->
            Lines = string:split(Body, "\n", all),
            Metrics = lists:filtermap(fun(Line) ->
                case Line of
                    <<"#", _/binary>> -> false;
                    <<>> -> false;
                    _ ->
                        case binary:split(Line, <<" ">>) of
                            [Name, Value] -> {true, #{name => Name, value => Value}};
                            _ -> false
                        end
                end
            end, [list_to_binary(L) || L <- Lines]),
            {200, Metrics, Req};
        _ ->
            {503, #{error => <<"metrics unavailable">>}, Req}
    end;

handle(Req) ->
    {404, #{error => <<"not found">>}, Req}.
