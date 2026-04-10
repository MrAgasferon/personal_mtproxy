%%%-------------------------------------------------------------------
%% @doc Basic Auth middleware for Cowboy
%% Protects /admin.html and /api/* with HTTP Basic Authentication.
%% Password is read from application env: {admin_password, "..."}
%% @end
%%%-------------------------------------------------------------------
-module(pm_auth_middleware).
-behaviour(cowboy_middleware).
-export([execute/2]).
-include_lib("kernel/include/logger.hrl").

execute(Req, Env) ->
    Path = cowboy_req:path(Req),
    try
        case needs_auth(Path) of
            false ->
                {ok, Req, Env};
            true ->
                case check_auth(Req) of
                    ok ->
                        {ok, Req, Env};
                    unauthorized ->
                        Req1 = cowboy_req:reply(401,
                            #{<<"www-authenticate">> => <<"Basic realm=\"MTProxy Admin\"">>},
                            <<"Unauthorized">>, Req),
                        {stop, Req1}
                end
        end
    catch
        Class:Reason:Stack ->
            ?LOG_ERROR("Auth middleware crash: ~p:~p ~p", [Class, Reason, Stack]),
            Req2 = cowboy_req:reply(500, #{}, <<"Internal error">>, Req),
            {stop, Req2}
    end.

needs_auth(<<"/admin.html">>) -> true;
needs_auth(<<"/api/", _/binary>>) -> true;
needs_auth(_) -> false.

check_auth(Req) ->
    {ok, AdminPass} = application:get_env(personal_mtproxy, admin_password),
    AdminPassBin = list_to_binary(AdminPass),
    try cowboy_req:parse_header(<<"authorization">>, Req) of
        {basic, _User, Pass} when Pass =:= AdminPassBin ->
            ok;
        _ ->
            unauthorized
    catch
        _:_ ->
            unauthorized
    end.
