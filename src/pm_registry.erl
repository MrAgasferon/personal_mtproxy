%%%-------------------------------------------------------------------
%% @doc Personal domain registry: DETS persistence + registration
%% @end
%%%-------------------------------------------------------------------

-module(pm_registry).

-behaviour(gen_server).

-export([start_link/0, register/2, revoke/1, list/0, size/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-include_lib("kernel/include/logger.hrl").

-define(SERVER, ?MODULE).
-define(APP, personal_mtproxy).
-define(DETS_TABLE, pm_subdomains).

-record(state, {dets_ref}).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% Register a new personal subdomain under BaseDomain.
register(Email, BaseDomain) ->
    gen_server:call(?SERVER, {register, Email, BaseDomain}).

revoke(Subdomain) ->
    gen_server:call(?SERVER, {revoke, Subdomain}).

list() ->
    gen_server:call(?SERVER, list).

size() ->
    case dets:info(?DETS_TABLE, size) of
        undefined -> 0;
        N         -> N
    end.

init([]) ->
    {ok, DetsFile} = application:get_env(?APP, dets_file),

    {ok, DetsRef} = dets:open_file(?DETS_TABLE, [{file, DetsFile}, {keypos, 1}]),

    ok = dets:foldl(
      fun({Subdomain, _Email, _Timestamp}, ok) ->
              mtp_policy_table:add(personal_domains, tls_domain, Subdomain)
      end,
      ok, DetsRef),

    {ok, #state{dets_ref = DetsRef}}.

handle_call({register, Email, BaseDomain}, _From, State = #state{dets_ref = DetsRef}) ->
    case generate_slug(DetsRef, BaseDomain, 5) of
        {error, Reason} ->
            pm_prometheus:count_inc(personal_mtproxy_registration_total, 1, [error]),
            {reply, {error, Reason}, State};
        Subdomain ->
            {ok, [#{port := Port, secret := BaseSecret} | _]} = application:get_env(mtproto_proxy, ports),
            ok = dets:insert(DetsRef, {Subdomain, Email, erlang:system_time(second)}),
            ok = mtp_policy_table:add(personal_domains, tls_domain, Subdomain),
            pm_prometheus:count_inc(personal_mtproxy_registration_total, 1, [ok]),
            {reply, {ok, Subdomain, Port, BaseSecret}, State}
    end;

handle_call({revoke, Subdomain}, _From, State = #state{dets_ref = DetsRef}) ->
    case dets:lookup(DetsRef, Subdomain) of
        [] ->
            pm_prometheus:count_inc(personal_mtproxy_revocation_total, 1, [not_found]),
            {reply, {error, not_found}, State};
        _ ->
            ok = dets:delete(DetsRef, Subdomain),
            ok = mtp_policy_table:del(personal_domains, tls_domain, Subdomain),
            pm_prometheus:count_inc(personal_mtproxy_revocation_total, 1, [ok]),
            {reply, ok, State}
    end;

handle_call(list, _From, State = #state{dets_ref = DetsRef}) ->
    Entries = dets:match_object(DetsRef, {'_', '_', '_'}),
    {reply, Entries, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{dets_ref = DetsRef}) ->
    ok = dets:close(DetsRef),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% Private helpers

generate_slug(DetsRef, BaseDomain, Retries) ->
    case Retries of
        0 ->
            {error, max_retries};
        _ ->
            Slug = [($a + rand:uniform(26) - 1) || _ <- lists:seq(1, 5)],
            Subdomain = list_to_binary(Slug ++ "." ++ BaseDomain),
            case dets:lookup(DetsRef, Subdomain) of
                [] ->
                    Subdomain;
                _ ->
                    pm_prometheus:count_inc(personal_mtproxy_slug_collision_total, 1, []),
                    generate_slug(DetsRef, BaseDomain, Retries - 1)
            end
    end.
