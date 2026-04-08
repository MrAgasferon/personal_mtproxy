%%% @doc
%%% Prometheus metrics backend for mtproto_proxy and personal_mtproxy.
%%%
%%% Serves two roles:
%%%   1. metric_backend for mtp_metric (implements notify/4)
%%%   2. prometheus_collector for passive metrics (implements collect_mf/2)
%%%
%%% Call init/0 before starting supervisors to declare all metrics and
%%% register this module as a collector. Until init/0 is called, notify/4
%%% silently returns ok (guarded by persistent_term).
%%% @end

-module(pm_prometheus).

-behaviour(prometheus_collector).

%% metric_backend API (called by mtp_metric)
-export([notify/4]).

%% Public API for personal_mtproxy modules
-export([count_inc/3]).

%% Lifecycle
-export([init/0]).

%% prometheus_collector callbacks
-export([deregister_cleanup/1, collect_mf/2]).

-define(PT_KEY, {?MODULE, label_orders}).
-define(MTP_APP, mtproto_proxy).
-define(PM_APP, personal_mtproxy).

%% ===================================================================
%% Lifecycle
%% ===================================================================

-spec init() -> ok.
init() ->
    AllActive = mtp_metric:active_metrics() ++ pm_active_metrics(),
    Lookup =
        lists:foldl(
          fun({Type, Name, Doc, Opts}, Acc) ->
                  MetricAtom = name_to_atom(Name),
                  declare_metric(Type, MetricAtom, Doc, Opts),
                  Acc#{Name => MetricAtom}
          end,
          #{},
          AllActive),
    persistent_term:put(?PT_KEY, Lookup),
    prometheus_registry:register_collector(?MODULE),
    ok.

%% ===================================================================
%% metric_backend callbacks (called by mtp_metric:notify/4)
%% ===================================================================

%% Extra = #{labels => [Val1, Val2, ...]} with values pre-ordered by the call site
notify(Type, Name, Value, Extra) ->
    case persistent_term:get(?PT_KEY, undefined) of
        undefined ->
            ok;
        Lookup ->
            MetricAtom = maps:get(Name, Lookup),
            LabelValues = maps:get(labels, Extra, []),
            dispatch(Type, MetricAtom, LabelValues, Value)
    end.

%% ===================================================================
%% Public API for personal_mtproxy modules
%% ===================================================================

-spec count_inc(Name :: atom(), Value :: number(), Labels :: [term()]) -> ok.
count_inc(Name, Value, LabelValues) ->
    case persistent_term:get(?PT_KEY, undefined) of
        undefined -> ok;
        _         -> prometheus_counter:inc(Name, LabelValues, Value)
    end.

%% ===================================================================
%% prometheus_collector callbacks
%% ===================================================================

deregister_cleanup(_Registry) ->
    ok.

collect_mf(_Registry, Callback) ->
    collect_mtp_passive(Callback),
    collect_pm_passive(Callback),
    ok.

collect_mtp_passive(Callback) ->
    lists:foreach(
      fun({Type, Name, Doc, TaggedValues}) ->
              MF = prometheus_model_helpers:create_mf(
                     name_to_atom(Name), Doc, prometheus_type(Type),
                     [{maps:to_list(Tags), Val} || {Tags, Val} <- TaggedValues]),
              Callback(MF)
      end,
      mtp_metric:passive_metrics()).

collect_pm_passive(Callback) ->
    Callback(prometheus_model_helpers:create_mf(
               personal_mtproxy_registered_subdomains,
               "Number of registered personal subdomains",
               gauge,
               [{[], pm_registry:size()}])).

%% ===================================================================
%% Internal
%% ===================================================================

pm_active_metrics() ->
    [{count, [?PM_APP, registration, total],
      "Personal proxy registration attempts",
      #{labels => [result]}},
     {count, [?PM_APP, revocation, total],
      "Personal proxy revocation attempts",
      #{labels => [result]}},
     {count, [?PM_APP, slug_collision, total],
      "Slug generation collisions",
      #{}}].

declare_metric(count, Name, Doc, Opts) ->
    prometheus_counter:declare(
      [{name, Name}, {help, Doc} | maps:to_list(maps:with([labels], Opts))]);
declare_metric(gauge, Name, Doc, Opts) ->
    prometheus_gauge:declare(
      [{name, Name}, {help, Doc} | maps:to_list(maps:with([labels], Opts))]);
declare_metric(histogram, Name, Doc, Opts) ->
    Pairs = maps:to_list(maps:with([labels, buckets, duration_unit], Opts)),
    prometheus_histogram:declare([{name, Name}, {help, Doc} | Pairs]).

dispatch(count, Name, LabelValues, Value) ->
    prometheus_counter:inc(Name, LabelValues, Value);
dispatch(gauge, Name, LabelValues, Value) ->
    prometheus_gauge:set(Name, LabelValues, Value);
dispatch(histogram, Name, LabelValues, Value) ->
    prometheus_histogram:observe(Name, LabelValues, Value).

name_to_atom([A]) ->
    A;
name_to_atom([A1, A2]) ->
    binary_to_atom(<<(atom_to_binary(A1))/binary, "_",
                     (atom_to_binary(A2))/binary>>);
name_to_atom([A1, A2, A3]) ->
    binary_to_atom(<<(atom_to_binary(A1))/binary, "_",
                     (atom_to_binary(A2))/binary, "_",
                     (atom_to_binary(A3))/binary>>);
name_to_atom([A1, A2, A3, A4]) ->
    binary_to_atom(<<(atom_to_binary(A1))/binary, "_",
                     (atom_to_binary(A2))/binary, "_",
                     (atom_to_binary(A3))/binary, "_",
                     (atom_to_binary(A4))/binary>>);
name_to_atom(More) ->
    list_to_atom(string:join([atom_to_list(A) || A <- More], "_")).

prometheus_type(count)     -> counter;
prometheus_type(gauge)     -> gauge;
prometheus_type(histogram) -> histogram.
