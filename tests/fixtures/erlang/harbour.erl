%% Harbour server
-module(harbour).
-export([start/0, count/1]).
-include_lib("kernel/include/logger.hrl").

start() ->
    ok.

count(Boats) when is_list(Boats) ->
    length(Boats).
