-- Boat registry for the harbour game
local json = require("dkjson")
local util = require "util"

--[[ Block comment:
     boats are tables ]]
local Boats = {}

function Boats.new(name)
  return { name = name }
end

local function count(list)
  return #list
end

return Boats
