# Tide model in Julia
module Tides

using Statistics
import LinearAlgebra

#= Harmonic
   model =#
struct Constituent
    period::Float64
end

function predict(c::Constituent, t)
    cos(2π * t / c.period)
end

end # module
