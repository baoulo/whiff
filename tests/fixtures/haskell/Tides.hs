-- | Tide predictions.
module Harbour.Tides (predict) where

import Data.List (sortOn)
import qualified Data.Map as Map

{- A block
   comment -}
data Tide = High | Low deriving (Show)

newtype Height = Height Double

predict :: Double -> [Tide]
predict _ = [High, Low]
