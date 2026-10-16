# Tide analysis in R
library(ggplot2)
require("dplyr")

load_tides <- function(path) {
  read.csv(path)  # TODO: validate columns
}

mean_height = function(df) mean(df$height_m)
