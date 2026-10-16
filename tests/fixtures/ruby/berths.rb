# frozen_string_literal: true
# Berth allocation for the harbour.
require 'json'
require_relative 'boat'

module Harbour
  class Berth
    attr_reader :id

    def initialize(id)
      @id = id
    end

    def free?
      true # FIXME: check bookings
    end

    def self.all
      []
    end
  end
end
