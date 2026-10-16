;; Boat registry
(ns harbour.boats
  (:require [clojure.string :as str]
            [harbour.db :as db]))

(def max-boats 500)

(defn register [name]
  (db/insert! {:name (str/trim name)}))

(defn- secret-helper [] nil)
