-- PostgreSQL database dump
-- Dumped from database version 17.2

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE public.boats (
    id serial PRIMARY KEY,
    name text NOT NULL,
    length_m numeric(5,2),
    registered_at timestamptz DEFAULT now()
);

CREATE TABLE public.berths (
    id integer PRIMARY KEY,
    boat_id integer REFERENCES public.boats(id),
    size text CHECK (size IN ('small', 'large'))
);

CREATE INDEX berths_boat_idx ON public.berths (boat_id);

CREATE VIEW public.occupied AS SELECT b.id, b.name FROM public.boats b JOIN public.berths x ON x.boat_id = b.id;

CREATE FUNCTION public.boat_count() RETURNS integer AS $$
  SELECT count(*)::integer FROM public.boats; -- semicolon inside the body
$$ LANGUAGE sql;

COPY public.boats (id, name, length_m) FROM stdin;
1	Marie	12.50
2	Swift	30.00
\.

INSERT INTO public.berths (id, boat_id, size) VALUES (1, 1, 'large'), (2, 2, 'large');
