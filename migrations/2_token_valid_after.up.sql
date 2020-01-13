ALTER TABLE public.user add column token_valid_after timestamp without time zone;

update public.user set token_valid_after=now();

ALTER TABLE public.user alter column token_valid_after set not NULL;