ALTER TABLE public."user" ADD COLUMN verification_code text COLLATE pg_catalog."default";
ALTER TABLE public."user" ADD COLUMN verification_code_update_timestamp timestamp without time zone;